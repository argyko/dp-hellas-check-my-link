from __future__ import annotations
import os
import httpx
from app.intelligence.base import ThreatProvider, ThreatFinding

class GoogleWebRiskProvider(ThreatProvider):
    name = "google_web_risk"

    def __init__(self):
        self.api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY")

    def check_url(self, url: str) -> list[ThreatFinding]:
        if not self.api_key:
            return [ThreatFinding(provider=self.name, category="reputation",
                                   status="UNAVAILABLE", details={"reason": "API key not configured"})]

        endpoint = "https://webrisk.googleapis.com/v1/uris:search"
        findings = []
        for threat_type, category in (("MALWARE", "malware"), ("SOCIAL_ENGINEERING", "phishing")):
            try:
                response = httpx.get(endpoint, params={
                    "key": self.api_key, "uri": url, "threatTypes": threat_type
                }, timeout=8.0)
            except httpx.RequestError as exc:
                findings.append(ThreatFinding(provider=self.name, category=category,
                                              status="UNAVAILABLE", details={"error": str(exc)}))
                continue
            if response.status_code == 200:
                data = response.json()
                matched = bool(data.get("threat", {}).get("threatTypes"))
                findings.append(ThreatFinding(
                    provider=self.name, category=category,
                    status="DETECTED" if matched else "NO_DETECTION",
                    severity="CRITICAL" if matched else "UNKNOWN",
                    confidence=0.99 if matched else None,
                    details=data.get("threat", {}),
                ))
            else:
                findings.append(ThreatFinding(provider=self.name, category=category,
                                              status="UNAVAILABLE",
                                              details={"http_status": response.status_code}))
        return findings
