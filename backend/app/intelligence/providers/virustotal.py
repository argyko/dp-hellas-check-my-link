from __future__ import annotations
import base64, os, httpx
from app.intelligence.base import ThreatProvider, ThreatFinding

class VirusTotalProvider(ThreatProvider):
    name = "virustotal"

    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")

    @staticmethod
    def _url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def check_url(self, url: str) -> list[ThreatFinding]:
        if not self.api_key:
            return [ThreatFinding(provider=self.name, category="reputation",
                                   status="UNAVAILABLE", details={"reason": "API key not configured"})]
        endpoint = f"https://www.virustotal.com/api/v3/urls/{self._url_id(url)}"
        try:
            response = httpx.get(endpoint,
                headers={"x-apikey": self.api_key, "accept": "application/json"},
                timeout=10.0)
        except httpx.RequestError as exc:
            return [ThreatFinding(provider=self.name, category="reputation",
                                   status="UNAVAILABLE", details={"error": str(exc)})]
        if response.status_code == 404:
            return [ThreatFinding(provider=self.name, category="reputation",
                                   status="NO_DETECTION",
                                   details={"reason": "No existing URL report found"})]
        if response.status_code >= 400:
            return [ThreatFinding(provider=self.name, category="reputation",
                                   status="UNAVAILABLE",
                                   details={"http_status": response.status_code})]
        try:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            undetected = int(stats.get("undetected", 0) or 0)
            total = malicious + suspicious + harmless + undetected
            findings = []
            if malicious:
                findings.append(ThreatFinding(
                    provider=self.name, category="malware", status="DETECTED",
                    severity="CRITICAL", confidence=min(0.99, malicious / total) if total else None,
                    details={"detections": malicious, "engines_total": total, "stats": stats}))
            if suspicious:
                findings.append(ThreatFinding(
                    provider=self.name, category="phishing", status="DETECTED",
                    severity="HIGH", confidence=min(0.99, suspicious / total) if total else None,
                    details={"detections": suspicious, "engines_total": total, "stats": stats}))
            if not findings:
                findings.append(ThreatFinding(
                    provider=self.name, category="reputation", status="NO_DETECTION",
                    details={"stats": stats, "engines_total": total}))
            return findings
        except (ValueError, TypeError, AttributeError) as exc:
            return [ThreatFinding(provider=self.name, category="reputation",
                                   status="UNAVAILABLE",
                                   details={"error": f"Invalid VT response: {exc}"})]
