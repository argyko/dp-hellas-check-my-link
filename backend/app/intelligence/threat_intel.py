from __future__ import annotations
from app.intelligence.base import ThreatFinding
from app.intelligence.providers.google_web_risk import GoogleWebRiskProvider
from app.intelligence.providers.virustotal import VirusTotalProvider

class ThreatIntelError(RuntimeError):
    pass

def analyze_threat_intelligence(url: str) -> dict:
    findings: list[ThreatFinding] = []
    for provider in (GoogleWebRiskProvider(), VirusTotalProvider()):
        try:
            findings.extend(provider.check_url(url))
        except Exception as exc:
            findings.append(ThreatFinding(
                provider=getattr(provider, "name", "unknown"),
                category="provider", status="UNAVAILABLE",
                details={"error": str(exc)}))

    detected = [f for f in findings if f.status == "DETECTED"]
    unavailable = [f for f in findings if f.status == "UNAVAILABLE"]
    no_detection = [f for f in findings if f.status == "NO_DETECTION"]

    return {
        "status": "DETECTED" if detected else ("PARTIAL" if unavailable else "NO_DETECTION"),
        "detections": len(detected),
        "no_detection_signals": len(no_detection),
        "providers": [f.as_dict() for f in findings],
        "important_rule": "NO_DETECTION does not mean SAFE.",
    }
