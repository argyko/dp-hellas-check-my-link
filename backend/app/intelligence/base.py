from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class ThreatFinding:
    provider: str
    category: str
    status: str
    severity: str = "UNKNOWN"
    confidence: float | None = None
    details: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "details": self.details,
        }

class ThreatProvider:
    name = "base"
    def check_url(self, url: str) -> list[ThreatFinding]:
        raise NotImplementedError
