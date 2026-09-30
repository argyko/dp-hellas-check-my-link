from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class EvidenceItem:
    source: str
    category: str
    status: str
    severity: str = "UNKNOWN"
    confidence: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "details": self.details,
        }

def build_unified_evidence(*, threat: dict, domain: dict, tls: dict, http: dict, url_intelligence: dict, browser: dict | None = None) -> dict:
    items: list[EvidenceItem] = []
    for finding in threat.get("providers", []):
        items.append(EvidenceItem(
            source=finding.get("provider", "threat_provider"),
            category=finding.get("category", "unknown"),
            status=finding.get("status", "UNAVAILABLE"),
            severity=finding.get("severity", "UNKNOWN"),
            confidence=finding.get("confidence"),
            details=finding.get("details", {}),
        ))

    rdap = domain.get("rdap", {})
    items.append(EvidenceItem(
        source="rdap", category="registration", status=rdap.get("status", "UNAVAILABLE"),
        severity="INFO", details={"registered_domain": domain.get("registered_domain"),
                                  "events": rdap.get("events", {}),
                                  "domain_age_days": domain.get("domain_age_days")},
    ))

    dns = domain.get("dns", {})
    dns_status = "NO_DATA" if not (dns.get("A") or dns.get("AAAA")) else "RESOLVED"
    items.append(EvidenceItem(
        source="dns", category="dns_resolution", status=dns_status,
        severity="INFO", details={"A": dns.get("A", []), "AAAA": dns.get("AAAA", [])},
    ))

    tls_status = tls.get("status", "UNAVAILABLE")
    items.append(EvidenceItem(
        source="tls", category="certificate", status=tls_status,
        severity="HIGH" if tls_status == "ERROR" else "INFO",
        details={k: tls.get(k) for k in ("tls_version", "cipher", "subject", "issuer", "not_before", "not_after", "expires_in_days", "san") if k in tls},
    ))

    items.append(EvidenceItem(
        source="http", category="http", status="OK" if http.get("http_status") else "UNAVAILABLE",
        severity="INFO", details={"http_status": http.get("http_status"), "final_url": http.get("final_url"),
                                  "redirect_count": http.get("redirect_count", 0)},
    ))

    for signal_name, value in (("url_lexical", url_intelligence), ("browser", browser or {})):
        if value:
            items.append(EvidenceItem(source=signal_name, category=signal_name,
                                      status="AVAILABLE", severity="INFO", details=value))

    available = sum(1 for i in items if i.status not in {"UNAVAILABLE"})
    unavailable = sum(1 for i in items if i.status == "UNAVAILABLE")
    return {
        "schema_version": "1.0",
        "items": [i.as_dict() for i in items],
        "available_items": available,
        "unavailable_items": unavailable,
        "coverage": round(available / max(1, len(items)), 3),
    }
