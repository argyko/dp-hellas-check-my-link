from __future__ import annotations

THREAT_STATUSES = {"DETECTED", "NO_DETECTION", "UNAVAILABLE"}

def _providers_for(items, category, status="DETECTED"):
    return sorted({i.get("source") for i in items if i.get("category") == category and i.get("status") == status})

def correlate_all(evidence: dict, *, threat_correlation: dict | None = None) -> dict:
    items = evidence.get("items", [])
    detected = [i for i in items if i.get("status") == "DETECTED"]
    unavailable = [i for i in items if i.get("status") == "UNAVAILABLE"]

    agreement = []
    categories = sorted({i.get("category", "unknown") for i in detected})
    for category in categories:
        providers = _providers_for(items, category)
        if len(providers) >= 2:
            agreement.append({"category": category, "providers": providers, "strength": "HIGH"})

    strong_malware = len(_providers_for(items, "malware")) >= 2
    strong_phishing = len(_providers_for(items, "phishing")) >= 2
    tls_error = any(i.get("source") == "tls" and i.get("status") == "ERROR" for i in items)
    rdap_unavailable = any(i.get("source") == "rdap" and i.get("status") == "UNAVAILABLE" for i in items)
    dns_unavailable = any(i.get("source") == "dns" and i.get("status") == "UNAVAILABLE" for i in items)

    if strong_malware:
        confidence = 0.98
        status = "STRONG_MULTI_PROVIDER"
    elif strong_phishing:
        confidence = 0.95
        status = "STRONG_MULTI_PROVIDER"
    elif detected:
        confidence = 0.88
        status = "SINGLE_OR_PARTIAL_DETECTION"
    else:
        confidence = 0.60
        status = "NO_THREAT_DETECTION"

    coverage = float(evidence.get("coverage", 0.0))
    confidence = min(confidence, 0.40 + 0.60 * coverage)

    reasons = []
    if agreement:
        reasons.append("Independent providers agree on at least one threat category.")
    if tls_error:
        reasons.append("TLS/certificate evidence contains an error.")
        confidence = min(confidence, 0.75)
    if rdap_unavailable:
        reasons.append("RDAP registration evidence unavailable.")
        confidence = min(confidence, 0.75)
    if dns_unavailable:
        reasons.append("DNS evidence unavailable.")
        confidence = min(confidence, 0.75)
    if unavailable:
        reasons.append(f"{len(unavailable)} evidence source(s) unavailable.")
        confidence = min(confidence, 0.70)

    return {
        "status": status,
        "confidence": round(confidence, 3),
        "coverage": coverage,
        "independent_agreement": agreement,
        "detected_sources": len(detected),
        "unavailable_sources": len(unavailable),
        "reasons": reasons,
        "strong_malware_agreement": strong_malware,
        "strong_phishing_agreement": strong_phishing,
        "note": "Confidence measures evidence completeness/agreement; it is not a safety guarantee.",
    }
