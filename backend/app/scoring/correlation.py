from __future__ import annotations

def correlate_threat_intelligence(threat_result: dict) -> dict:
    findings = threat_result.get("providers", [])
    detected = [f for f in findings if f.get("status") == "DETECTED"]
    unavailable = [f for f in findings if f.get("status") == "UNAVAILABLE"]

    by_category: dict[str, list[dict]] = {}
    for finding in detected:
        by_category.setdefault(finding.get("category", "unknown"), []).append(finding)

    independent_agreement = []
    for category, items in by_category.items():
        providers = sorted({item.get("provider") for item in items})
        if len(providers) >= 2:
            independent_agreement.append({
                "category": category,
                "providers": providers,
                "strength": "HIGH",
            })

    if independent_agreement:
        confidence = 0.97
        correlation_status = "STRONG_AGREEMENT"
    elif detected:
        confidence = 0.88
        correlation_status = "SINGLE_PROVIDER_DETECTION"
    elif unavailable:
        confidence = 0.25
        correlation_status = "LIMITED_EVIDENCE"
    else:
        confidence = 0.55
        correlation_status = "NO_THREAT_DETECTION"

    return {
        "status": correlation_status,
        "detected_signals": len(detected),
        "unavailable_signals": len(unavailable),
        "independent_agreement": independent_agreement,
        "confidence": confidence,
        "note": "Correlation confidence is evidence confidence, not a safety guarantee.",
    }
