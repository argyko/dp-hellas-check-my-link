from __future__ import annotations

from urllib.parse import urlsplit

STATUS_BY_SCORE = [
    (90, "MALICIOUS", "ΚΑΚΟΒΟΥΛΟ"),
    (70, "HIGH_RISK", "ΠΟΛΥ ΥΨΗΛΟΣ ΚΙΝΔΥΝΟΣ"),
    (40, "SUSPICIOUS", "ΥΠΟΠΤΟ"),
    (20, "LOW_RISK", "ΠΙΘΑΝΩΣ ΑΣΦΑΛΕΣ"),
    (0, "LOW", "ΧΑΜΗΛΟΣ ΚΙΝΔΥΝΟΣ"),
]

def _status(score: int) -> tuple[str, str]:
    for minimum, code, label in STATUS_BY_SCORE:
        if score >= minimum:
            return code, label
    return "UNKNOWN", "ΑΓΝΩΣΤΟ"

def _add_signal(signals, name, points, severity, evidence):
    signals.append({
        "signal": name,
        "risk_points": points,
        "severity": severity,
        "evidence": evidence,
    })

def calculate_risk(url, http_result, domain_result, tls_result, threat_result, correlation,
                   url_intelligence=None, impersonation=None, web_content=None):
    score = 0
    signals = []
    hard_floor = 0
    url_intelligence = url_intelligence or {}
    impersonation = impersonation or {}
    web_content = web_content or {}

    # CR-01 / CR-02: confirmed malware.
    malware = [
        f for f in threat_result.get("providers", [])
        if f.get("status") == "DETECTED" and f.get("category") == "malware"
    ]
    phishing = [
        f for f in threat_result.get("providers", [])
        if f.get("status") == "DETECTED" and f.get("category") == "phishing"
    ]

    if malware:
        _add_signal(signals, "Confirmed malware detection", 90, "CRITICAL",
                    {"providers": [f["provider"] for f in malware]})
        hard_floor = max(hard_floor, 90)

        providers = {f["provider"] for f in malware}
        if len(providers) >= 2:
            hard_floor = max(hard_floor, 95)
            _add_signal(signals, "Independent malware agreement", 5, "CRITICAL",
                        {"providers": sorted(providers)})

    if phishing:
        _add_signal(signals, "Phishing detection", 75, "HIGH",
                    {"providers": [f["provider"] for f in phishing]})
        hard_floor = max(hard_floor, 80)

    # CR-09 / CR-11: redirect pressure.
    redirect_count = int(http_result.get("redirect_count", 0) or 0)
    if redirect_count >= 3:
        _add_signal(signals, "Multiple redirects", 10, "MEDIUM",
                    {"redirect_count": redirect_count})
    elif redirect_count >= 1:
        _add_signal(signals, "Redirect chain present", 3, "LOW",
                    {"redirect_count": redirect_count})

    # CR-14 / CR-15: new domain pressure.
    age = domain_result.get("domain_age_days")
    if age is not None:
        if age < 7:
            _add_signal(signals, "Very new domain", 15, "HIGH", {"age_days": age})
        elif age < 30:
            _add_signal(signals, "New domain", 10, "MEDIUM", {"age_days": age})
        elif age < 90:
            _add_signal(signals, "Young domain", 4, "LOW", {"age_days": age})

    # URL lexical evidence: intentionally weak in isolation.
    credential_terms = url_intelligence.get("credential_terms", [])
    payment_terms = url_intelligence.get("payment_terms", [])
    urgency_terms = url_intelligence.get("urgency_terms", [])
    redirect_params = url_intelligence.get("redirect_parameters", [])
    external_redirect_targets = url_intelligence.get("external_redirect_targets", [])
    homograph = url_intelligence.get("homograph", {})
    brands = url_intelligence.get("brand_similarity", [])

    if credential_terms:
        _add_signal(signals, "Credential-related URL terms", 3, "LOW", {"terms": credential_terms})
    if payment_terms:
        _add_signal(signals, "Payment-related URL terms", 3, "LOW", {"terms": payment_terms})
    if urgency_terms:
        _add_signal(signals, "Urgency-related URL terms", 2, "LOW", {"terms": urgency_terms})
    if redirect_params:
        points = 6 if external_redirect_targets else 2
        _add_signal(signals, "Redirect-like URL parameters", points, "MEDIUM" if points > 2 else "LOW", {"parameters": redirect_params, "external_targets": bool(external_redirect_targets)})

    if homograph.get("punycode"):
        _add_signal(signals, "Punycode/IDN hostname", 5, "MEDIUM", {"labels": homograph.get("punycode_labels", [])})
    if homograph.get("mixed_script"):
        _add_signal(signals, "Mixed-script hostname", 8, "MEDIUM", {"scripts": homograph.get("scripts", [])})

    if brands:
        top_brand = brands[0]
        if top_brand.get("similarity", 0) >= 0.90:
            _add_signal(signals, "High brand similarity", 8, "MEDIUM", top_brand)
        elif top_brand.get("similarity", 0) >= 0.80:
            _add_signal(signals, "Brand similarity", 4, "LOW", top_brand)

    if impersonation.get("detected"):
        _add_signal(signals, "Potential brand impersonation", 12, "HIGH", impersonation)
        if credential_terms and brands:
            hard_floor = max(hard_floor, 80)
            _add_signal(signals, "Brand impersonation + credential collection", 0, "CRITICAL", {"brand": impersonation.get("brand")})
        elif payment_terms and brands:
            hard_floor = max(hard_floor, 80)
            _add_signal(signals, "Brand impersonation + payment language", 0, "CRITICAL", {"brand": impersonation.get("brand")})

    if homograph.get("suspicious") and brands:
        _add_signal(signals, "Homograph + known brand similarity", 10, "HIGH", {"brand": brands[0].get("brand")})

    # Browser/content evidence. These signals are intentionally correlation-heavy:
    # a login/payment form is not malicious by itself.
    password_fields = int(web_content.get("password_field_count", 0) or 0)
    card_fields = int(web_content.get("card_like_field_count", 0) or 0)
    credential_language = bool(web_content.get("credential_language"))
    payment_language = bool(web_content.get("payment_language"))
    urgency_language = bool(web_content.get("urgency_language"))

    if password_fields:
        _add_signal(signals, "Password field detected", 4, "LOW",
                    {"password_field_count": password_fields})
    if card_fields:
        _add_signal(signals, "Payment/card field detected", 5, "LOW",
                    {"card_like_field_count": card_fields})

    if brands and top_brand.get("similarity", 0) >= 0.90 and password_fields:
        hard_floor = max(hard_floor, 80)
        _add_signal(
            signals,
            "Lookalike brand + login credential collection",
            0,
            "CRITICAL",
            {"brand": top_brand.get("brand"), "password_field_count": password_fields},
        )

    if impersonation.get("detected") and password_fields:
        hard_floor = max(hard_floor, 80)
        _add_signal(
            signals,
            "Impersonation + credential collection",
            0,
            "CRITICAL",
            {"brand": impersonation.get("brand"), "password_field_count": password_fields},
        )

    if impersonation.get("detected") and card_fields:
        hard_floor = max(hard_floor, 85)
        _add_signal(
            signals,
            "Impersonation + payment credential collection",
            0,
            "CRITICAL",
            {"brand": impersonation.get("brand"), "card_like_field_count": card_fields},
        )

    if credential_language and urgency_language and (brands or impersonation.get("detected")):
        _add_signal(
            signals,
            "Urgency + credential language + brand context",
            12,
            "HIGH",
            {"urgency_terms": web_content.get("urgency_terms", [])[:10]},
        )

    if payment_language and urgency_language and (brands or impersonation.get("detected")):
        _add_signal(
            signals,
            "Urgency + payment language + brand context",
            12,
            "HIGH",
            {"urgency_terms": web_content.get("urgency_terms", [])[:10]},
        )

    # Unified infrastructure correlation. These signals never treat HTTPS alone as safe.
    infra = correlation or {}
    if infra.get("strong_malware_agreement"):
        hard_floor = max(hard_floor, 95)
        _add_signal(signals, "Independent malware agreement", 0, "CRITICAL", {"status": infra.get("status")})
    elif infra.get("strong_phishing_agreement"):
        hard_floor = max(hard_floor, 85)
        _add_signal(signals, "Independent phishing agreement", 0, "CRITICAL", {"status": infra.get("status")})

    # Infrastructure evidence: useful but deliberately limited.
    tls_status = tls_result.get("status")
    if tls_status == "ERROR":
        _add_signal(signals, "TLS error", 8, "MEDIUM",
                    {"error": tls_result.get("error")})

    # HTTP error is not malicious by itself.
    status = http_result.get("http_status")
    if isinstance(status, int) and status >= 500:
        _add_signal(signals, "Server error", 2, "LOW", {"http_status": status})

    # HTTPS is not a negative risk signal.
    # It must never cancel threat detections.

    raw_score = min(100, max(0, score + sum(s["risk_points"] for s in signals)))
    final_score = max(raw_score, hard_floor)
    final_score = min(100, final_score)

    status_code, status_label = _status(final_score)

    # Evidence confidence is independent from risk.
    confidence = float(correlation.get("confidence", 0.55))
    confidence_reasons = []

    if threat_result.get("status") == "PARTIAL":
        confidence = min(confidence, 0.50)
        confidence_reasons.append("At least one threat-intelligence provider unavailable.")

    if not http_result.get("final_url"):
        confidence = min(confidence, 0.35)
        confidence_reasons.append("Final URL unavailable.")

    if domain_result.get("rdap", {}).get("status") == "UNAVAILABLE":
        confidence = min(confidence, 0.70)
        confidence_reasons.append("RDAP evidence unavailable.")

    if web_content.get("status") == "UNAVAILABLE":
        confidence = min(confidence, 0.60)
        confidence_reasons.append("Rendered web-content evidence unavailable.")
    elif web_content:
        # Browser evidence increases confidence only when it is actually present;
        # it does not make a benign page trustworthy by itself.
        confidence = min(1.0, confidence + 0.05)
        confidence_reasons.append("Rendered page evidence available.")

    confidence = round(max(0.0, min(1.0, confidence)) * 100)

    # Unknown/insufficient evidence should not be presented as safe.
    evidence_count = len(signals) + len(threat_result.get("providers", []))
    if evidence_count == 0:
        status_code = "UNKNOWN"
        status_label = "ΑΔΥΝΑΤΟΣ Ο ΠΛΗΡΗΣ ΕΛΕΓΧΟΣ"

    return {
        "risk_score": final_score,
        "confidence_score": int(confidence),
        "status": status_code,
        "status_label": status_label,
        "signals": signals,
        "hard_floor": hard_floor,
        "confidence_reasons": confidence_reasons,
        "model": "rule-based-risk-engine-v1",
        "ai_used_for_score": False,
        "note": "Risk score is rule-based. AI may explain evidence later but does not independently set the score.",
    }
