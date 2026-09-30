from app.scoring.risk_engine import calculate_risk

def base():
    return (
        "https://paypa1.example/login",
        {"redirect_count": 0, "final_url": "https://paypa1.example/login"},
        {"domain_age_days": 10, "rdap": {"status": "OK"}},
        {"status": "OK"},
        {"providers": [], "status": "NO_DETECTION"},
        {"confidence": 0.55},
    )

def test_lookalike_login_has_high_floor():
    args = base()
    result = calculate_risk(*args,
        {"credential_terms": ["login"], "payment_terms": [], "urgency_terms": [],
         "redirect_parameters": [], "external_redirect_targets": [],
         "homograph": {}, "brand_similarity": [{"brand": "paypal", "similarity": 0.96}]},
        {"detected": True, "brand": "paypal"},
        {"password_field_count": 1, "card_like_field_count": 0,
         "credential_language": True, "payment_language": False,
         "urgency_language": False},
    )
    assert result["risk_score"] >= 80

def test_impersonation_payment_has_critical_floor():
    args = base()
    result = calculate_risk(*args,
        {"credential_terms": [], "payment_terms": ["payment"], "urgency_terms": [],
         "redirect_parameters": [], "external_redirect_targets": [],
         "homograph": {}, "brand_similarity": [{"brand": "paypal", "similarity": 0.95}]},
        {"detected": True, "brand": "paypal"},
        {"password_field_count": 0, "card_like_field_count": 1,
         "credential_language": False, "payment_language": True,
         "urgency_language": False},
    )
    assert result["risk_score"] >= 85
