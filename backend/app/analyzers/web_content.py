from __future__ import annotations

import re
from typing import Any


CREDENTIAL_TERMS = re.compile(r"\b(password|passwd|passcode|username|sign in|log in|login|verify account|verification code|one[- ]time code|otp|pin)\b", re.I)
PAYMENT_TERMS = re.compile(r"\b(card number|credit card|debit card|cvv|cvc|expiry|expiration|payment|billing)\b", re.I)
URGENCY_TERMS = re.compile(r"\b(urgent|immediately|act now|expires? today|suspended|suspend|final warning|verify now)\b", re.I)


def analyze_web_content(browser_result: dict[str, Any]) -> dict[str, Any]:
    content = browser_result.get("content") or {}
    text = content.get("text") or ""
    forms = browser_result.get("forms") or []
    form_inputs = [i for f in forms for i in (f.get("inputs") or [])]
    password_fields = [i for i in form_inputs if (i.get("type") or "").lower() == "password"]
    card_like = [i for i in form_inputs if any(k in ((i.get("name") or "") + " " + (i.get("autocomplete") or "")).lower() for k in ("cc", "card", "cvv", "cvc", "expiry"))]
    credential_hits = sorted(set(m.group(0).lower() for m in CREDENTIAL_TERMS.finditer(text)))[:20]
    payment_hits = sorted(set(m.group(0).lower() for m in PAYMENT_TERMS.finditer(text)))[:20]
    urgency_hits = sorted(set(m.group(0).lower() for m in URGENCY_TERMS.finditer(text)))[:20]
    return {
        "credential_language": bool(credential_hits or password_fields),
        "credential_terms": credential_hits,
        "password_field_count": len(password_fields),
        "payment_language": bool(payment_hits or card_like),
        "payment_terms": payment_hits,
        "card_like_field_count": len(card_like),
        "urgency_language": bool(urgency_hits),
        "urgency_terms": urgency_hits,
    }
