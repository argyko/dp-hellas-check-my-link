from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, unquote, urlsplit

KNOWN_BRANDS = {
    "microsoft": ["microsoft.com"],
    "google": ["google.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com"],
    "openai": ["openai.com"],
    "wise": ["wise.com"],
    "revolut": ["revolut.com"],
}

SUSPICIOUS_PATH_TERMS = {
    "login": "credential",
    "signin": "credential",
    "sign-in": "credential",
    "verify": "verification",
    "verification": "verification",
    "account": "account",
    "password": "credential",
    "passwd": "credential",
    "credential": "credential",
    "billing": "payment",
    "payment": "payment",
    "invoice": "payment",
    "wallet": "payment",
    "security-check": "verification",
    "confirm": "verification",
    "suspended": "urgency",
    "urgent": "urgency",
    "unlock": "urgency",
}

REDIRECT_PARAMETER_NAMES = {"url", "uri", "target", "dest", "destination", "redirect", "redirect_url", "redirect_uri", "next", "return", "return_url", "continue", "goto"}
CREDENTIAL_TERMS = {"login", "signin", "sign-in", "password", "passwd", "credential", "verify", "verification", "account"}
PAYMENT_TERMS = {"payment", "billing", "invoice", "card", "wallet", "checkout"}
URGENCY_TERMS = {"urgent", "suspended", "suspension", "verify-now", "immediately", "expire", "expired", "unlock"}


def _tokens(value: str) -> list[str]:
    decoded = unquote(value).lower()
    return [x for x in re.split(r"[^a-z0-9-]+", decoded) if x]


def _normalize_brand_text(value: str) -> str:
    return value.lower().translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}))

def _brand_similarity(hostname: str) -> list[dict]:
    host = hostname.lower().rstrip(".")
    labels = host.split(".")
    candidates = []
    for brand, official_domains in KNOWN_BRANDS.items():
        best = 0.0
        best_label = ""
        brand_norm = _normalize_brand_text(brand)
        for label in labels:
            if not label or label == "www":
                continue
            parts = [p for p in re.split(r"[-_.]+", label) if p]
            comparisons = [label] + parts
            for candidate in comparisons:
                score = SequenceMatcher(None, _normalize_brand_text(candidate), brand_norm).ratio()
                if brand_norm in _normalize_brand_text(candidate) and candidate != brand:
                    score = max(score, 0.92)
                if score > best:
                    best = score
                    best_label = label
        official_match = any(host == d or host.endswith("." + d) for d in official_domains)
        if not official_match and best >= 0.72:
            candidates.append({"brand": brand, "matched_label": best_label, "similarity": round(best, 3)})
    return sorted(candidates, key=lambda x: x["similarity"], reverse=True)[:5]


def _script_set(value: str) -> set[str]:
    scripts = set()
    for ch in value:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        for marker, script in (("LATIN", "Latin"), ("GREEK", "Greek"), ("CYRILLIC", "Cyrillic"), ("HEBREW", "Hebrew"), ("ARABIC", "Arabic")):
            if marker in name:
                scripts.add(script)
                break
        else:
            scripts.add("Other")
    return scripts


def _homograph(hostname: str) -> dict:
    host = hostname.rstrip(".")
    unicode_host = host
    punycode_labels = [label for label in host.split(".") if label.lower().startswith("xn--")]
    try:
        unicode_host = host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        pass
    scripts = sorted(_script_set(unicode_host))
    mixed_script = len(set(scripts) - {"Other"}) > 1
    return {
        "punycode": bool(punycode_labels),
        "punycode_labels": punycode_labels,
        "unicode_host": unicode_host,
        "scripts": scripts,
        "mixed_script": mixed_script,
        "suspicious": bool(punycode_labels) or mixed_script,
    }


def analyze_url_intelligence(url: str) -> dict:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = unquote(parsed.path or "")
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_names = [name.lower() for name, _ in query_pairs]
    full_text = f"{path} {parsed.query}".lower()
    path_tokens = _tokens(path)
    query_tokens = _tokens(parsed.query)
    all_tokens = set(path_tokens + query_tokens)

    path_matches = sorted({SUSPICIOUS_PATH_TERMS[t] for t in all_tokens if t in SUSPICIOUS_PATH_TERMS})
    credential_terms = sorted(CREDENTIAL_TERMS.intersection(all_tokens))
    payment_terms = sorted(PAYMENT_TERMS.intersection(all_tokens))
    urgency_terms = sorted(URGENCY_TERMS.intersection(all_tokens))
    redirect_params = sorted(set(query_names).intersection(REDIRECT_PARAMETER_NAMES))

    external_target_values = []
    for name, value in query_pairs:
        if name.lower() in REDIRECT_PARAMETER_NAMES:
            decoded = unquote(value)
            if re.match(r"^https?://", decoded, re.I):
                external_target_values.append(decoded[:500])

    encoded_markers = len(re.findall(r"%[0-9a-fA-F]{2}", parsed.path + "?" + parsed.query))
    long_url = len(url) >= 180
    many_subdirs = len([x for x in parsed.path.split("/") if x]) >= 6
    special_char_density = len(re.findall(r"[^A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]", url))

    return {
        "hostname": host,
        "path": parsed.path,
        "decoded_path": path,
        "query_parameter_names": query_names,
        "path_matches": path_matches,
        "credential_terms": credential_terms,
        "payment_terms": payment_terms,
        "urgency_terms": urgency_terms,
        "redirect_parameters": redirect_params,
        "external_redirect_targets": external_target_values,
        "encoded_marker_count": encoded_markers,
        "long_url": long_url,
        "many_subdirectories": many_subdirs,
        "special_character_count": special_char_density,
        "homograph": _homograph(host),
        "brand_similarity": _brand_similarity(host),
    }


def detect_impersonation(url_analysis: dict, domain_result: dict) -> dict:
    brands = url_analysis.get("brand_similarity", [])
    if not brands:
        return {"detected": False, "confidence": 0.0, "reasons": []}

    age = domain_result.get("domain_age_days")
    credential = bool(url_analysis.get("credential_terms"))
    payment = bool(url_analysis.get("payment_terms"))
    homograph = bool(url_analysis.get("homograph", {}).get("suspicious"))
    top = brands[0]
    reasons = [f"Domain resembles known brand: {top['brand']}"]
    confidence = 0.45 if top["similarity"] >= 0.85 else 0.30

    if credential or payment:
        confidence += 0.20
        reasons.append("Credential/payment-related URL terms present")
    if homograph:
        confidence += 0.20
        reasons.append("IDN/punycode or mixed-script hostname signal")
    if age is not None and age < 30:
        confidence += 0.10
        reasons.append("Young domain")

    return {
        "detected": confidence >= 0.60,
        "confidence": round(min(confidence, 1.0), 3),
        "brand": top["brand"],
        "similarity": top["similarity"],
        "reasons": reasons,
    }
