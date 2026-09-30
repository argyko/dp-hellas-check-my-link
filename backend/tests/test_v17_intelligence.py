from app.intelligence.evidence_model import build_unified_evidence
from app.scoring.correlation_v2 import correlate_all


def test_multi_provider_malware_agreement():
    threat = {"providers": [
        {"provider":"google_web_risk","category":"malware","status":"DETECTED"},
        {"provider":"virustotal","category":"malware","status":"DETECTED"},
    ]}
    ev = build_unified_evidence(
        threat=threat,
        domain={"registered_domain":"example.com","rdap":{"status":"OK","events":{}},"dns":{"A":["1.2.3.4"],"AAAA":[]}},
        tls={"status":"OK","tls_version":"TLSv1.3"},
        http={"http_status":200,"final_url":"https://example.com","redirect_count":0},
        url_intelligence={}, browser={"status":"OK"}
    )
    c = correlate_all(ev)
    assert c["strong_malware_agreement"] is True
    assert c["confidence"] > 0.8


def test_partial_evidence_caps_confidence():
    ev = build_unified_evidence(
        threat={"providers":[{"provider":"google_web_risk","category":"reputation","status":"UNAVAILABLE"}]},
        domain={"registered_domain":"example.com","rdap":{"status":"UNAVAILABLE"},"dns":{"A":[],"AAAA":[]}},
        tls={"status":"ERROR"},
        http={}, url_intelligence={}, browser={}
    )
    c = correlate_all(ev)
    assert c["unavailable_sources"] >= 2
    assert c["confidence"] <= 0.70
