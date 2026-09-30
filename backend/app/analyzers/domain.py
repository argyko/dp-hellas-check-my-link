from __future__ import annotations
import ipaddress, socket
from datetime import datetime, timezone
from urllib.parse import urlsplit
import httpx

class DomainAnalysisError(RuntimeError):
    pass

def _host_parts(hostname: str) -> tuple[str, str | None]:
    labels = hostname.rstrip(".").lower().split(".")
    if len(labels) < 2:
        return hostname, None
    registered_domain = ".".join(labels[-2:])
    subdomain = ".".join(labels[:-2]) or None
    return registered_domain, subdomain

def _dns_records(hostname: str) -> dict:
    records = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        records["A"] = sorted({i[4][0] for i in infos})
    except socket.gaierror:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
        records["AAAA"] = sorted({i[4][0] for i in infos})
    except socket.gaierror:
        pass
    return records

def _rdap_lookup(domain: str) -> dict:
    url = f"https://rdap.org/domain/{domain}"
    try:
        response = httpx.get(url, timeout=httpx.Timeout(8.0, connect=4.0),
                              headers={"User-Agent": "DP-Hellas-Check-My-Link/0.8"},
                              follow_redirects=True)
    except httpx.RequestError as exc:
        return {"status": "UNAVAILABLE", "error": str(exc)}
    if response.status_code == 404:
        return {"status": "NOT_FOUND"}
    if response.status_code >= 400:
        return {"status": "UNAVAILABLE", "http_status": response.status_code}
    try:
        data = response.json()
    except ValueError:
        return {"status": "UNAVAILABLE", "error": "Invalid RDAP JSON"}
    events = {}
    for event in data.get("events", []):
        action, date = event.get("eventAction"), event.get("eventDate")
        if action and date:
            events[action] = date
    return {"status": "OK", "handle": data.get("handle"),
            "ldh_name": data.get("ldhName"), "status_codes": data.get("status", []),
            "events": events, "rdap_conformance": data.get("rdapConformance", [])}

def _domain_age_days(events: dict) -> int | None:
    raw = events.get("registration")
    if not raw:
        return None
    try:
        created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - created).days)
    except ValueError:
        return None

def analyze_domain(url: str) -> dict:
    hostname = urlsplit(url).hostname
    if not hostname:
        raise DomainAnalysisError("Δεν βρέθηκε hostname.")
    hostname = hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
        return {"hostname": hostname, "is_ip_address": True, "registered_domain": None,
                "subdomain": None, "dns": {"A": [hostname], "AAAA": []},
                "rdap": {"status": "NOT_APPLICABLE"}, "domain_age_days": None}
    except ValueError:
        pass
    registered_domain, subdomain = _host_parts(hostname)
    dns = _dns_records(hostname)
    rdap = _rdap_lookup(registered_domain)
    return {"hostname": hostname, "is_ip_address": False,
            "registered_domain": registered_domain, "subdomain": subdomain,
            "dns": dns, "rdap": rdap,
            "domain_age_days": _domain_age_days(rdap.get("events", {}))}
