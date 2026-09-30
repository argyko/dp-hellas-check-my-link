from __future__ import annotations
from urllib.parse import urljoin
import httpx
from app.security.url_validator import URLValidationError, validate_and_normalize_url
from app.security.network_policy import egress_proxy_url

MAX_REDIRECTS = 7
TIMEOUT = httpx.Timeout(10.0, connect=5.0)
USER_AGENT = "DP-Hellas-Check-My-Link/0.8"
MAX_BODY_BYTES = 512_000

class ScanError(RuntimeError):
    pass

def _safe_redirect_url(current_url: str, location: str) -> str:
    return validate_and_normalize_url(urljoin(current_url, location))

def scan_url(start_url: str) -> dict:
    current_url = validate_and_normalize_url(start_url)
    redirects, seen = [], {current_url}
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5"}
    kwargs = {"timeout": TIMEOUT, "follow_redirects": False, "headers": headers, "max_redirects": 0}
    proxy = egress_proxy_url()
    if proxy:
        kwargs["proxy"] = proxy
    try:
        with httpx.Client(**kwargs) as client:
            for _ in range(MAX_REDIRECTS + 1):
                # Re-resolve/validate immediately before each outbound request.
                current_url = validate_and_normalize_url(current_url)
                try:
                    response = client.get(current_url)
                except httpx.RequestError as exc:
                    raise ScanError(f"Αποτυχία HTTP request: {exc}") from exc
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_BODY_BYTES:
                    raise ScanError("Η απόκριση υπερβαίνει το επιτρεπόμενο μέγεθος.")
                location = response.headers.get("location")
                if response.is_redirect:
                    if not location:
                        break
                    target = _safe_redirect_url(current_url, location)
                    if target in seen:
                        raise ScanError("Εντοπίστηκε redirect loop.")
                    redirects.append({"from": current_url, "to": target, "status_code": response.status_code})
                    seen.add(target)
                    current_url = target
                    continue
                return {
                    "initial_url": start_url, "final_url": current_url, "http_status": response.status_code,
                    "content_type": response.headers.get("content-type"), "server": response.headers.get("server"),
                    "redirect_count": len(redirects), "redirects": redirects,
                }
            raise ScanError(f"Υπέρβαση μέγιστου αριθμού redirects ({MAX_REDIRECTS}).")
    except URLValidationError as exc:
        raise ScanError(f"Μη ασφαλές redirect: {exc}") from exc
