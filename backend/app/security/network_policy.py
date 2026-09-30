from __future__ import annotations
import os
from urllib.parse import urlparse

class NetworkPolicyError(RuntimeError):
    pass

def require_egress_proxy() -> bool:
    return os.getenv('REQUIRE_EGRESS_PROXY','false').strip().lower() in {'1','true','yes','on'}

def egress_proxy_url() -> str | None:
    value = os.getenv('EGRESS_PROXY_URL','').strip()
    return value or None

def validate_network_policy() -> None:
    proxy = egress_proxy_url()
    if proxy:
        scheme = urlparse(proxy).scheme.lower()
        if scheme not in {'http','https','socks5','socks5h'}:
            raise NetworkPolicyError('EGRESS_PROXY_URL must use HTTP(S) or SOCKS5.')
    if require_egress_proxy() and not proxy:
        raise NetworkPolicyError('Production egress proxy is required but EGRESS_PROXY_URL is not configured.')
