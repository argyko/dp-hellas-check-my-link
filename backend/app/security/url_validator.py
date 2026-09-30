from __future__ import annotations
import ipaddress, socket
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = {"http", "https"}

class URLValidationError(ValueError):
    pass

def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    # Explicitly reject cloud metadata and all non-routable/reserved ranges.
    blocked_exact = {
        "169.254.169.254",
        "100.100.100.200",
    }
    if value in blocked_exact:
        return False
    return not any([
        ip.is_private, ip.is_loopback, ip.is_link_local,
        ip.is_multicast, ip.is_reserved, ip.is_unspecified,
    ])

def resolve_public_ips(hostname: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise URLValidationError("Το hostname δεν μπορεί να αναλυθεί μέσω DNS.")
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise URLValidationError("Δεν βρέθηκε IP address για το hostname.")
    for address in addresses:
        try:
            if not _is_public_ip(address):
                raise URLValidationError("Το URL οδηγεί σε μη δημόσια ή εσωτερική IP address.")
        except ValueError:
            raise URLValidationError("Μη έγκυρη IP address από το DNS.")
    return addresses

def validate_and_normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise URLValidationError("Το URL είναι κενό.")
    if len(value) > int(__import__("os").getenv("MAX_URL_LENGTH", "4096")):
        raise URLValidationError("Το URL είναι υπερβολικά μεγάλο.")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise URLValidationError("Επιτρέπονται μόνο HTTP και HTTPS URLs.")
    if not parsed.hostname:
        raise URLValidationError("Το URL δεν περιέχει έγκυρο hostname.")
    if parsed.username or parsed.password:
        raise URLValidationError("URLs με username ή password δεν επιτρέπονται.")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost","localhost.localdomain","ip6-localhost","ip6-loopback"} or hostname.endswith(".local"):
        raise URLValidationError("Το hostname είναι τοπικό/internal.")
    try:
        if not _is_public_ip(hostname):
            raise URLValidationError("Το URL οδηγεί σε μη δημόσια ή εσωτερική IP address.")
    except ValueError:
        resolve_public_ips(hostname)
    return urlunsplit((
        parsed.scheme.lower(),
        hostname + (f":{parsed.port}" if parsed.port else ""),
        parsed.path or "/",
        parsed.query,
        parsed.fragment,
    ))
