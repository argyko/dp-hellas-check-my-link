from __future__ import annotations
import socket, ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

class TLSAnalysisError(RuntimeError):
    pass

def _decode_name(name) -> str | None:
    parts = []
    for item in name or ():
        for key, value in item:
            if key in {"commonName", "organizationName"}:
                parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None

def analyze_tls(url: str) -> dict:
    parsed = urlsplit(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if parsed.scheme.lower() != "https":
        return {"status": "NOT_APPLICABLE", "https": False, "hostname": hostname, "port": port}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=6) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as conn:
                cert = conn.getpeercert()
                cipher, version = conn.cipher(), conn.version()
                not_before, not_after = cert.get("notBefore"), cert.get("notAfter")
                expiry_days = None
                if not_after:
                    try:
                        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        expiry_days = (expires - datetime.now(timezone.utc)).days
                    except ValueError:
                        pass
                sans = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"]
                return {"status": "OK", "https": True, "hostname": hostname, "port": port,
                        "tls_version": version, "cipher": cipher[0] if cipher else None,
                        "certificate": {"subject": _decode_name(cert.get("subject")),
                        "issuer": _decode_name(cert.get("issuer")),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": not_before, "not_after": not_after,
                        "expires_in_days": expiry_days, "subject_alt_names": sans[:100]}}
    except (OSError, ssl.SSLError) as exc:
        return {"status": "ERROR", "https": True, "hostname": hostname, "port": port, "error": str(exc)}
