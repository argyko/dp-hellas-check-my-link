from __future__ import annotations
import hashlib, hmac, os
from dataclasses import dataclass
from fastapi import Header, HTTPException

@dataclass(frozen=True)
class Principal:
    key_id: str
    role: str = "client"

def _env_bool(name: str, default: bool=False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1","true","yes","on"}

def _keys() -> dict[str, str]:
    raw=os.getenv("API_KEYS", "")
    out={}
    for item in raw.split(","):
        item=item.strip()
        if not item or ":" not in item: continue
        key_id, secret=item.split(":",1)
        if key_id and secret: out[key_id]=secret
    return out

def auth_required() -> bool:
    return _env_bool("AUTH_REQUIRED", os.getenv("ENVIRONMENT","development").lower()=="production")

def _matches(presented: str, expected: str) -> bool:
    return hmac.compare_digest(hashlib.sha256(presented.encode()).digest(), hashlib.sha256(expected.encode()).digest())

def principal_from_api_key(api_key: str | None) -> Principal | None:
    keys=_keys()
    if not api_key: return None
    for key_id, secret in keys.items():
        if _matches(api_key, secret): return Principal(key_id=key_id)
    return None

def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> Principal:
    p=principal_from_api_key(x_api_key)
    if p: return p
    if not auth_required(): return Principal(key_id="anonymous")
    raise HTTPException(status_code=401, detail="Valid X-API-Key is required.")

def require_admin(x_admin_key: str | None = Header(default=None, alias="X-Admin-Key")) -> Principal:
    expected=os.getenv("ADMIN_API_KEY", "")
    if expected and x_admin_key and _matches(x_admin_key, expected):
        return Principal(key_id="admin", role="admin")
    raise HTTPException(status_code=403, detail="Admin credentials required.")

def validate_production_auth_config() -> None:
    if os.getenv("ENVIRONMENT","development").lower()=="production" and auth_required():
        if not _keys(): raise RuntimeError("Production requires API_KEYS.")
        if not os.getenv("ADMIN_API_KEY"): raise RuntimeError("Production requires ADMIN_API_KEY.")
