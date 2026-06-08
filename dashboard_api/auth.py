"""Authentication: password hashing (PBKDF2, stdlib only) and JWT issuance.

Why PBKDF2 over bcrypt: bcrypt needs a native build that is fragile in slim
containers. PBKDF2-HMAC-SHA256 ships with the stdlib, has no build step, and at
260k iterations is a sound choice for this workload.
"""
import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dashboard_api.config import JWT_SECRET, JWT_TTL_MINUTES
from dashboard_api.db import get_conn, row_to_dict

_PBKDF2_ITERS = 260_000


# --- Minimal HS256 JWT (stdlib only) ---------------------------------------
# We implement the JWT ourselves rather than depend on PyJWT, because PyJWT in
# this environment imports `cryptography`'s Rust bindings (needed only for RSA/EC)
# which are broken here. HS256 needs nothing beyond hmac/hashlib/base64.
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _jwt_encode(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def _jwt_decode(token: str) -> dict:
    try:
        h, p, s = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")
    signing_input = f"{h}.{p}".encode()
    expected = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(s)):
        raise HTTPException(status_code=401, detail="Invalid token")
    payload = json.loads(_b64url_decode(p))
    if payload.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=401, detail="Token expired")
    return payload


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (hash_hex, salt_hex). Generates a fresh salt when not supplied."""
    salt = salt or os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ITERS)
    return dk.hex(), salt


def verify_password(password: str, hash_hex: str, salt: str) -> bool:
    candidate, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate, hash_hex)


def create_token(user: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "name": user["name"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_TTL_MINUTES)).timestamp()),
    }
    return _jwt_encode(payload)


def decode_token(token: str) -> dict:
    return _jwt_decode(token)


_bearer = HTTPBearer(auto_error=False)


def current_user(creds: HTTPAuthorizationCredentials = Security(_bearer)) -> dict:
    """Resolve the authenticated user from the Bearer token, fresh from the DB."""
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(creds.credentials)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (payload["sub"],)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User no longer exists")
    user = row_to_dict(row)
    if user["status"] == "disabled":
        raise HTTPException(status_code=403, detail="Account disabled")
    user.pop("password_hash", None)
    user.pop("password_salt", None)
    return user


def require_role(*roles: str):
    """Dependency factory enforcing one of the given roles."""
    def dep(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dep
