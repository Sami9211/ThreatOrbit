"""TOTP multi-factor authentication (RFC 6238) - stdlib only.

The standard 6-digit, 30-second, SHA-1 flavour every authenticator app
(Google Authenticator, Authy, 1Password, …) implements. Secrets are
generated here, stored encrypted at rest (secretstore), and verified with
a ±1-step window to absorb clock skew. `otpauth_uri` yields the string a
QR generator encodes for one-tap enrolment.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6


def new_secret() -> str:
    """A fresh 160-bit base32 secret (the RFC 4226 recommended size)."""
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp_code(secret_b32: str, at: float | None = None) -> str:
    """The TOTP code for a secret at a moment in time."""
    key = base64.b32decode(secret_b32.upper(), casefold=True)
    counter = int((time.time() if at is None else at) // STEP_SECONDS)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def verify_code(secret_b32: str, code: str, window: int = 1) -> bool:
    """Constant-time check of a submitted code, accepting ±`window` steps of
    clock skew. Empty inputs never verify."""
    cleaned = (code or "").strip().replace(" ", "")
    if not cleaned or not secret_b32:
        return False
    now = time.time()
    try:
        return any(
            hmac.compare_digest(totp_code(secret_b32, now + i * STEP_SECONDS), cleaned)
            for i in range(-window, window + 1))
    except (ValueError, TypeError):  # malformed secret - never verifies
        return False


def otpauth_uri(secret_b32: str, email: str, issuer: str = "ThreatOrbit") -> str:
    """The otpauth:// provisioning URI authenticator apps scan as a QR."""
    return (f"otpauth://totp/{quote(issuer)}:{quote(email)}"
            f"?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")
