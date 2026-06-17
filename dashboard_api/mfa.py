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


def verify_code_counter(secret_b32: str, code: str, window: int = 1, after: int = -1) -> int | None:
    """Like `verify_code` but returns the time-step counter the code matched (for
    replay protection), or None. A counter <= `after` is rejected as already-used,
    so a still-valid code can't be replayed within its window."""
    cleaned = (code or "").strip().replace(" ", "")
    if not cleaned or not secret_b32:
        return None
    now = time.time()
    try:
        for i in range(-window, window + 1):
            t = now + i * STEP_SECONDS
            counter = int(t // STEP_SECONDS)
            if counter <= after:
                continue
            if hmac.compare_digest(totp_code(secret_b32, t), cleaned):
                return counter
    except (ValueError, TypeError):
        return None
    return None


def otpauth_uri(secret_b32: str, email: str, issuer: str = "ThreatOrbit") -> str:
    """The otpauth:// provisioning URI authenticator apps scan as a QR."""
    return (f"otpauth://totp/{quote(issuer)}:{quote(email)}"
            f"?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")


# ── Recovery (backup) codes ───────────────────────────────────────────────────
# One-time codes shown ONCE at enrolment so a lost authenticator isn't a lockout.
# Only their SHA-256 hashes are stored; the high entropy (50 bits) makes a plain
# hash safe (no fast-hash brute-force risk on a random code).
_RC_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no ambiguous 0/o/1/i/l


def new_recovery_codes(n: int = 10) -> list[str]:
    """`n` fresh human-friendly codes, formatted `xxxxx-xxxxx`."""
    def one() -> str:
        body = "".join(secrets.choice(_RC_ALPHABET) for _ in range(10))
        return f"{body[:5]}-{body[5:]}"
    return [one() for _ in range(n)]


def _rc_normalize(code: str) -> str:
    return "".join(c for c in (code or "").lower() if c.isalnum())


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(_rc_normalize(code).encode()).hexdigest()


def consume_recovery_code(hashes: list, code: str):
    """If `code` matches a stored hash, return the list WITHOUT it (consumed);
    otherwise return None. Tolerant of spacing/hyphens/case in the input."""
    if not code or not hashes:
        return None
    target = hash_recovery_code(code)
    matched = None
    for h in hashes:
        if hmac.compare_digest(str(h), target):
            matched = h
    if matched is None:
        return None
    return [h for h in hashes if h != matched]

