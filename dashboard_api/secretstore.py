"""Secrets at rest (Tier-1 production hardening).

Credentials the platform stores in its own DB — connector API keys,
integration API keys, per-user Slack webhook URLs — are encrypted with
Fernet (AES-128-CBC + HMAC-SHA256) before they touch disk. Values are
written as `enc:v1:<token>`; anything without that prefix is treated as
legacy plaintext: still readable, and re-encrypted in place by the boot
migration (`encrypt_existing`), so upgrades are seamless.

Key material: `DASHBOARD_ENCRYPTION_KEY` (recommended — set it once and
keep it stable), falling back to the JWT secret so encryption is on by
default. The caveat of the fallback is documented loudly: rotating
`DASHBOARD_JWT_SECRET` without having pinned a dedicated encryption key
makes previously stored secrets undecryptable. A failed decrypt is an
HONEST failure — the value reads back empty, so dependent features
degrade to their not-configured behaviour instead of sending garbage
credentials to a vendor.
"""
import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("dashboard_api.secretstore")

_PREFIX = "enc:v1:"

# Every DB column that holds a secret (the boot migration sweeps these).
SECRET_COLUMNS = (
    ("connectors", "api_key"),
    ("integrations", "api_key"),
    ("users", "slack_webhook"),
    ("users", "mfa_secret"),
)


def _fernet() -> Fernet:
    from dashboard_api.config import JWT_SECRET
    secret = os.environ.get("DASHBOARD_ENCRYPTION_KEY") or JWT_SECRET
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


def encrypt(value: str | None) -> str | None:
    """Encrypt a secret for storage. None/empty pass through; already-encrypted
    values are returned unchanged (idempotent)."""
    if not value:
        return value
    s = str(value)
    if s.startswith(_PREFIX):
        return s
    return _PREFIX + _fernet().encrypt(s.encode()).decode()


def decrypt(value: str | None) -> str | None:
    """Read a stored secret. Legacy plaintext passes through unchanged; an
    undecryptable token (rotated key) reads back as '' so callers degrade to
    not-configured rather than using a corrupt credential."""
    if not value:
        return value
    s = str(value)
    if not s.startswith(_PREFIX):
        return s  # legacy plaintext (pre-encryption row)
    try:
        return _fernet().decrypt(s[len(_PREFIX):].encode()).decode()
    except InvalidToken:
        logger.warning(
            "Stored secret could not be decrypted (encryption key changed?) — "
            "treating as not configured. Set DASHBOARD_ENCRYPTION_KEY and keep it stable.")
        return ""


def is_encrypted(value: str | None) -> bool:
    return bool(value) and str(value).startswith(_PREFIX)


def encrypt_existing(conn) -> int:
    """Boot migration: encrypt any legacy plaintext secrets in place.
    Idempotent; returns how many values were upgraded."""
    upgraded = 0
    for table, col in SECRET_COLUMNS:
        rows = conn.execute(
            f"SELECT id, {col} AS v FROM {table} WHERE {col} IS NOT NULL AND {col} != ''"
        ).fetchall()
        for r in rows:
            if not is_encrypted(r["v"]):
                conn.execute(f"UPDATE {table} SET {col}=? WHERE id=?", (encrypt(r["v"]), r["id"]))
                upgraded += 1
    if upgraded:
        logger.info("Encrypted %d legacy plaintext secret(s) at rest", upgraded)
    return upgraded
