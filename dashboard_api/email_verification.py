"""Email-ownership verification for self-service signups.

Gated by config.REQUIRE_EMAIL_VERIFICATION and only active when SMTP is
configured. A pending user gets a single-use, time-limited token: the raw
token is emailed, only its SHA-256 hash is persisted (in the `settings` table,
so there is no schema migration), and login is blocked until the account is
verified. Honest by construction - if SMTP can't send, the feature simply
isn't engaged rather than trapping users in an unverifiable pending state.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from html import escape

from dashboard_api import mailer
from dashboard_api.config import APP_BASE_URL

TOKEN_TTL_HOURS = 24
_PREFIX = "emailverify:"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


def issue_token(conn, user_id: str) -> str:
    """Create a verification token for user_id, store its hash + expiry, and
    return the raw token (the only place it ever exists in the clear)."""
    token = secrets.token_urlsafe(32)
    expires = (_now() + timedelta(hours=TOKEN_TTL_HOURS)).replace(microsecond=0).isoformat()
    conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",
                 (_PREFIX + _hash(token), f"{user_id}|{expires}"))
    return token


def verify_token(conn, token: str) -> str | None:
    """Consume a token (single-use). Returns the user_id if it was valid and
    unexpired, else None. Any matched token is deleted whether or not it had
    expired, so a link can never be replayed."""
    key = _PREFIX + _hash(token)
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if not row or not row[0]:
        return None
    conn.execute("DELETE FROM settings WHERE key=?", (key,))  # single-use
    try:
        user_id, expires = str(row[0]).split("|", 1)
        exp = datetime.fromisoformat(expires)
    except Exception:
        return None
    if _now() > exp:
        return None
    return user_id


def verification_link(token: str) -> str:
    base = APP_BASE_URL or ""
    return f"{base}/verify?token={token}" if base else f"/verify?token={token}"


def send_verification(to_email: str, name: str, token: str) -> dict:
    """Email the verification link. Returns the mailer result (never raises)."""
    link = verification_link(token)
    safe_name = escape(name or "there")
    subject = "Verify your ThreatOrbit account"
    html = (
        f"<p>Hi {safe_name},</p>"
        f"<p>Confirm your email address to activate your ThreatOrbit account:</p>"
        f'<p><a href="{escape(link)}">Verify my email</a></p>'
        f"<p>Or paste this link into your browser:<br>{escape(link)}</p>"
        f"<p>This link expires in {TOKEN_TTL_HOURS} hours. If you didn't sign up, you can ignore this email.</p>"
    )
    text = (f"Verify your ThreatOrbit account:\n{link}\n\n"
            f"This link expires in {TOKEN_TTL_HOURS} hours. If you didn't sign up, ignore this email.")
    return mailer.send_email(to_email, subject, html, text=text)
