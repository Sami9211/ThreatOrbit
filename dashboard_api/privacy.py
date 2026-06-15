"""GDPR data-subject tooling: export (access / portability) + erase (right to be
forgotten, by anonymisation).

Erasure **anonymises** rather than hard-deletes: the user row's PII is replaced
and the account disabled, and the subject's email is rewritten to an anonymised
placeholder everywhere it appears as an *identity* - their audit trail and the
records they own/authored. Anonymising (not deleting) keeps audit + security
records referentially intact and satisfies retention obligations while removing
the personal data. Every rewrite is `WHERE <col> = <subject email>`, so only
this subject's references change - never threat-actor attribution or other data.
"""
import uuid
from datetime import datetime, timezone

# Columns that hold a USER's email as an identity (hand-verified; deliberately
# NOT the threat-actor `actor` columns). Anonymisation only rewrites rows whose
# value equals the subject's exact email, so there's no collateral.
_EMAIL_REFS = [
    ("audit_log", "actor"),
    ("alerts", "owner"),
    ("cases", "owner"),
    ("detection_rules", "updated_by"),
]

_EXPORT_FIELDS = ("id", "email", "name", "role", "status", "avatar_color",
                  "created_at", "last_login", "org_id", "mfa_enabled", "slack_min_severity")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def export_user(conn, user: dict) -> dict:
    """Everything held that is personal data for this subject (a DSAR response)."""
    email = user["email"]
    profile = {k: user.get(k) for k in _EXPORT_FIELDS}
    # The webhook URL is a secret; report only that one is configured.
    profile["slack_webhook_configured"] = bool(user.get("slack_webhook"))
    trail = [dict(r) for r in conn.execute(
        "SELECT ts, action, target, detail FROM audit_log WHERE actor=? ORDER BY ts",
        (email,)).fetchall()]
    references = {}
    for table, col in _EMAIL_REFS:
        references[f"{table}.{col}"] = conn.execute(
            f"SELECT COUNT(*) c FROM {table} WHERE {col}=?", (email,)).fetchone()["c"]
    return {"subject": email, "exportedAt": _now(), "profile": profile,
            "auditTrail": trail, "references": references}


def erase_user(conn, user: dict) -> dict:
    """Anonymise the subject: replace PII, disable login, rewrite identity refs.
    Caller commits + audits. Returns a summary of what changed."""
    from dashboard_api.auth import hash_password
    old = user["email"]
    anon = f"erased-{uuid.uuid4().hex[:12]}@anonymized.invalid"
    ph, salt = hash_password(uuid.uuid4().hex + uuid.uuid4().hex)  # login disabled regardless
    conn.execute(
        "UPDATE users SET email=?, name='Erased user', avatar_color='#555555', "
        "slack_webhook=NULL, slack_min_severity='high', mfa_secret=NULL, mfa_enabled=0, "
        "status='disabled', password_hash=?, password_salt=? WHERE id=?",
        (anon, ph, salt, user["id"]))
    rewritten = {}
    for table, col in _EMAIL_REFS:
        cur = conn.execute(f"UPDATE {table} SET {col}=? WHERE {col}=?", (anon, old))
        rewritten[f"{table}.{col}"] = cur.rowcount or 0
    return {"subject": old, "anonymizedTo": anon, "anonymizedAt": _now(), "rewritten": rewritten}
