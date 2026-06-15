"""Authentication routes: login, registration, current user, password change.

Login and registration share a small in-memory failure throttle: repeated
failures from the same client for the same identity inside a sliding window
return 429. Success clears the counter. State is per-process, which is the
right scope for a single-instance SQLite-backed service.
"""
import re
import threading
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from dashboard_api.auth import (
    create_token, current_session_id, current_user, hash_password,
    record_session, verify_password,
)
from dashboard_api.config import ALLOW_REGISTRATION, AUTH_FAILURE_WINDOW_SEC, AUTH_MAX_FAILURES
from dashboard_api.db import audit, get_conn, row_to_dict

router = APIRouter(prefix="/auth", tags=["auth"])

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_failures: dict[str, list[float]] = {}
_failures_lock = threading.Lock()


def _throttle_key(request: Request, email: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}:{email.lower()}"


def _check_throttle(key: str):
    now = time.monotonic()
    with _failures_lock:
        attempts = [t for t in _failures.get(key, []) if now - t < AUTH_FAILURE_WINDOW_SEC]
        _failures[key] = attempts
        if len(attempts) >= AUTH_MAX_FAILURES:
            raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")


def _record_failure(key: str):
    with _failures_lock:
        _failures.setdefault(key, []).append(time.monotonic())


def _clear_failures(key: str):
    with _failures_lock:
        _failures.pop(key, None)


class LoginRequest(BaseModel):
    email: str
    password: str
    code: str | None = None  # TOTP code - required only when MFA is enrolled


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    company: str | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _public(user: dict) -> dict:
    for k in ("password_hash", "password_salt", "slack_webhook", "mfa_secret", "mfa_recovery_codes"):
        user.pop(k, None)
    return user


@router.post("/login")
def login(body: LoginRequest, request: Request):
    key = _throttle_key(request, body.email)
    _check_throttle(key)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (body.email.lower(),)).fetchone()
        if not row:
            _record_failure(key)
            raise HTTPException(status_code=401, detail="Invalid email or password")
        user = row_to_dict(row)
        if not verify_password(body.password, user["password_hash"], user["password_salt"]):
            _record_failure(key)
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if user["status"] == "disabled":
            raise HTTPException(status_code=403, detail="Account disabled")
        # TOTP step-up: enrolled users must supply a valid current code. The
        # password is verified FIRST, so this never becomes a user-enumeration
        # oracle; wrong codes count against the same login throttle.
        if user.get("mfa_enabled"):
            from dashboard_api.mfa import verify_code
            from dashboard_api.secretstore import decrypt
            secret = decrypt(user.get("mfa_secret"))
            if secret:  # enabled-but-secretless (admin reset) falls through
                if not body.code:
                    raise HTTPException(status_code=401, detail="MFA code required")
                if not verify_code(secret, body.code):
                    # Fall back to a one-time recovery code (lost authenticator).
                    from dashboard_api.mfa import consume_recovery_code
                    import json
                    remaining = consume_recovery_code(
                        json.loads(user.get("mfa_recovery_codes") or "[]"), body.code)
                    if remaining is None:
                        _record_failure(key)
                        raise HTTPException(status_code=401, detail="Invalid MFA code")
                    conn.execute("UPDATE users SET mfa_recovery_codes=? WHERE id=?",
                                 (json.dumps(remaining), user["id"]))
                    audit(conn, user["email"], "auth.mfa_recovery_used", user["id"],
                          f"remaining={len(remaining)}")
        now = _now()
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (now, user["id"]))
        sid = record_session(conn, user["id"], request)
        conn.commit()
    _clear_failures(key)
    token = create_token(user, sid=sid)
    user = _public(user)
    user["last_login"] = now
    return {"token": token, "user": user}


@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request):
    """Self-service signup. The first account ever created becomes admin;
    later signups get the analyst role and can be promoted by an admin."""
    if not ALLOW_REGISTRATION:
        raise HTTPException(status_code=403, detail="Self-service registration is disabled")
    key = _throttle_key(request, body.email)
    _check_throttle(key)

    name = body.name.strip()
    email = body.email.strip().lower()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    if len(name) > 200:
        raise HTTPException(status_code=400, detail="Name must be 200 characters or fewer")
    if not _EMAIL_RE.match(email):
        _record_failure(key)
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    if len(body.password) < 8:
        _record_failure(key)
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    ph, salt = hash_password(body.password)
    uid = str(uuid.uuid4())
    now = _now()
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            _record_failure(key)
            raise HTTPException(status_code=409, detail="An account with that email already exists")
        first_user = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0
        role = "admin" if first_user else "analyst"
        conn.execute(
            "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
            "avatar_color,mfa_enabled,last_login,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uid, email, name, role, "active", ph, salt, "#FF2E97", 0, now, now),
        )
        detail = f"role={role}" + (f" company={body.company.strip()}" if body.company and body.company.strip() else "")
        audit(conn, email, "auth.register", uid, detail)
        user = row_to_dict(conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())
        sid = record_session(conn, uid, request)
        conn.commit()
    _clear_failures(key)
    return {"token": create_token(user, sid=sid), "user": _public(user)}


@router.get("/me")
def me(user: dict = Depends(current_user)):
    return user


# ── TOTP multi-factor authentication ─────────────────────────────────────────────

class MfaCode(BaseModel):
    code: str


@router.get("/mfa")
def mfa_status(user: dict = Depends(current_user)):
    """Whether the caller has MFA enabled, and whether an enrolment is pending
    verification. The secret itself never leaves the server after enrolment."""
    import json
    with get_conn() as conn:
        row = conn.execute("SELECT mfa_enabled, mfa_secret, mfa_recovery_codes FROM users WHERE id=?",
                           (user["id"],)).fetchone()
    return {"enabled": bool(row["mfa_enabled"]),
            "pending": bool(row["mfa_secret"]) and not row["mfa_enabled"],
            "recoveryCodesRemaining": len(json.loads(row["mfa_recovery_codes"] or "[]"))}


@router.post("/mfa/enroll")
def mfa_enroll(user: dict = Depends(current_user)):
    """Start TOTP enrolment: generate a secret (stored encrypted, not yet
    active) and return it once, with the otpauth:// URI an authenticator app
    scans. MFA only turns on after /auth/mfa/verify proves the app works."""
    from dashboard_api.mfa import new_secret, otpauth_uri
    from dashboard_api.secretstore import encrypt
    with get_conn() as conn:
        row = conn.execute("SELECT mfa_enabled FROM users WHERE id=?", (user["id"],)).fetchone()
        if row["mfa_enabled"]:
            raise HTTPException(status_code=400, detail="MFA is already enabled - disable it first")
        secret = new_secret()
        conn.execute("UPDATE users SET mfa_secret=? WHERE id=?", (encrypt(secret), user["id"]))
        audit(conn, user["email"], "auth.mfa_enroll", user["id"])
        conn.commit()
    return {"secret": secret, "otpauthUri": otpauth_uri(secret, user["email"])}


@router.post("/mfa/verify")
def mfa_verify(body: MfaCode, user: dict = Depends(current_user)):
    """Prove the authenticator works (a valid current code) and switch MFA on.
    From the next login, the code is required."""
    from dashboard_api.mfa import verify_code, new_recovery_codes, hash_recovery_code
    from dashboard_api.secretstore import decrypt
    import json
    with get_conn() as conn:
        row = conn.execute("SELECT mfa_secret, mfa_enabled FROM users WHERE id=?",
                           (user["id"],)).fetchone()
        secret = decrypt(row["mfa_secret"])
        if not secret:
            raise HTTPException(status_code=400, detail="No enrolment in progress - call /auth/mfa/enroll first")
        if not verify_code(secret, body.code):
            raise HTTPException(status_code=400, detail="Invalid MFA code")
        # Issue one-time recovery codes (shown once now) so a lost authenticator
        # isn't a lockout; only their hashes are stored.
        codes = new_recovery_codes()
        conn.execute("UPDATE users SET mfa_enabled=1, mfa_recovery_codes=? WHERE id=?",
                     (json.dumps([hash_recovery_code(c) for c in codes]), user["id"]))
        audit(conn, user["email"], "auth.mfa_enabled", user["id"])
        conn.commit()
    return {"enabled": True, "recoveryCodes": codes}


@router.post("/mfa/disable")
def mfa_disable(body: MfaCode, user: dict = Depends(current_user)):
    """Turn MFA off - requires a valid current code (possession proof), so a
    hijacked session can't silently strip the second factor."""
    from dashboard_api.mfa import verify_code
    from dashboard_api.secretstore import decrypt
    with get_conn() as conn:
        row = conn.execute("SELECT mfa_secret, mfa_enabled FROM users WHERE id=?",
                           (user["id"],)).fetchone()
        if not row["mfa_enabled"]:
            raise HTTPException(status_code=400, detail="MFA is not enabled")
        if not verify_code(decrypt(row["mfa_secret"]), body.code):
            raise HTTPException(status_code=400, detail="Invalid MFA code")
        conn.execute("UPDATE users SET mfa_enabled=0, mfa_secret=NULL, mfa_recovery_codes=NULL WHERE id=?",
                     (user["id"],))
        audit(conn, user["email"], "auth.mfa_disabled", user["id"])
        conn.commit()
    return {"enabled": False}


@router.post("/mfa/recovery-codes")
def regenerate_recovery_codes(body: MfaCode, user: dict = Depends(current_user)):
    """Issue a fresh set of one-time recovery codes (invalidating the old ones).
    Requires a valid current TOTP code as possession proof."""
    from dashboard_api.mfa import verify_code, new_recovery_codes, hash_recovery_code
    from dashboard_api.secretstore import decrypt
    import json
    with get_conn() as conn:
        row = conn.execute("SELECT mfa_secret, mfa_enabled FROM users WHERE id=?",
                           (user["id"],)).fetchone()
        if not row["mfa_enabled"]:
            raise HTTPException(status_code=400, detail="MFA is not enabled")
        if not verify_code(decrypt(row["mfa_secret"]), body.code):
            raise HTTPException(status_code=400, detail="Invalid MFA code")
        codes = new_recovery_codes()
        conn.execute("UPDATE users SET mfa_recovery_codes=? WHERE id=?",
                     (json.dumps([hash_recovery_code(c) for c in codes]), user["id"]))
        audit(conn, user["email"], "auth.mfa_recovery_regenerated", user["id"])
        conn.commit()
    return {"recoveryCodes": codes}


# ── Per-user Slack notification routing ─────────────────────────────────────────

class SlackPrefs(BaseModel):
    webhook_url: str | None = None  # null/empty clears the routing
    min_severity: str = "high"


@router.get("/me/slack")
def my_slack_routing(user: dict = Depends(current_user)):
    """The caller's personal Slack routing (the URL is only ever shown to its
    owner - it is scrubbed from every other user payload and encrypted at rest)."""
    from dashboard_api.secretstore import decrypt
    with get_conn() as conn:
        row = conn.execute("SELECT slack_webhook, slack_min_severity FROM users WHERE id=?",
                           (user["id"],)).fetchone()
    url = decrypt(row["slack_webhook"])
    return {"configured": bool(url),
            "webhookUrl": url,
            "minSeverity": row["slack_min_severity"] or "high"}


@router.put("/me/slack")
def set_slack_routing(body: SlackPrefs, user: dict = Depends(current_user)):
    from dashboard_api.webhooks import _SEV_RANK
    if body.min_severity not in _SEV_RANK:
        raise HTTPException(status_code=400,
                            detail=f"min_severity must be one of {sorted(_SEV_RANK)}")
    url = (body.webhook_url or "").strip() or None
    if url:
        from dashboard_api.net_guard import validate_external_url, UnsafeUrlError
        try:
            validate_external_url(url)  # SSRF guard (blocks internal/reserved)
        except UnsafeUrlError as e:
            raise HTTPException(status_code=400, detail=str(e))
    from dashboard_api.secretstore import encrypt
    with get_conn() as conn:
        conn.execute("UPDATE users SET slack_webhook=?, slack_min_severity=? WHERE id=?",
                     (encrypt(url), body.min_severity, user["id"]))
        audit(conn, user["email"], "auth.slack_routing",
              user["id"], "configured" if url else "cleared")
        conn.commit()
    return {"configured": bool(url), "webhookUrl": url, "minSeverity": body.min_severity}


@router.post("/me/slack/test")
def test_slack_routing(user: dict = Depends(current_user)):
    """Send a test message to the caller's configured Slack webhook and report
    the real outcome (no pretend success)."""
    from dashboard_api.secretstore import decrypt
    from dashboard_api.webhooks import deliver_slack
    with get_conn() as conn:
        row = conn.execute("SELECT slack_webhook FROM users WHERE id=?", (user["id"],)).fetchone()
    url = decrypt(row["slack_webhook"])
    if not url:
        raise HTTPException(status_code=400, detail="No Slack webhook configured")
    ok = deliver_slack(url,
                       f"ThreatOrbit test notification for {user['email']} - routing works.")
    return {"delivered": ok}


@router.get("/permissions")
def my_permissions(user: dict = Depends(current_user)):
    """The caller's effective capabilities - the UI uses this to hide controls
    the role can't use (RBAC depth)."""
    from dashboard_api.permissions import CAPABILITIES, perms_for
    granted = sorted(perms_for(user["role"]))
    return {"role": user["role"], "permissions": granted,
            "capabilities": {p: p in granted for p in CAPABILITIES}}


@router.post("/change-password")
def change_password(body: PasswordChange, user: dict = Depends(current_user),
                    sid: str | None = Depends(current_session_id)):
    with get_conn() as conn:
        row = conn.execute("SELECT password_hash, password_salt FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(body.current_password, row["password_hash"], row["password_salt"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        if len(body.new_password) < 8:
            raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
        ph, salt = hash_password(body.new_password)
        # Bumping the token epoch revokes every existing session for this user
        # (security best practice on a credential change).
        new_epoch = int(user.get("token_epoch", 0) or 0) + 1
        conn.execute("UPDATE users SET password_hash=?, password_salt=?, token_epoch=? WHERE id=?",
                     (ph, salt, new_epoch, user["id"]))
        # Keep the per-device list honest: revoke every OTHER device's session row
        # (this one continues on the fresh token below).
        if sid:
            conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0 AND id<>?",
                         (user["id"], sid))
        else:
            conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0", (user["id"],))
        audit(conn, user["email"], "auth.change_password", user["id"], "other sessions revoked")
        conn.commit()
    # Issue a fresh token carrying the new epoch so THIS session continues
    # seamlessly (same sid); every other (older-epoch) session is signed out.
    return {"ok": True, "token": create_token({**user, "token_epoch": new_epoch}, sid=sid)}


@router.post("/sessions/revoke-all")
def revoke_all_sessions(user: dict = Depends(current_user)):
    """Sign out everywhere: invalidate all of the caller's tokens, including this
    one (the client must re-authenticate)."""
    with get_conn() as conn:
        conn.execute("UPDATE users SET token_epoch = token_epoch + 1 WHERE id=?", (user["id"],))
        # Tidy the per-device list too (the epoch bump already kills the tokens).
        conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0", (user["id"],))
        audit(conn, user["email"], "auth.revoke_all_sessions", user["id"])
        conn.commit()
    return {"ok": True}


@router.get("/sessions")
def list_sessions(user: dict = Depends(current_user), sid: str | None = Depends(current_session_id)):
    """The caller's active per-device sessions, most-recently-active first, with
    the current one flagged. Each can be signed out individually below."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, created_at, last_seen, user_agent, ip FROM sessions "
            "WHERE user_id=? AND revoked=0 ORDER BY last_seen DESC", (user["id"],)).fetchall()
    return [{
        "id": r["id"],
        "createdAt": r["created_at"],
        "lastSeen": r["last_seen"],
        "userAgent": r["user_agent"],
        "ip": r["ip"],
        "current": r["id"] == sid,
    } for r in rows]


@router.post("/sessions/{session_id}/revoke")
def revoke_session(session_id: str, user: dict = Depends(current_user)):
    """Sign out one device: revoke a single session you own (404 if it isn't
    yours or is already gone). Revoking the current session ends it immediately."""
    with get_conn() as conn:
        row = conn.execute("SELECT id FROM sessions WHERE id=? AND user_id=? AND revoked=0",
                           (session_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Session not found")
        conn.execute("UPDATE sessions SET revoked=1 WHERE id=?", (session_id,))
        audit(conn, user["email"], "auth.revoke_session", user["id"], f"session={session_id}")
        conn.commit()
    return {"ok": True}
