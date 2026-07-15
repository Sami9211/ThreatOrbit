"""Authentication: password hashing (PBKDF2, stdlib only) and JWT issuance.

Why PBKDF2 over bcrypt: bcrypt needs a native build that is fragile in slim
containers. PBKDF2-HMAC-SHA256 ships with the stdlib, has no build step, and at
600k iterations meets the OWASP/NIST 2023+ floor. Stored hashes are
self-describing ("<iterations>$<hex>") so the cost can be raised over time
without invalidating hashes written at an older cost.
"""
import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dashboard_api.config import JWT_SECRET, JWT_TTL_MINUTES
from dashboard_api.db import get_conn, row_to_dict

_PBKDF2_ITERS = 600_000          # cost for NEW hashes (OWASP/NIST 2023+ floor)
_PBKDF2_ITERS_LEGACY = 260_000   # assumed for hashes stored before the cost marker


# --- Minimal HS256 JWT (stdlib only) ---------------------------------------
# Implemented from the stdlib (hmac/hashlib/base64) to demonstrate the mechanics
# and keep this path dependency-free; HS256 needs nothing more. It is safe
# against algorithm-confusion because it never branches on the header `alg` (it
# only ever computes/verifies HS256). NOTE: `cryptography` IS a project
# dependency (used by secretstore/oidc/saml), so for production a maintained JWT
# library (PyJWT / Authlib / joserfc) would be the lower-assurance-risk choice;
# this hand-rolled version is a deliberate, self-contained demonstration.
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
    """Return (stored_hash, salt_hex), generating a fresh salt when not supplied.
    The stored hash is self-describing - "<iterations>$<hex>" - so the PBKDF2
    cost can be raised later without invalidating existing hashes."""
    salt = salt or os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ITERS)
    return f"{_PBKDF2_ITERS}${dk.hex()}", salt


def verify_password(password: str, stored: str, salt: str) -> bool:
    """Verify against a stored hash, honouring an embedded "<iters>$<hex>" cost
    marker and falling back to the legacy cost for hashes written before it."""
    iters, expected = _PBKDF2_ITERS_LEGACY, stored
    if stored and "$" in stored:
        head, tail = stored.split("$", 1)
        if head.isdigit():
            iters, expected = int(head), tail
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iters)
    return hmac.compare_digest(dk.hex(), expected)


def create_token(user: dict, sid: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "name": user["name"],
        "ep": int(user.get("token_epoch", 0)),   # session-revocation counter
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_TTL_MINUTES)).timestamp()),
    }
    if sid:
        payload["sid"] = sid     # per-device session row (listable + revocable)
    return _jwt_encode(payload)


_STREAM_TICKET_TTL_SECONDS = 60


def create_stream_ticket(user_id: str) -> str:
    """A short-lived, single-use token for opening the SSE stream. EventSource
    can't send an Authorization header, so a ticket rides in the URL instead of
    the long-lived session JWT (audit B3): it expires in ~60s, is consumed on
    first use, and carries a `typ=stream` marker so it can't be replayed as a
    session token. A leaked stream URL (proxy log, browser history, Referer) is
    therefore near-worthless."""
    now = datetime.now(timezone.utc)
    return _jwt_encode({
        "sub": user_id,
        "typ": "stream",
        "jti": os.urandom(12).hex(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=_STREAM_TICKET_TTL_SECONDS)).timestamp()),
    })


def decode_stream_ticket(ticket: str) -> dict:
    """Verify a stream ticket (signature + expiry + `typ`); return its payload.
    Raises 401 for anything that isn't a live stream ticket."""
    payload = _jwt_decode(ticket)            # signature + exp
    if payload.get("typ") != "stream":
        raise HTTPException(status_code=401, detail="Not a stream ticket")
    return payload


def record_session(conn, user_id: str, request=None, sid: str | None = None) -> str:
    """Create a per-device session row and return its id (used as the JWT `sid`).
    Best-effort device metadata (user-agent / client IP) for the "your sessions"
    list; the row is the unit an individual sign-out revokes."""
    sid = sid or os.urandom(16).hex()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    ua, ip = None, None
    if request is not None:
        ua = (request.headers.get("user-agent") or "")[:300] or None
        ip = getattr(getattr(request, "client", None), "host", None)
    conn.execute(
        "INSERT INTO sessions (id, user_id, created_at, last_seen, user_agent, ip, revoked) "
        "VALUES (?,?,?,?,?,?,0)",
        (sid, user_id, now, now, ua, ip),
    )
    return sid


def _seconds_since(iso: str | None) -> float:
    """Seconds since an ISO-8601 timestamp (0 if missing/unparseable)."""
    if not iso:
        return 0.0
    try:
        prev = datetime.fromisoformat(iso)
        if prev.tzinfo is None:
            prev = prev.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - prev).total_seconds()
    except ValueError:
        return 0.0


def _idle_timeout_minutes(conn) -> int:
    """The configured idle window in minutes (the `session_timeout_minutes`
    setting). Defaults to the JWT hard-expiry when unset (so the default is a
    no-op); <=0 disables the idle check entirely."""
    try:
        row = conn.execute("SELECT value FROM settings WHERE key='session_timeout_minutes'").fetchone()
        return int(row["value"]) if row and row["value"] not in (None, "") else JWT_TTL_MINUTES
    except (ValueError, TypeError, KeyError):
        return JWT_TTL_MINUTES


def _touch_session(sid: str, last_seen: str | None) -> None:
    """Advance a session's last_seen for the "last active" column. Throttled to
    once a minute and best-effort: a telemetry write must never fail a request."""
    now = datetime.now(timezone.utc)
    try:
        if last_seen:
            prev = datetime.fromisoformat(last_seen)
            if prev.tzinfo is None:
                prev = prev.replace(tzinfo=timezone.utc)
            if (now - prev).total_seconds() < 60:
                return
        with get_conn() as conn:
            conn.execute("UPDATE sessions SET last_seen=? WHERE id=?",
                         (now.replace(microsecond=0).isoformat(), sid))
            conn.commit()
    except Exception:
        pass


def decode_token(token: str) -> dict:
    return _jwt_decode(token)


_bearer = HTTPBearer(auto_error=False)

# Non-interactive service credentials. Issued API keys carry a scope-encoding
# prefix (see config.create_api_key); a presented token starting with one of
# these is a machine credential (collectors, CI, integrations) and is verified
# against the api_keys table rather than JWT-decoded. Scope maps onto the
# built-in role matrix so every require_perm gate works unchanged.
_API_KEY_PREFIXES = ("to_ak_live_", "to_sk_live_", "to_rk_live_")
_API_KEY_SCOPE_ROLE = {"admin": "admin", "write": "analyst", "read": "viewer"}


def record_api_key_use(conn, key_id: str, now_iso: str) -> None:
    """Per-key request telemetry: bump today's usage bucket (drives the real
    'requests today'/total counters in Config → API). Called wherever a key
    authenticates a request. ON CONFLICT upsert works on SQLite and Postgres."""
    conn.execute(
        "INSERT INTO api_key_usage (key_id, day, count) VALUES (?,?,1) "
        "ON CONFLICT(key_id, day) DO UPDATE SET count = api_key_usage.count + 1",
        (key_id, now_iso[:10]))


def _principal_from_api_key(token: str) -> dict | None:
    """If `token` is a ThreatOrbit API key, verify it and return a synthetic
    service principal; None if it isn't key-shaped (so the JWT path takes over).
    A key-shaped but invalid/revoked token raises 401 - it never falls through."""
    if not any(token.startswith(p) for p in _API_KEY_PREFIXES):
        return None
    # The stored secret_hash is sha256 of the full secret; look the key up by
    # that hash directly (the high-entropy digest is the lookup key, GitHub-PAT
    # style - no plaintext secret is ever stored or compared).
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, name, scope, revoked, secret_hash, org_id FROM api_keys WHERE secret_hash=?",
            (digest,)).fetchone()
        if row is None or not hmac.compare_digest(str(row["secret_hash"]), digest):
            raise HTTPException(status_code=401, detail="Invalid API key")
        if row["revoked"]:
            raise HTTPException(status_code=401, detail="API key revoked")
        conn.execute("UPDATE api_keys SET last_used=? WHERE id=?", (now, row["id"]))
        record_api_key_use(conn, row["id"], now)
        conn.commit()
    from dashboard_api.tenancy import DEFAULT_ORG_ID
    role = _API_KEY_SCOPE_ROLE.get(str(row["scope"]), "viewer")
    # A complete principal so downstream code (audit, tenancy, RBAC) is happy.
    # Org-scoped keys act in their workspace, so a collector ingests per-tenant.
    return {
        "id": row["id"], "email": f"apikey:{row['name']}", "name": row["name"],
        "role": role, "status": "active",
        "org_id": (row["org_id"] if "org_id" in row.keys() else None) or DEFAULT_ORG_ID,
        "is_service": True, "api_key_scope": row["scope"],
    }


def current_user(
    creds: HTTPAuthorizationCredentials = Security(_bearer),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    x_org_id: str | None = Header(None, alias="X-Org-Id"),
) -> dict:
    """Resolve the authenticated principal. Accepts either a human JWT (Bearer)
    or a machine API key (Bearer or X-API-Key header), fresh from the DB."""
    token = (creds.credentials if creds and creds.credentials else None) or x_api_key
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    service = _principal_from_api_key(token)
    if service is not None:
        return service
    payload = decode_token(token)
    # A stream ticket is a 60s SSE-only credential - never a session token.
    if payload.get("typ") == "stream":
        raise HTTPException(status_code=401, detail="Not a session token")
    sid = payload.get("sid")
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (payload["sub"],)).fetchone()
        sess = conn.execute("SELECT revoked, last_seen FROM sessions WHERE id=?",
                            (sid,)).fetchone() if sid else None
        idle_minutes = _idle_timeout_minutes(conn) if sid else 0
    if not row:
        raise HTTPException(status_code=401, detail="User no longer exists")
    user = row_to_dict(row)
    if user["status"] == "disabled":
        raise HTTPException(status_code=403, detail="Account disabled")
    # Session revocation: a token whose epoch is behind the user's current
    # token_epoch was issued before a "sign out" / password change / admin revoke.
    if int(payload.get("ep", 0)) < int(user.get("token_epoch", 0) or 0):
        raise HTTPException(status_code=401, detail="Session ended; please sign in again")
    # Per-device session: tokens minted with a `sid` are killable individually
    # ("sign out this device") via a row flag. Tokens without one (older sessions,
    # SSO/SAML) fall through on the epoch check alone - backward compatible.
    if sid:
        if sess is None or sess["revoked"]:
            raise HTTPException(status_code=401, detail="Session ended; please sign in again")
        # Idle timeout (sliding): sign out a session left inactive longer than the
        # configured window, even though its JWT hasn't hit its hard expiry yet.
        if idle_minutes > 0 and _seconds_since(sess["last_seen"]) > idle_minutes * 60:
            raise HTTPException(status_code=401, detail="Signed out after inactivity; please sign in again")
        _touch_session(sid, sess["last_seen"])
    user.pop("password_hash", None)
    user.pop("password_salt", None)
    # A personal Slack webhook URL is a quasi-secret: only its owner sees it,
    # via GET /auth/me/slack - never on the general principal payload.
    user.pop("slack_webhook", None)
    user.pop("mfa_secret", None)  # the TOTP secret never leaves the server
    user.pop("mfa_recovery_codes", None)  # recovery-code hashes stay server-side
    # Workspace membership (multi-tenancy foundation): default when unset.
    from dashboard_api.tenancy import DEFAULT_ORG_ID
    home_org = user.get("org_id") or DEFAULT_ORG_ID
    user["org_id"] = home_org
    # Per-workspace acting org (scale-grade RBAC): under multi-tenancy a member of
    # another workspace may act in it via X-Org-Id, taking their granted role AND
    # data scope there. Requesting a workspace you're not a member of is a 403.
    if x_org_id and x_org_id != home_org:
        from dashboard_api import tenancy
        if tenancy.enforced():
            from dashboard_api.permissions import workspace_role
            wr = workspace_role(user["id"], x_org_id)
            if wr is None:
                raise HTTPException(status_code=403, detail="No access to that workspace")
            user["org_id"] = x_org_id
            user["role"] = wr
            user["acting_org"] = x_org_id
    # Tenant lifecycle: block all access to a suspended workspace (no-op when
    # isolation is off or for the default workspace).
    if tenancy_enforced():
        with get_conn() as conn:
            from dashboard_api import tenancy
            if not tenancy.is_org_active(conn, user["org_id"]):
                raise HTTPException(status_code=403, detail="Workspace suspended")
    return user


def tenancy_enforced() -> bool:
    from dashboard_api import tenancy
    return tenancy.enforced()


def current_session_id(creds: HTTPAuthorizationCredentials = Security(_bearer)) -> str | None:
    """The caller's session id (JWT `sid`), so the sessions list can flag which
    row is "this device". None for sid-less tokens. Never raises - the paired
    `current_user` dependency already authenticates."""
    if creds is None or not creds.credentials:
        return None
    try:
        return decode_token(creds.credentials).get("sid")
    except HTTPException:
        return None


def require_role(*roles: str):
    """Dependency factory enforcing one of the given roles.

    Superseded: every endpoint now enforces a named capability via
    `require_perm` (one matrix in permissions.py instead of scattered role
    lists). Kept as an escape hatch for ad-hoc role gates in extensions."""
    def dep(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dep


def require_perm(*perms: str):
    """Dependency factory enforcing a named capability (RBAC depth). The caller
    must hold at least one of `perms` for their role. Denials are audited
    (who-tried-what), so unauthorized attempts are visible."""
    from dashboard_api.permissions import has_perm

    def dep(user: dict = Depends(current_user)) -> dict:
        role = user.get("role", "")
        if any(has_perm(role, p) for p in perms):
            return user
        # Base role lacks it. A live break-glass session grants any capability -
        # but each such elevated use is audited individually so the trail shows
        # exactly what the emergency access was used for.
        from dashboard_api import break_glass
        if break_glass.is_active(user.get("id")):
            _audit_rbac(user, "rbac.break_glass", perms, f"role={role} (emergency elevation)")
            return user
        _audit_rbac(user, "rbac.denied", perms, f"role={role}")
        raise HTTPException(status_code=403,
                            detail=f"Requires permission: {' or '.join(perms)}")
    return dep


def _audit_rbac(user: dict, action: str, perms, detail: str) -> None:
    try:
        from dashboard_api.db import audit, get_conn
        with get_conn() as conn:
            audit(conn, user.get("email", "?"), action, ",".join(perms), detail)
            conn.commit()
    except Exception:
        pass
