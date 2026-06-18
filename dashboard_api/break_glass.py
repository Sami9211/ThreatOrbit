"""Break-glass: time-boxed emergency RBAC elevation, fully audited.

A user who holds the gating capability ``break_glass.use`` (admin + manager by
default) can activate a short-lived session that grants them EVERY capability -
for the rare case where the normal approver is unavailable. While a session is
active:

  - ``require_perm`` grants any capability the base role lacks, and audits each
    such elevated use individually (``rbac.break_glass``), so the trail shows
    exactly what was done with the elevated access;
  - activation/deactivation are audited prominently and raise a critical
    notification.

Sessions auto-expire (capped by ``DASHBOARD_BREAK_GLASS_MAX_MINUTES``) and can be
ended early. Low-privilege roles (analyst/viewer) lack ``break_glass.use``, so
they can never self-elevate - the gate is the *base* role.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

MAX_MINUTES = int(os.environ.get("DASHBOARD_BREAK_GLASS_MAX_MINUTES", "240") or "240")
DEFAULT_MINUTES = 60


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def is_active(user_id: str | None) -> bool:
    """True if `user_id` has a live (not deactivated, not expired) session."""
    if not user_id:
        return False
    from dashboard_api.db import get_conn
    try:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM break_glass WHERE user_id=? AND deactivated_at IS NULL "
                "AND expires_at > ? LIMIT 1", (user_id, _iso(_now()))).fetchone()
        return row is not None
    except Exception:
        return False


def status(user_id: str | None) -> dict:
    """The caller's current break-glass state: {active, expiresAt?, reason?, …}."""
    if not user_id:
        return {"active": False}
    from dashboard_api.db import get_conn, row_to_dict
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM break_glass WHERE user_id=? AND deactivated_at IS NULL "
            "AND expires_at > ? ORDER BY activated_at DESC LIMIT 1",
            (user_id, _iso(_now()))).fetchone()
    if not row:
        return {"active": False}
    r = row_to_dict(row)
    return {"active": True, "expiresAt": r["expires_at"], "reason": r["reason"],
            "activatedAt": r["activated_at"], "activatedBy": r["activated_by"]}


def activate(conn, *, user_id: str, reason: str, minutes: int, activated_by: str,
             org_id: str = "org-default") -> dict:
    """Open a break-glass session (replacing any live one). Caller commits +
    audits + notifies. `minutes` is clamped to [1, MAX_MINUTES]."""
    minutes = max(1, min(int(minutes or DEFAULT_MINUTES), MAX_MINUTES))
    now = _now()
    expires = now + timedelta(minutes=minutes)
    conn.execute("UPDATE break_glass SET deactivated_at=? WHERE user_id=? AND deactivated_at IS NULL",
                 (_iso(now), user_id))
    conn.execute(
        "INSERT INTO break_glass (id,user_id,reason,activated_by,activated_at,expires_at,org_id) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), user_id, reason, activated_by, _iso(now), _iso(expires), org_id))
    return {"active": True, "expiresAt": _iso(expires), "reason": reason, "minutes": minutes}


def deactivate(conn, user_id: str) -> bool:
    """End any live session early. Returns True if one was closed."""
    cur = conn.execute(
        "UPDATE break_glass SET deactivated_at=? WHERE user_id=? AND deactivated_at IS NULL",
        (_iso(_now()), user_id))
    return cur.rowcount > 0


def active_sessions() -> list[dict]:
    """All currently-live sessions (admin visibility)."""
    from dashboard_api.db import get_conn, rows_to_dicts
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM break_glass WHERE deactivated_at IS NULL AND expires_at > ? "
            "ORDER BY activated_at DESC", (_iso(_now()),)).fetchall()
    return rows_to_dicts(rows)
