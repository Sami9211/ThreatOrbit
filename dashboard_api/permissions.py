"""Role → capability permission model (RBAC depth).

The four roles map to named, per-section/per-action capabilities. Endpoints
enforce a *capability* (e.g. `siem.write`) rather than hard-coding role names,
so authorisation is one matrix instead of scattered role lists - and the UI can
ask `/auth/permissions` for the caller's effective set to hide controls it
can't use.

Roles (most → least privileged): admin ⊃ manager ⊃ analyst ⊃ viewer.
  admin   - everything, incl. user deletion + API-key/secret administration.
  manager - platform + SOC operations; cannot delete users.
  analyst - SOC operations (triage, detections, response, intel) read+write.
  viewer  - read-only across the board.
"""

# Catalogue of capabilities (kept here so /config/roles can advertise them).
CAPABILITIES = {
    "siem.write": "Create/triage alerts, author detections, ingest logs, tune suppressions",
    "soar.write": "Run playbooks, manage cases, approve responses",
    "cti.write": "Manage indicators (import, sightings, known-good, decay), hunts",
    "darkweb.write": "Triage dark-web findings",
    "assets.write": "Create assets, recompute risk",
    "connectors.manage": "Add/run/remove ingestion connectors",
    "services.run": "Trigger companion-service fetch/sync actions",
    "reports.manage": "Create/schedule/deliver reports",
    "config.manage": "Settings, API keys, webhooks, engine, jobs, retention",
    "license.manage": "Activate, issue and clear license keys",
    "users.manage": "Create and update users",
    "users.delete": "Delete users",
    "break_glass.use": "Activate emergency break-glass elevation (time-boxed, fully audited)",
}

_ALL = set(CAPABILITIES)

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": set(_ALL),
    "manager": _ALL - {"users.delete", "license.manage"},
    "analyst": {"siem.write", "soar.write", "cti.write", "darkweb.write",
                "assets.write", "reports.manage"},
    "viewer": set(),
}


def perms_for(role: str) -> set[str]:
    if role in ROLE_PERMISSIONS:        # built-in role: authoritative, unchanged
        return ROLE_PERMISSIONS[role]
    return _custom_perms(role)          # operator-defined custom role


def _custom_perms(role: str) -> set[str]:
    """Capabilities for a custom role, read from the `roles` table. Validated
    against the catalogue and fail-closed (empty set = deny) on any error, so a
    missing/garbled role never grants access."""
    import json
    try:
        from dashboard_api.db import get_conn
        with get_conn() as conn:
            row = conn.execute("SELECT capabilities FROM roles WHERE id=?", (role,)).fetchone()
    except Exception:
        return set()
    if not row:
        return set()
    raw = row["capabilities"]
    try:
        caps = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except (ValueError, TypeError):
        return set()
    return {c for c in caps if c in CAPABILITIES}


def has_perm(role: str, perm: str) -> bool:
    return perm in perms_for(role)


def role_exists(role: str) -> bool:
    """True if `role` is a built-in or a defined custom role (for assignment)."""
    if role in ROLE_PERMISSIONS:
        return True
    try:
        from dashboard_api.db import get_conn
        with get_conn() as conn:
            return conn.execute("SELECT 1 FROM roles WHERE id=?", (role,)).fetchone() is not None
    except Exception:
        return False
