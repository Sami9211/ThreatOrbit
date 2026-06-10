"""Licensing — signed license keys + plan limits, enforced server-side.

The pricing tiers the site sells become real:

  * a license key is a base64url JSON payload (`plan`, `seats`, `connectors`,
    `expires`, `org`) signed with HMAC-SHA256 (`DASHBOARD_LICENSE_SECRET`), so
    keys can't be forged or tampered with;
  * `current_license()` resolves the active license (activated key, else the
    built-in enterprise default so existing installs lose nothing);
  * enforcement points call `check_limit()` — adding a user/connector beyond
    the plan's seats fails with 402, naming the limit.

Issuing keys is the vendor side (`generate_key`), exposed admin-only so a
self-hosted operator can mint keys for their own tenants.
"""
import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone

LICENSE_SECRET = os.environ.get("DASHBOARD_LICENSE_SECRET", "dev-license-secret-change-me")

PLANS = {
    "starter":    {"label": "Starter",    "seats": 5,    "connectors": 3},
    "pro":        {"label": "Pro",        "seats": 25,   "connectors": 10},
    "enterprise": {"label": "Enterprise", "seats": None, "connectors": None},  # unlimited
}

_BUILTIN = {"plan": "enterprise", "seats": None, "connectors": None,
            "expires": None, "org": "built-in", "builtin": True}


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload: bytes) -> str:
    return _b64e(hmac.new(LICENSE_SECRET.encode(), payload, hashlib.sha256).digest())


def generate_key(*, plan: str, org: str, seats: int | None = None,
                 connectors: int | None = None, expires: str | None = None) -> str:
    """Mint a signed license key (vendor side)."""
    if plan not in PLANS:
        raise ValueError(f"plan must be one of {sorted(PLANS)}")
    limits = PLANS[plan]
    payload = json.dumps({
        "plan": plan, "org": org,
        "seats": seats if seats is not None else limits["seats"],
        "connectors": connectors if connectors is not None else limits["connectors"],
        "expires": expires,
    }, separators=(",", ":"), sort_keys=True).encode()
    return f"TOL-{_b64e(payload)}.{_sign(payload)}"


def verify_key(key: str) -> dict:
    """Validate a key's signature + expiry. Raises ValueError when invalid."""
    if not key or not key.startswith("TOL-") or "." not in key:
        raise ValueError("malformed license key")
    body, _, sig = key[4:].partition(".")
    try:
        payload = _b64d(body)
    except Exception:
        raise ValueError("malformed license key")
    if not hmac.compare_digest(_sign(payload), sig):
        raise ValueError("invalid license signature")
    data = json.loads(payload)
    if data.get("plan") not in PLANS:
        raise ValueError("unknown plan in license")
    exp = data.get("expires")
    if exp:
        try:
            edt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            if edt.tzinfo is None:
                edt = edt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            raise ValueError("invalid expiry in license")
        if edt < datetime.now(timezone.utc):
            raise ValueError("license expired")
    return data


def current_license(conn) -> dict:
    """The active license: an activated key when present (and still valid),
    else the built-in enterprise default."""
    row = conn.execute("SELECT value FROM settings WHERE key='license_key'").fetchone()
    if row and row["value"]:
        try:
            return {**verify_key(row["value"]), "builtin": False}
        except ValueError as e:
            return {**_BUILTIN, "warning": f"stored license invalid: {e}"}
    return dict(_BUILTIN)


def usage(conn) -> dict:
    return {
        "seats": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "connectors": conn.execute("SELECT COUNT(*) FROM connectors").fetchone()[0],
    }


def check_limit(conn, kind: str) -> str | None:
    """Return an error message when adding one more `kind` (seats|connectors)
    would exceed the active plan's limit; None when allowed."""
    lic = current_license(conn)
    limit = lic.get(kind)
    if limit is None:
        return None
    used = usage(conn)[kind]
    if used + 1 > int(limit):
        noun = "users" if kind == "seats" else "connectors"
        return (f"{PLANS[lic['plan']]['label']} plan allows {limit} {noun} "
                f"({used} in use) — upgrade the license to add more")
    return None
