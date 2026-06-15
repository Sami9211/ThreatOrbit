"""SCIM 2.0 mapping helpers (RFC 7643 / 7644).

Pure functions that translate between the dashboard's `users` rows and SCIM
`User` resources, plus role resolution. The HTTP surface (auth, CRUD, discovery)
lives in routers/scim.py. Kept dependency-free and side-effect-free so it's
trivially unit-testable.
"""
from dashboard_api.config import SCIM_DEFAULT_ROLE, SCIM_ROLE_MAP, SCIM_TOKEN

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

_VALID_ROLES = {"admin", "manager", "analyst", "viewer"}
_TRUE = (True, "true", "True", 1, "1")


def configured() -> bool:
    return bool(SCIM_TOKEN)


def _default_role() -> str:
    return SCIM_DEFAULT_ROLE if SCIM_DEFAULT_ROLE in _VALID_ROLES else "viewer"


def resolve_role(scim_roles) -> str:
    """Map a SCIM `roles` attribute (list of {value:..} or strings) to a
    dashboard role via SCIM_ROLE_MAP; falls back to the configured default."""
    for r in scim_roles or []:
        val = r.get("value") if isinstance(r, dict) else r
        mapped = SCIM_ROLE_MAP.get(val)
        if mapped in _VALID_ROLES:
            return mapped
    return _default_role()


def to_scim(user: dict, base_url: str) -> dict:
    """A `users` row (dict) -> a SCIM User resource."""
    name = user.get("name") or ""
    given, _, family = name.partition(" ")
    created = user.get("created_at") or ""
    return {
        "schemas": [USER_SCHEMA],
        "id": user["id"],
        "userName": user["email"],
        "name": {"formatted": name, "givenName": given, "familyName": family},
        "displayName": name,
        "active": user.get("status") == "active",
        "emails": [{"value": user["email"], "primary": True, "type": "work"}],
        "meta": {
            "resourceType": "User",
            "created": created,
            "lastModified": user.get("last_login") or created,
            "location": f"{base_url}/scim/v2/Users/{user['id']}",
        },
    }


def from_scim(body: dict) -> dict:
    """A SCIM User payload -> fields for provisioning. Raises ValueError on bad
    input (the router maps that to a 400 SCIM error)."""
    email = (body.get("userName") or "").strip().lower()
    if "@" not in email:  # some IdPs only populate emails[]
        for e in body.get("emails") or []:
            v = (e.get("value") if isinstance(e, dict) else e) or ""
            if "@" in v:
                email = v.strip().lower()
                break
    if "@" not in email:
        raise ValueError("userName (an email address) is required")
    n = body.get("name") or {}
    name = (n.get("formatted")
            or " ".join(p for p in (n.get("givenName"), n.get("familyName")) if p).strip()
            or body.get("displayName")
            or email.split("@", 1)[0])
    # `active` defaults to True when absent (provisioning an active user).
    status = "active" if body.get("active", True) in _TRUE else "disabled"
    return {"email": email, "name": str(name).strip(), "status": status,
            "role": resolve_role(body.get("roles"))}


def apply_patch(user: dict, ops: list) -> dict:
    """Apply SCIM PatchOp operations to a user dict, returning the updated copy.
    Supports the operations IdPs actually send: replace `active`
    (deactivate/reactivate), replace name/displayName, and pathless value maps."""
    out = dict(user)
    for op in ops or []:
        if (op.get("op") or "").lower() not in ("replace", "add"):
            continue
        path, value = op.get("path"), op.get("value")
        if path:
            _set_path(out, path, value)
        elif isinstance(value, dict):
            for k, v in value.items():
                _set_path(out, k, v)
    return out


def _set_path(user: dict, path: str, value):
    p = (path or "").lower()
    if p == "active":
        user["status"] = "active" if value in _TRUE else "disabled"
    elif p in ("displayname", "name.formatted"):
        user["name"] = str(value)
    elif p == "username":
        user["email"] = str(value).strip().lower()
    # Unmodelled paths are ignored (small, explicit attribute surface).


def error(status: int, detail: str) -> dict:
    return {"schemas": [ERROR_SCHEMA], "detail": detail, "status": str(status)}
