"""SCIM 2.0 provisioning endpoints (RFC 7644).

An IdP (Okta, Entra ID / Azure AD, OneLogin…) pushes user lifecycle here -
create, update, deactivate - authenticating with a bearer token (config
SCIM_TOKEN). With no token configured every endpoint returns 404. Provisioned
users live in the same `users` table the dashboard uses and sign in through the
existing OIDC SSO.

Scope: the `User` resource + the discovery documents IdPs probe
(ServiceProviderConfig / ResourceTypes / Schemas). Deactivation is a soft
disable (status='disabled') so owned records (alerts, cases) aren't orphaned;
Group push and externalId filtering are tracked follow-ups.
"""
import hmac
import re
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from dashboard_api import scim, tenancy
from dashboard_api.auth import hash_password
from dashboard_api.config import SCIM_TOKEN
from dashboard_api.db import audit, get_conn, row_to_dict

router = APIRouter(prefix="/scim/v2", tags=["scim"])

_FILTER_RE = re.compile(r'userName\s+eq\s+"([^"]+)"', re.IGNORECASE)
_SCIM_MEDIA = "application/scim+json"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _json(data, status: int = 200) -> JSONResponse:
    return JSONResponse(content=data, status_code=status, media_type=_SCIM_MEDIA)


def require_scim(authorization: str | None = Header(default=None)):
    """Bearer-token gate for every SCIM route (constant-time compare)."""
    if not scim.configured():
        raise HTTPException(status_code=404, detail="SCIM is not configured on this deployment.")
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token or not hmac.compare_digest(token, SCIM_TOKEN):
        raise HTTPException(status_code=401, detail="invalid SCIM bearer token")


def _base(request: Request) -> str:
    return str(request.base_url).rstrip("/")


# ── Discovery ────────────────────────────────────────────────────────────────

@router.get("/ServiceProviderConfig", dependencies=[Depends(require_scim)])
def service_provider_config():
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://threatorbit.space/docs",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken", "name": "OAuth Bearer Token",
            "description": "Authentication via the SCIM bearer token (SCIM_TOKEN).",
            "primary": True,
        }],
    }


@router.get("/ResourceTypes", dependencies=[Depends(require_scim)])
def resource_types(request: Request):
    base = _base(request)
    user_rt = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User", "name": "User", "endpoint": "/Users", "schema": scim.USER_SCHEMA,
        "meta": {"resourceType": "ResourceType", "location": f"{base}/scim/v2/ResourceTypes/User"},
    }
    return {"schemas": [scim.LIST_SCHEMA], "totalResults": 1, "startIndex": 1,
            "itemsPerPage": 1, "Resources": [user_rt]}


@router.get("/Schemas", dependencies=[Depends(require_scim)])
def schemas():
    user_schema = {
        "id": scim.USER_SCHEMA, "name": "User",
        "description": "SCIM core User",
        "attributes": [
            {"name": "userName", "type": "string", "required": True, "uniqueness": "server"},
            {"name": "name", "type": "complex", "required": False},
            {"name": "displayName", "type": "string", "required": False},
            {"name": "active", "type": "boolean", "required": False},
            {"name": "emails", "type": "complex", "multiValued": True, "required": False},
        ],
        "meta": {"resourceType": "Schema"},
    }
    return {"schemas": [scim.LIST_SCHEMA], "totalResults": 1, "startIndex": 1,
            "itemsPerPage": 1, "Resources": [user_schema]}


# ── Users ────────────────────────────────────────────────────────────────────

@router.get("/Users", dependencies=[Depends(require_scim)])
def list_users(request: Request, filter: str | None = None,
               startIndex: int = 1, count: int = 100):
    base = _base(request)
    count = max(0, min(int(count), 500))
    start = max(1, int(startIndex))
    where, params = "", []
    if filter:
        m = _FILTER_RE.search(filter)
        if m:
            where, params = "WHERE email=?", [m.group(1).strip().lower()]
        else:
            # Unsupported filter → empty result rather than leaking the full list.
            return _json({"schemas": [scim.LIST_SCHEMA], "totalResults": 0,
                          "startIndex": start, "itemsPerPage": 0, "Resources": []})
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) c FROM users {where}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM users {where} ORDER BY created_at LIMIT ? OFFSET ?",
            (*params, count, start - 1)).fetchall()
    resources = [scim.to_scim(row_to_dict(r), base) for r in rows]
    return _json({"schemas": [scim.LIST_SCHEMA], "totalResults": total, "startIndex": start,
                  "itemsPerPage": len(resources), "Resources": resources})


@router.post("/Users", dependencies=[Depends(require_scim)])
def create_user(request: Request, body: dict):
    try:
        fields = scim.from_scim(body)
    except ValueError as e:
        return _json(scim.error(400, str(e)), 400)
    base = _base(request)
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=?", (fields["email"],)).fetchone():
            return _json(scim.error(409, "a user with this userName already exists"), 409)
        uid = str(uuid.uuid4())
        ph, salt = hash_password(secrets.token_urlsafe(24))  # IdP-managed; local pw disabled
        now = _now()
        conn.execute(
            "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
            "avatar_color,mfa_enabled,created_at,org_id) "
            "VALUES (?,?,?,?,?,?,?, '#7A3CFF', 0, ?, ?)",
            (uid, fields["email"], fields["name"], fields["role"], fields["status"],
             ph, salt, now, tenancy.DEFAULT_ORG_ID))
        audit(conn, fields["email"], "scim.user_create", uid, f"role={fields['role']}")
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return _json(scim.to_scim(row_to_dict(row), base), 201)


@router.get("/Users/{user_id}", dependencies=[Depends(require_scim)])
def get_user(request: Request, user_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return _json(scim.error(404, "user not found"), 404)
    return _json(scim.to_scim(row_to_dict(row), _base(request)))


@router.put("/Users/{user_id}", dependencies=[Depends(require_scim)])
def replace_user(request: Request, user_id: str, body: dict):
    try:
        fields = scim.from_scim(body)
    except ValueError as e:
        return _json(scim.error(400, str(e)), 400)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return _json(scim.error(404, "user not found"), 404)
        conn.execute("UPDATE users SET name=?, status=?, role=? WHERE id=?",
                     (fields["name"], fields["status"], fields["role"], user_id))
        audit(conn, fields["email"], "scim.user_replace", user_id, f"status={fields['status']}")
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return _json(scim.to_scim(row_to_dict(row), _base(request)))


@router.patch("/Users/{user_id}", dependencies=[Depends(require_scim)])
def patch_user(request: Request, user_id: str, body: dict):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return _json(scim.error(404, "user not found"), 404)
        updated = scim.apply_patch(row_to_dict(row), body.get("Operations"))
        conn.execute("UPDATE users SET name=?, status=?, email=? WHERE id=?",
                     (updated["name"], updated["status"], updated["email"], user_id))
        audit(conn, updated["email"], "scim.user_patch", user_id, f"status={updated['status']}")
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return _json(scim.to_scim(row_to_dict(row), _base(request)))


@router.delete("/Users/{user_id}", dependencies=[Depends(require_scim)])
def delete_user(user_id: str):
    """Soft delete: deactivate rather than hard-remove, so records owned by the
    user (alerts, cases, audit trail) aren't orphaned. IdPs that deprovision via
    PATCH active:false land in the same state."""
    with get_conn() as conn:
        row = conn.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return _json(scim.error(404, "user not found"), 404)
        conn.execute("UPDATE users SET status='disabled' WHERE id=?", (user_id,))
        audit(conn, row["email"], "scim.user_deactivate", user_id, "via DELETE")
        conn.commit()
    return Response(status_code=204)
