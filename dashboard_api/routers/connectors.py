"""Connector management: register/run threat-intel sources that feed the IOC store."""
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user, require_perm
from dashboard_api.connectors import KIND_PRESETS, run_connector
from dashboard_api.db import audit, dumps, get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/connectors", tags=["connectors"], dependencies=[Depends(current_user)])

# api_key is never returned to the browser; we expose only whether one is set.
_PUBLIC = ("id, name, kind, url, auth_header, enabled, interval_minutes, field_map, "
           "status, last_run, last_error, indicator_count, builtin, created_at, created_by")


class ConnectorCreate(BaseModel):
    name: str
    kind: str
    url: str | None = None
    api_key: str | None = None
    auth_header: str | None = None
    interval_minutes: int = 60
    field_map: dict = {}
    enabled: bool = True


class ConnectorUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    api_key: str | None = None
    auth_header: str | None = None
    interval_minutes: int | None = None
    field_map: dict | None = None
    enabled: bool | None = None


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _public_row(row) -> dict:
    d = row_to_dict(row)
    d["hasKey"] = bool(d.pop("api_key", None)) if "api_key" in d else None
    return d


@router.get("/kinds")
def list_kinds():
    """Preset metadata for the 'Add connector' form."""
    return [{"kind": k, **v} for k, v in KIND_PRESETS.items()]


@router.get("")
def list_connectors(user: dict = Depends(current_user)):
    where, params = "", []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        where, params = "WHERE org_id=?", [tenancy.org_of(user)]
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT {_PUBLIC}, (api_key IS NOT NULL AND api_key != '') AS has_key "
            f"FROM connectors {where} ORDER BY builtin DESC, name", params
        ).fetchall()
    return rows_to_dicts(rows)


@router.post("", status_code=201)
def create_connector(body: ConnectorCreate, user: dict = Depends(require_perm("connectors.manage"))):
    if body.kind not in KIND_PRESETS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {sorted(KIND_PRESETS)}")
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Connector name is required")
    if KIND_PRESETS[body.kind]["needs_key"] and not (body.api_key or "").strip():
        raise HTTPException(status_code=400, detail=f"{KIND_PRESETS[body.kind]['label']} requires an API key")
    from dashboard_api.licensing import check_limit
    with get_conn() as conn:
        limit_err = check_limit(conn, "connectors")
    if limit_err:
        raise HTTPException(status_code=402, detail=limit_err)
    cid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO connectors (id,name,kind,url,api_key,auth_header,enabled,"
            "interval_minutes,field_map,status,builtin,created_at,created_by,org_id) "
            "VALUES (?,?,?,?,?,?,?,?,?, 'idle',0,?,?,?)",
            (cid, name, body.kind, (body.url or KIND_PRESETS[body.kind]["default_url"]) or None,
             body.api_key or None, body.auth_header or None, 1 if body.enabled else 0,
             max(5, body.interval_minutes), dumps(body.field_map or {}), _now(), user["email"],
             tenancy.org_of(user)),
        )
        audit(conn, user["email"], "connector.create", cid, f"kind={body.kind} name={name}")
        conn.commit()
        row = conn.execute(f"SELECT {_PUBLIC} FROM connectors WHERE id=?", (cid,)).fetchone()
    return row_to_dict(row)


@router.patch("/{connector_id}")
def update_connector(connector_id: str, body: ConnectorUpdate,
                     user: dict = Depends(require_perm("connectors.manage"))):
    fields, values = [], []
    for col in ("name", "url", "auth_header", "interval_minutes"):
        v = getattr(body, col)
        if v is not None:
            fields.append(f"{col}=?"); values.append(v)
    if body.api_key is not None:
        fields.append("api_key=?"); values.append(body.api_key or None)
    if body.field_map is not None:
        fields.append("field_map=?"); values.append(dumps(body.field_map))
    if body.enabled is not None:
        fields.append("enabled=?"); values.append(1 if body.enabled else 0)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    values.append(connector_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE connectors SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Connector not found")
        audit(conn, user["email"], "connector.update", connector_id)
        conn.commit()
        row = conn.execute(f"SELECT {_PUBLIC} FROM connectors WHERE id=?", (connector_id,)).fetchone()
    return row_to_dict(row)


@router.delete("/{connector_id}", status_code=204)
def delete_connector(connector_id: str, user: dict = Depends(require_perm("connectors.manage"))):
    with get_conn() as conn:
        row = conn.execute("SELECT builtin FROM connectors WHERE id=?", (connector_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Connector not found")
        if row["builtin"]:
            raise HTTPException(status_code=400, detail="Built-in connectors can be disabled but not deleted")
        conn.execute("DELETE FROM connectors WHERE id=?", (connector_id,))
        audit(conn, user["email"], "connector.delete", connector_id)
        conn.commit()
    return None


@router.post("/{connector_id}/run")
def run_now(connector_id: str, user: dict = Depends(require_perm("connectors.manage"))):
    """Sync this connector immediately and return the import result."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Connector not found")
    connector = dict(row)
    if isinstance(connector.get("field_map"), str):
        try:
            connector["field_map"] = json.loads(connector["field_map"])
        except (ValueError, TypeError):
            connector["field_map"] = {}
    result = run_connector(connector, actor=user["email"])
    with get_conn() as conn:
        updated = conn.execute(f"SELECT {_PUBLIC} FROM connectors WHERE id=?", (connector_id,)).fetchone()
    return {"result": result, "connector": row_to_dict(updated)}
