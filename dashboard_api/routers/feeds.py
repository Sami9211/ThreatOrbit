"""Threat feed routes: list feeds/sources, create, toggle, and a summary."""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/feeds", tags=["feeds"], dependencies=[Depends(current_user)])

_FEED_TYPES = {"commercial", "opensource", "community", "internal"}


class FeedToggle(BaseModel):
    enabled: bool


class FeedCreate(BaseModel):
    name: str
    provider: str | None = None
    type: str = "opensource"
    url: str | None = None
    format: str = "STIX 2.1"
    sync_interval: int = 3600
    reliability: str = "B"


@router.get("")
def list_feeds(type: str | None = None, status: str | None = None,
               user: dict = Depends(current_user)):
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
    if type:
        clauses.append("type=?"); params.append(type)
    if status:
        clauses.append("status=?"); params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM feeds {where} ORDER BY indicators DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.get("/summary")
def feeds_summary(user: dict = Depends(current_user)):
    # Workspace clause for the rollups - a no-op until multi-tenancy is on.
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT status, enabled, indicators, type FROM feeds WHERE 1=1 {sc}", sp).fetchall()
    return {
        "totalFeeds": len(rows),
        "active": sum(1 for r in rows if r["status"] == "active"),
        "errored": sum(1 for r in rows if r["status"] == "error"),
        "totalIndicators": sum(r["indicators"] for r in rows),
        "byType": {t: sum(1 for r in rows if r["type"] == t)
                   for t in ("commercial", "opensource", "community", "internal")},
    }


@router.post("", status_code=201)
def create_feed(body: FeedCreate, user: dict = Depends(current_user)):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Feed name is required")
    if body.type not in _FEED_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {sorted(_FEED_TYPES)}")
    if body.reliability not in ("A", "B", "C"):
        raise HTTPException(status_code=400, detail="reliability must be A, B or C")
    fid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO feeds (id,name,provider,type,status,enabled,indicators,last_sync,"
            "sync_interval,reliability,url,format,org_id) VALUES (?,?,?,?,'active',1,0,NULL,?,?,?,?,?)",
            (fid, name, body.provider or name, body.type, body.sync_interval,
             body.reliability, body.url, body.format, tenancy.org_of(user)),
        )
        audit(conn, user["email"], "feed.create", fid, f"name={name} type={body.type}")
        conn.commit()
        row = conn.execute("SELECT * FROM feeds WHERE id=?", (fid,)).fetchone()
    return row_to_dict(row)


@router.patch("/{feed_id}")
def toggle_feed(feed_id: str, body: FeedToggle, user: dict = Depends(current_user)):
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE feeds SET enabled=?, status=? WHERE id=?",
            (1 if body.enabled else 0, "active" if body.enabled else "paused", feed_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Feed not found")
        audit(conn, user["email"], "feed.toggle", feed_id, f"enabled={body.enabled}")
        conn.commit()
        row = conn.execute("SELECT * FROM feeds WHERE id=?", (feed_id,)).fetchone()
    return row_to_dict(row)
