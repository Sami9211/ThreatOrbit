"""Threat feed routes: list feeds/sources, create, toggle, and a summary."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user, require_perm
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
        out = rows_to_dicts(rows)
        if not out:
            # The `feeds` table is a vestigial duplicate of `connectors` and is
            # empty by design in live mode - which is why the Threat Feeds page
            # read "from 0 sources" and "No sources configured yet" while two
            # connectors were actively importing 315,185 indicators. Until the
            # table is removed (see the Phase 1 removal list), report the real
            # sources rather than an empty list that is simply false.
            out = _feeds_from_connectors(conn, type_filter=type, status_filter=status)
    return out


def _feeds_from_connectors(conn, *, type_filter=None, status_filter=None) -> list[dict]:
    """Present configured connectors in the `feeds` response shape.

    Same fields the page already reads, sourced from the table that actually
    holds the truth. `indicators` is the connector's own running total, which is
    what it has imported - not a nominal daily rate.
    """
    rows = conn.execute(
        "SELECT id, name, kind, url, enabled, status, last_run, indicator_count "
        "FROM connectors ORDER BY indicator_count DESC").fetchall()
    out = []
    for r in rows:
        status = "active" if (r["enabled"] and r["status"] != "error") else (
            "error" if r["status"] == "error" else "paused")
        if status_filter and status != status_filter:
            continue
        # Every connector this platform ships is an open-source feed; a bespoke
        # one added by an operator is too, as far as this field is concerned.
        if type_filter and type_filter != "opensource":
            continue
        out.append({
            "id": r["id"], "name": r["name"], "provider": r["kind"],
            "type": "opensource", "url": r["url"], "format": "native",
            "enabled": r["enabled"], "status": status,
            "indicators": r["indicator_count"] or 0,
            "last_sync": r["last_run"], "reliability": "B",
            # Flagged so a caller can tell this came from the connector table
            # rather than from a configured `feeds` row.
            "derived_from": "connector",
        })
    return out


@router.get("/summary")
def feeds_summary(user: dict = Depends(current_user)):
    # Workspace clause for the rollups - a no-op until multi-tenancy is on.
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0,
                                                  microsecond=0).isoformat()
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT status, enabled, indicators, type FROM feeds WHERE 1=1 {sc}", sp).fetchall()
        derived = []
        if not rows:
            # Same reason as list_feeds: the `feeds` table is empty by design in
            # live mode, so summing it reported "Total IOCs 0" over a store
            # holding 315,185.
            derived = _feeds_from_connectors(conn)
        # Real "IOCs today" - indicators first seen since midnight UTC, not a sum
        # of per-feed nominal daily rates.
        new_today = conn.execute(
            f"SELECT COUNT(*) AS n FROM iocs WHERE first_seen >= ? {sc}", [midnight] + sp
        ).fetchone()["n"]
        # The store's OWN count, not a sum of per-source tallies. Those tallies
        # double-count anything two feeds both list, which after the
        # corroboration work is a large and growing share of the store.
        total_indicators = conn.execute(
            f"SELECT COUNT(*) AS n FROM iocs WHERE 1=1 {sc}", sp).fetchone()["n"]
    if derived:
        return {
            "totalFeeds": len(derived),
            "active": sum(1 for r in derived if r["status"] == "active"),
            "errored": sum(1 for r in derived if r["status"] == "error"),
            "totalIndicators": total_indicators,
            "newToday": new_today,
            "byType": {"commercial": 0, "opensource": len(derived),
                       "community": 0, "internal": 0},
        }
    return {
        "totalFeeds": len(rows),
        "active": sum(1 for r in rows if r["status"] == "active"),
        "errored": sum(1 for r in rows if r["status"] == "error"),
        "totalIndicators": total_indicators,
        "newToday": new_today,
        "byType": {t: sum(1 for r in rows if r["type"] == t)
                   for t in ("commercial", "opensource", "community", "internal")},
    }


@router.post("", status_code=201)
def create_feed(body: FeedCreate, user: dict = Depends(require_perm("connectors.manage"))):
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
def toggle_feed(feed_id: str, body: FeedToggle, user: dict = Depends(require_perm("connectors.manage"))):
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
