"""CTI routes: threat actors, IOCs, hunts, and a relationship graph."""
from fastapi import APIRouter, Depends, HTTPException, Query

from dashboard_api.auth import current_user
from dashboard_api.db import get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/cti", tags=["cti"], dependencies=[Depends(current_user)])


@router.get("/actors")
def list_actors(active: bool | None = None):
    where = "WHERE active=1" if active else ""
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM threat_actors {where} ORDER BY sophistication DESC, name").fetchall()
    return rows_to_dicts(rows)


@router.get("/actors/{actor_id}")
def get_actor(actor_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM threat_actors WHERE id=?", (actor_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Actor not found")
    return row_to_dict(row)


# Whitelisted IOC sort columns; anything else is rejected (no SQL injection).
_IOC_SORTS = {
    "last_seen": "last_seen",
    "first_seen": "first_seen",
    "confidence": "confidence",
    "severity": "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
                "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END",
}


@router.get("/iocs")
def list_iocs(type: str | None = None, severity: str | None = None,
              actor: str | None = None, source: str | None = None,
              min_confidence: int | None = Query(None, ge=0, le=100),
              q: str | None = None,
              sort: str = Query("last_seen", description=f"one of {sorted(_IOC_SORTS)}"),
              order: str = Query("desc", pattern="^(asc|desc)$"),
              limit: int = Query(100, le=1000), offset: int = 0):
    if sort not in _IOC_SORTS:
        raise HTTPException(status_code=400, detail=f"sort must be one of {sorted(_IOC_SORTS)}")
    clauses, params = [], []
    for col, val in (("type", type), ("severity", severity), ("actor", actor), ("source", source)):
        if val:
            clauses.append(f"{col}=?"); params.append(val)
    if min_confidence is not None:
        clauses.append("confidence>=?"); params.append(min_confidence)
    if q:
        clauses.append("value LIKE ?"); params.append(f"%{q}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order_sql = f"{_IOC_SORTS[sort]} {order.upper()}"
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM iocs {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM iocs {where} ORDER BY {order_sql} LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {"total": total, "items": rows_to_dicts(rows)}


@router.get("/ioc-types")
def ioc_types():
    with get_conn() as conn:
        rows = conn.execute("SELECT type AS label, COUNT(*) AS count FROM iocs GROUP BY type ORDER BY count DESC").fetchall()
    return rows_to_dicts(rows)


@router.get("/hunts")
def list_hunts():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description AS hypothesis, author AS analyst, "
            "query, technique, last_run, hit_count AS artifacts, "
            "status, progress, domain "
            "FROM saved_hunts WHERE domain='cti' ORDER BY last_run DESC"
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/graph")
def relationship_graph(limit: int = Query(40, le=200)):
    """Build a force-graph of actors -> IOCs they are attributed to."""
    nodes, links, seen = [], [], set()
    with get_conn() as conn:
        actors = conn.execute("SELECT name, threat_level, ioc_count FROM threat_actors").fetchall()
        iocs = conn.execute(
            "SELECT value, type, actor, severity FROM iocs WHERE actor != '' LIMIT ?", (limit,)
        ).fetchall()
    for a in actors:
        nid = f"actor:{a['name']}"
        nodes.append({"id": nid, "label": a["name"], "group": "actor",
                      "level": a["threat_level"], "size": min(30, 10 + a["ioc_count"] // 20)})
        seen.add(nid)
    for i in iocs:
        nid = f"ioc:{i['value']}"
        if nid not in seen:
            nodes.append({"id": nid, "label": i["value"], "group": "ioc",
                          "iocType": i["type"], "level": i["severity"], "size": 6})
            seen.add(nid)
        anid = f"actor:{i['actor']}"
        if anid in seen:
            links.append({"source": anid, "target": nid, "kind": "attributed"})
    return {"nodes": nodes, "links": links}
