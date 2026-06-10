"""CTI routes: threat actors, IOCs, hunts, and a relationship graph."""
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.webhooks import dispatch

router = APIRouter(prefix="/cti", tags=["cti"], dependencies=[Depends(current_user)])

_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "cve"}


class IocImportItem(BaseModel):
    type: str
    value: str


class IocImport(BaseModel):
    indicators: list[IocImportItem]
    confidence: int = 50
    severity: str = "medium"
    source: str = "manual-import"
    actor: str = ""
    threat_type: str = "Imported indicator"
    tags: list[str] = []


class HuntCreate(BaseModel):
    name: str
    description: str | None = None
    query: str | None = None
    technique: str | None = None


class ScanRecord(BaseModel):
    target: str
    type: str
    verdict: str
    score: float = 0
    engines: str | None = None


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


@router.post("/iocs/import", status_code=201)
def import_iocs(body: IocImport, user: dict = Depends(current_user)):
    """Bulk-insert indicators into the IOC store. Duplicates (by value) are
    skipped, invalid types rejected; returns a per-batch tally for the UI."""
    if not body.indicators:
        raise HTTPException(status_code=400, detail="No indicators supplied")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    tags_json = json.dumps(body.tags, separators=(",", ":"))
    imported = duplicates = skipped = 0
    with get_conn() as conn:
        for item in body.indicators:
            val = item.value.strip()
            itype = item.type.strip().lower()
            if not val or itype not in _IOC_TYPES:
                skipped += 1
                continue
            if conn.execute("SELECT 1 FROM iocs WHERE value=?", (val,)).fetchone():
                duplicates += 1
                continue
            conn.execute(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
                "first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), itype, val, body.threat_type,
                 max(0, min(100, body.confidence)), body.severity, body.source, body.actor,
                 now, now, tags_json),
            )
            imported += 1
        audit(conn, user["email"], "ioc.import", None,
              f"imported={imported} duplicates={duplicates} skipped={skipped}")
        conn.commit()
    if imported:
        dispatch("ioc.confirmed", {"imported": imported, "source": body.source,
                                   "severity": body.severity, "actor": body.actor or None,
                                   "importedBy": user["email"]})
    return {"imported": imported, "duplicates": duplicates, "skipped": skipped,
            "total": len(body.indicators)}


@router.get("/ioc-types")
def ioc_types():
    with get_conn() as conn:
        rows = conn.execute("SELECT type AS label, COUNT(*) AS count FROM iocs GROUP BY type ORDER BY count DESC").fetchall()
    return rows_to_dicts(rows)


@router.get("/summary")
def cti_summary():
    """Top-line CTI counts: actors by type, active actors/campaigns, IOC total."""
    with get_conn() as conn:
        actors = conn.execute("SELECT type, active, campaign_count FROM threat_actors").fetchall()
        total_iocs = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    by_type: dict[str, int] = {}
    active = active_campaigns = 0
    for a in actors:
        # Normalise type casing/format so buckets are robust ("Nation-State" → "nation-state").
        key = (a["type"] or "").lower().replace(" ", "-")
        by_type[key] = by_type.get(key, 0) + 1
        if a["active"]:
            active += 1
            active_campaigns += a["campaign_count"] or 0
    return {
        "trackedActors": len(actors),
        "activeActors": active,
        "activeCampaigns": active_campaigns,
        "nationState": by_type.get("nation-state", 0),
        "cybercrime": by_type.get("cybercrime", 0),
        "hacktivist": by_type.get("hacktivist", 0),
        "totalIocs": total_iocs,
    }


@router.get("/lookup")
def ioc_lookup(value: str):
    """Look an indicator up against the IOC store and return a verdict + enrichment.

    Exact match first, then a substring fallback (handles URLs/paths). A known
    indicator's verdict follows its severity/confidence; unknown values are
    reported clean-but-unverified so the caller can distinguish "not in our TI".
    """
    v = value.strip()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM iocs WHERE value=?", (v,)).fetchone()
        if row is None and v:
            row = conn.execute(
                "SELECT * FROM iocs WHERE value LIKE ? ORDER BY confidence DESC LIMIT 1",
                (f"%{v}%",),
            ).fetchone()
    if row is None:
        return {"value": v, "found": False, "verdict": "clean", "confidence": 0,
                "severity": None, "threatType": None, "actor": None, "source": None,
                "firstSeen": None, "lastSeen": None, "tags": []}
    ioc = row_to_dict(row)
    verdict = "malicious" if ioc["severity"] in ("critical", "high") else (
        "suspicious" if ioc["severity"] == "medium" else "clean")
    return {
        "value": ioc["value"], "found": True, "verdict": verdict,
        "confidence": ioc["confidence"], "severity": ioc["severity"],
        "threatType": ioc["threat_type"], "actor": ioc["actor"], "source": ioc["source"],
        "firstSeen": ioc["first_seen"], "lastSeen": ioc["last_seen"], "tags": ioc["tags"],
    }


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


@router.post("/hunts", status_code=201)
def create_hunt(body: HuntCreate, user: dict = Depends(current_user)):
    from dashboard_api.hunting import create_saved_hunt
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Hunt name is required")
    return create_saved_hunt("cti", name, body.description, body.query, body.technique, user["email"])


@router.post("/hunts/{hunt_id}/run")
def run_hunt(hunt_id: str, user: dict = Depends(current_user)):
    from dashboard_api.hunting import run_saved_hunt
    result = run_saved_hunt("cti", hunt_id, user["email"])
    if result is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return result


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


# ── Scanner history ────────────────────────────────────────────────────────────

_SCAN_TYPES = {"url", "ip", "hash", "domain", "file"}
_VERDICTS = {"malicious", "suspicious", "clean"}


@router.post("/scans", status_code=201)
def record_scan(body: ScanRecord, user: dict = Depends(current_user)):
    """Persist an IntelScope scan so history and stats survive reloads."""
    if body.type not in _SCAN_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {sorted(_SCAN_TYPES)}")
    if body.verdict not in _VERDICTS:
        raise HTTPException(status_code=400, detail=f"verdict must be one of {sorted(_VERDICTS)}")
    target = body.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    sid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (id,ts,target,type,verdict,score,engines,actor) VALUES (?,?,?,?,?,?,?,?)",
            (sid, now, target, body.type, body.verdict, body.score, body.engines, user["email"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return row_to_dict(row)


@router.get("/scans")
def list_scans(limit: int = Query(20, le=100)):
    """Recent scans plus aggregate stats for the scanner header."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        today_count = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE ts >= ?", (today,)
        ).fetchone()["n"]
        malicious = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE verdict='malicious'"
        ).fetchone()["n"]
    return {"items": rows_to_dicts(rows), "scansToday": today_count, "malicious": malicious}
