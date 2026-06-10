"""CTI routes: threat actors, IOCs, hunts, and a relationship graph."""
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api.auth import current_user, require_perm, require_role
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.webhooks import dispatch
from dashboard_api.ioc_lifecycle import (
    decay_iocs, effective_confidence, lifecycle_of, record_sighting, set_known_good)

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
              status: str | None = None,
              min_confidence: int | None = Query(None, ge=0, le=100),
              q: str | None = None,
              sort: str = Query("last_seen", description=f"one of {sorted(_IOC_SORTS)}"),
              order: str = Query("desc", pattern="^(asc|desc)$"),
              limit: int = Query(100, le=1000), offset: int = 0):
    if sort not in _IOC_SORTS:
        raise HTTPException(status_code=400, detail=f"sort must be one of {sorted(_IOC_SORTS)}")
    if status is not None and status not in ("active", "expired", "known-good"):
        raise HTTPException(status_code=400, detail="status must be active|expired|known-good")
    clauses, params = [], []
    for col, val in (("type", type), ("severity", severity), ("actor", actor),
                     ("source", source), ("status", status)):
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
    items = []
    for ioc in rows_to_dicts(rows):
        items.append({**ioc, "effectiveConfidence": effective_confidence(
            ioc["confidence"], ioc["last_seen"], ioc["type"])})
    return {"total": total, "items": items}


@router.post("/iocs/import", status_code=201)
def import_iocs(body: IocImport, user: dict = Depends(require_perm("cti.write"))):
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
        life = {r["status"]: r["n"] for r in conn.execute(
            "SELECT status, COUNT(*) AS n FROM iocs GROUP BY status").fetchall()}
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
        "activeIocs": life.get("active", 0),
        "expiredIocs": life.get("expired", 0),
        "knownGoodIocs": life.get("known-good", 0),
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
    life = lifecycle_of(ioc)
    if ioc.get("status") == "known-good":
        verdict = "benign"
    elif life["status"] == "expired":
        verdict = "expired"
    else:
        verdict = "malicious" if ioc["severity"] in ("critical", "high") else (
            "suspicious" if ioc["severity"] == "medium" else "clean")
    return {
        "value": ioc["value"], "found": True, "verdict": verdict,
        "confidence": ioc["confidence"], "severity": ioc["severity"],
        "threatType": ioc["threat_type"], "actor": ioc["actor"], "source": ioc["source"],
        "firstSeen": ioc["first_seen"], "lastSeen": ioc["last_seen"], "tags": ioc["tags"],
        "status": life["status"], "effectiveConfidence": life["effectiveConfidence"],
        "sightings": life["sightings"], "knownGood": ioc.get("status") == "known-good",
    }


class SightingBody(BaseModel):
    source: str = "manual"
    context: str | None = None


@router.get("/iocs/{ioc_id}")
def get_ioc(ioc_id: str):
    """IOC detail with full lifecycle (effective confidence, decay, expiry) and
    its sightings history."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="IOC not found")
        ioc = row_to_dict(row)
        sightings = rows_to_dicts(conn.execute(
            "SELECT id, ts, source, context FROM ioc_sightings WHERE ioc_id=? "
            "ORDER BY ts DESC LIMIT 50", (ioc_id,)).fetchall())
    return {**ioc, "lifecycle": lifecycle_of(ioc), "sightingsHistory": sightings}


@router.post("/iocs/{ioc_id}/sighting")
def add_sighting(ioc_id: str, body: SightingBody, user: dict = Depends(require_perm("cti.write"))):
    """Record a manual sighting — refreshes the indicator and reactivates it."""
    with get_conn() as conn:
        updated = record_sighting(conn, ioc_id=ioc_id, source=body.source.strip() or "manual",
                                  context=body.context)
        if updated is None:
            raise HTTPException(status_code=404, detail="IOC not found")
        audit(conn, user["email"], "ioc.sighting", ioc_id, f"source={body.source}")
        conn.commit()
    return {**updated, "lifecycle": lifecycle_of(updated)}


@router.post("/iocs/{ioc_id}/known-good")
def whitelist_ioc(ioc_id: str, user: dict = Depends(require_perm("cti.write"))):
    """Mark an indicator known-good: it stops matching and reads back benign."""
    with get_conn() as conn:
        if not set_known_good(conn, ioc_id, True):
            raise HTTPException(status_code=404, detail="IOC not found")
        audit(conn, user["email"], "ioc.known_good", ioc_id, "whitelisted")
        conn.commit()
        row = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
    return {**row_to_dict(row), "lifecycle": lifecycle_of(row_to_dict(row))}


@router.delete("/iocs/{ioc_id}/known-good")
def unwhitelist_ioc(ioc_id: str, user: dict = Depends(require_perm("cti.write"))):
    """Remove the known-good flag and reactivate the indicator."""
    with get_conn() as conn:
        if not set_known_good(conn, ioc_id, False):
            raise HTTPException(status_code=404, detail="IOC not found")
        audit(conn, user["email"], "ioc.known_good", ioc_id, "removed")
        conn.commit()
        row = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
    return {**row_to_dict(row), "lifecycle": lifecycle_of(row_to_dict(row))}


@router.get("/stix/bundle")
def stix_bundle(type: str | None = None, limit: int = Query(2000, le=10000)):
    """Export the IOC + actor stores as a STIX 2.1 bundle (downloadable; the
    same content the TAXII server publishes). `type=indicator|threat-actor|…`
    filters the objects."""
    from dashboard_api import stix
    with get_conn() as conn:
        actors = rows_to_dicts(conn.execute("SELECT * FROM threat_actors").fetchall())
        iocs = rows_to_dicts(conn.execute(
            "SELECT * FROM iocs WHERE status != 'known-good' ORDER BY last_seen DESC LIMIT ?",
            (limit,)).fetchall())
    objects = stix.build_objects(iocs, actors)
    if type:
        wanted = {t.strip() for t in type.split(",")}
        objects = [o for o in objects if o["type"] in wanted]
    return stix.bundle(objects)


@router.post("/iocs/decay")
def run_decay(user: dict = Depends(require_role("admin", "manager"))):
    """Run IOC decay maintenance: expire stale indicators, reactivate refreshed."""
    with get_conn() as conn:
        result = decay_iocs(conn)
        audit(conn, user["email"], "ioc.decay", None,
              f"expired={result['expired']} reactivated={result['reactivated']}")
        conn.commit()
    return result


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
def relationship_graph(limit: int = Query(120, le=600),
                       focus: str | None = None, depth: int = Query(2, ge=1, le=4)):
    """Interactive intelligence graph: actors ↔ malware ↔ techniques ↔ IOCs ↔
    sectors. Pass `focus=<nodeId>` to pivot to that node's `depth`-hop
    neighbourhood."""
    from dashboard_api import cti_graph
    with get_conn() as conn:
        return cti_graph.build(conn, focus=focus, depth=depth, ioc_limit=limit)


@router.get("/graph/expand")
def graph_expand(node: str):
    """Pivot: the immediate neighbours of a graph node, grouped by relationship."""
    from dashboard_api import cti_graph
    with get_conn() as conn:
        result = cti_graph.neighbours(conn, node)
    if result["node"] is None:
        raise HTTPException(status_code=404, detail="Node not found in graph")
    return result


@router.get("/graph/path")
def graph_path(from_: str = Query(..., alias="from"), to: str = Query(...)):
    """Path-finding: the shortest relationship chain between two graph nodes."""
    from dashboard_api import cti_graph
    with get_conn() as conn:
        return cti_graph.shortest_path(conn, from_, to)


# ── Scanner history ────────────────────────────────────────────────────────────

_SCAN_TYPES = {"url", "ip", "hash", "domain", "file"}
_VERDICTS = {"malicious", "suspicious", "clean"}


@router.post("/scans", status_code=201)
def record_scan(body: ScanRecord, user: dict = Depends(require_perm("cti.write"))):
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
