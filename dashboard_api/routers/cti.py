"""CTI routes: threat actors, IOCs, hunts, and a relationship graph."""
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user, require_perm
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
def list_actors(active: bool | None = None, user: dict = Depends(current_user)):
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
    if active:
        clauses.append("active=1")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM threat_actors {where} ORDER BY sophistication DESC, name", params).fetchall()
    return rows_to_dicts(rows)


@router.get("/actors/{actor_id}")
def get_actor(actor_id: str, user: dict = Depends(current_user)):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM threat_actors WHERE id=?", (actor_id,)).fetchone()
    if not row or tenancy.cross_org(row, user):
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
              limit: int = Query(100, le=1000), offset: int = 0,
              user: dict = Depends(current_user)):
    if sort not in _IOC_SORTS:
        raise HTTPException(status_code=400, detail=f"sort must be one of {sorted(_IOC_SORTS)}")
    if status is not None and status not in ("active", "expired", "known-good"):
        raise HTTPException(status_code=400, detail="status must be active|expired|known-good")
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
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
                "first_seen,last_seen,tags,org_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), itype, val, body.threat_type,
                 max(0, min(100, body.confidence)), body.severity, body.source, body.actor,
                 now, now, tags_json, tenancy.org_of(user)),
            )
            imported += 1
        _record_import(conn, body.source or "manual import", "manual", imported, duplicates,
                       skipped, user["email"])
        audit(conn, user["email"], "ioc.import", None,
              f"imported={imported} duplicates={duplicates} skipped={skipped}")
        conn.commit()
    if imported:
        dispatch("ioc.confirmed", {"imported": imported, "source": body.source,
                                   "severity": body.severity, "actor": body.actor or None,
                                   "importedBy": user["email"]},
                 org=tenancy.org_of(user))
    return {"imported": imported, "duplicates": duplicates, "skipped": skipped,
            "total": len(body.indicators)}


def _record_import(conn, source: str, method: str, imported: int, duplicates: int,
                   skipped: int, actor: str):
    status = "completed" if imported and not skipped else "partial" if imported else "failed"
    conn.execute(
        "INSERT INTO ioc_imports (id,source,method,imported,duplicates,skipped,status,actor,ts) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), source[:120], method, imported, duplicates, skipped, status, actor,
         datetime.now(timezone.utc).replace(microsecond=0).isoformat()))


@router.get("/import-history")
def import_history(limit: int = Query(50, le=200)):
    """Recent IOC imports (manual / MISP / connector) - the Feeds → Import log."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, source, method, imported, duplicates, skipped, status, actor, ts "
            "FROM ioc_imports ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return rows_to_dicts(rows)


@router.get("/ioc-types")
def ioc_types():
    with get_conn() as conn:
        rows = conn.execute("SELECT type AS label, COUNT(*) AS count FROM iocs GROUP BY type ORDER BY count DESC").fetchall()
    return rows_to_dicts(rows)


@router.get("/summary")
def cti_summary(user: dict = Depends(current_user)):
    """Top-line CTI counts: actors by type, active actors/campaigns, IOC total."""
    # Workspace clause for the rollups - a no-op until multi-tenancy is on.
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        actors = conn.execute(
            f"SELECT type, active, campaign_count FROM threat_actors WHERE 1=1 {sc}", sp).fetchall()
        total_iocs = conn.execute(f"SELECT COUNT(*) FROM iocs WHERE 1=1 {sc}", sp).fetchone()[0]
        life = {r["status"]: r["n"] for r in conn.execute(
            f"SELECT status, COUNT(*) AS n FROM iocs WHERE 1=1 {sc} GROUP BY status", sp).fetchall()}
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
def get_ioc(ioc_id: str, user: dict = Depends(current_user)):
    """IOC detail with full lifecycle (effective confidence, decay, expiry) and
    its sightings history."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row or tenancy.cross_org(row, user):
            raise HTTPException(status_code=404, detail="IOC not found")
        ioc = row_to_dict(row)
        sightings = rows_to_dicts(conn.execute(
            "SELECT id, ts, source, context FROM ioc_sightings WHERE ioc_id=? "
            "ORDER BY ts DESC LIMIT 50", (ioc_id,)).fetchall())
    return {**ioc, "lifecycle": lifecycle_of(ioc), "sightingsHistory": sightings}


@router.post("/iocs/{ioc_id}/sighting")
def add_sighting(ioc_id: str, body: SightingBody, user: dict = Depends(require_perm("cti.write"))):
    """Record a manual sighting - refreshes the indicator and reactivates it."""
    with get_conn() as conn:
        updated = record_sighting(conn, ioc_id=ioc_id, source=body.source.strip() or "manual",
                                  context=body.context)
        if updated is None:
            raise HTTPException(status_code=404, detail="IOC not found")
        audit(conn, user["email"], "ioc.sighting", ioc_id, f"source={body.source}")
        conn.commit()
    return {**updated, "lifecycle": lifecycle_of(updated)}


class ReportCreate(BaseModel):
    title: str
    summary: str | None = None
    body: str | None = None
    tlp: str = "amber"
    actors: list[str] = []
    iocs: list[str] = []
    tags: list[str] = []


class ReportUpdate(BaseModel):
    title: str | None = None
    summary: str | None = None
    body: str | None = None
    tlp: str | None = None
    status: str | None = None
    actors: list[str] | None = None
    iocs: list[str] | None = None
    tags: list[str] | None = None


class MispImport(BaseModel):
    event: dict


_TLP = {"white", "green", "amber", "red"}


@router.get("/reports")
def list_reports(status: str | None = None):
    where = "WHERE status=?" if status else ""
    params = [status] if status else []
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM intel_reports {where} ORDER BY updated_at DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.post("/reports", status_code=201)
def create_report(body: ReportCreate, user: dict = Depends(require_perm("cti.write"))):
    title = body.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Report title is required")
    if body.tlp not in _TLP:
        raise HTTPException(status_code=400, detail=f"tlp must be one of {sorted(_TLP)}")
    from dashboard_api.db import dumps
    rid = f"INTEL-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO intel_reports (id,title,tlp,status,summary,body,actors,iocs,tags,"
            "author,created_at,updated_at) VALUES (?,?,?,'draft',?,?,?,?,?,?,?,?)",
            (rid, title, body.tlp, body.summary, body.body, dumps(body.actors),
             dumps(body.iocs), dumps(body.tags), user["email"], now, now))
        audit(conn, user["email"], "intel.report_create", rid, f"title={title}")
        conn.commit()
        row = conn.execute("SELECT * FROM intel_reports WHERE id=?", (rid,)).fetchone()
    return row_to_dict(row)


@router.get("/reports/{report_id}")
def get_report(report_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM intel_reports WHERE id=?", (report_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return row_to_dict(row)


@router.patch("/reports/{report_id}")
def update_report(report_id: str, body: ReportUpdate, user: dict = Depends(require_perm("cti.write"))):
    from dashboard_api.db import dumps
    fields, values = [], []
    for col in ("title", "summary", "body", "tlp", "status"):
        v = getattr(body, col)
        if v is not None:
            if col == "tlp" and v not in _TLP:
                raise HTTPException(status_code=400, detail="invalid tlp")
            if col == "status" and v not in ("draft", "published"):
                raise HTTPException(status_code=400, detail="status must be draft|published")
            fields.append(f"{col}=?"); values.append(v)
    for col in ("actors", "iocs", "tags"):
        v = getattr(body, col)
        if v is not None:
            fields.append(f"{col}=?"); values.append(dumps(v))
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    fields.append("updated_at=?")
    values.append(datetime.now(timezone.utc).replace(microsecond=0).isoformat())
    values.append(report_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE intel_reports SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Report not found")
        audit(conn, user["email"], "intel.report_update", report_id)
        conn.commit()
        row = conn.execute("SELECT * FROM intel_reports WHERE id=?", (report_id,)).fetchone()
    return row_to_dict(row)


@router.delete("/reports/{report_id}", status_code=204)
def delete_report(report_id: str, user: dict = Depends(require_perm("cti.write"))):
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM intel_reports WHERE id=?", (report_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Report not found")
        audit(conn, user["email"], "intel.report_delete", report_id)
        conn.commit()
    return None


@router.get("/reports/{report_id}/misp")
def export_report_misp(report_id: str):
    """Export an intel report (its referenced indicators) as a MISP Event."""
    from dashboard_api import misp
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM intel_reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        report = row_to_dict(row)
        values = report.get("iocs") or []
        iocs = []
        if values:
            ph = ",".join("?" * len(values))
            iocs = rows_to_dicts(conn.execute(
                f"SELECT type, value, severity, threat_type FROM iocs WHERE value IN ({ph})",
                values).fetchall())
    return misp.to_misp_event(iocs, info=report["title"], tlp=report["tlp"],
                              tags=report.get("tags") or [])


@router.get("/misp/export")
def export_misp(severity: str | None = None, limit: int = Query(500, le=5000)):
    """Export the IOC store (optionally filtered) as a MISP Event."""
    from dashboard_api import misp
    clauses = ["status != 'known-good'"]
    params: list = []
    if severity:
        clauses.append("severity=?"); params.append(severity)
    where = "WHERE " + " AND ".join(clauses)
    with get_conn() as conn:
        iocs = rows_to_dicts(conn.execute(
            f"SELECT type, value, severity, threat_type FROM iocs {where} "
            f"ORDER BY last_seen DESC LIMIT ?", params + [limit]).fetchall())
    return misp.to_misp_event(iocs, info="ThreatOrbit IOC export")


@router.post("/misp/import", status_code=201)
def import_misp(body: MispImport, user: dict = Depends(require_perm("cti.write"))):
    """Import a MISP Event's attributes into the IOC store."""
    from dashboard_api import misp
    from dashboard_api.db import dumps
    parsed = misp.parse_misp_event(body.event)
    if not parsed:
        raise HTTPException(status_code=400, detail="No importable attributes in the MISP event")
    tlp = misp.misp_tlp(body.event)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    imported = duplicates = skipped = 0
    with get_conn() as conn:
        for a in parsed:
            if a.get("skipped") or a["type"] not in _IOC_TYPES:
                skipped += 1
                continue
            val = a["value"].strip()
            if conn.execute("SELECT 1 FROM iocs WHERE value=?", (val,)).fetchone():
                duplicates += 1
                continue
            sev = "high" if a.get("to_ids") else "medium"
            conn.execute(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
                "first_seen,last_seen,tags,org_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), a["type"], val, a.get("comment") or "misp-import",
                 70 if a.get("to_ids") else 50, sev, "MISP import", "", now, now,
                 dumps([f"tlp:{tlp}", "misp"]), tenancy.org_of(user)))
            imported += 1
        _record_import(conn, f"MISP event ({body.event.get('Event', {}).get('info', 'import')})"[:100],
                       "misp", imported, duplicates, skipped, user["email"])
        audit(conn, user["email"], "intel.misp_import", None,
              f"imported={imported} duplicates={duplicates} skipped={skipped}")
        conn.commit()
    return {"imported": imported, "duplicates": duplicates, "skipped": skipped,
            "total": len(parsed), "tlp": tlp}


class AttributionQuery(BaseModel):
    techniques: list[str] = []
    iocs: list[str] = []
    malware: list[str] = []
    sectors: list[str] = []
    origin: str | None = None


@router.post("/attribution")
def attribute(body: AttributionQuery):
    """Evidence-weighted actor attribution for observed activity."""
    from dashboard_api.attribution import score_actors
    if not any([body.techniques, body.iocs, body.malware, body.sectors, body.origin]):
        raise HTTPException(status_code=400, detail="Provide at least one observable")
    with get_conn() as conn:
        candidates = score_actors(conn, techniques=body.techniques, iocs=body.iocs,
                                  malware=body.malware, sectors=body.sectors, origin=body.origin)
    return {"candidates": candidates}


@router.get("/attribution/case/{case_id}")
def attribute_case_endpoint(case_id: str):
    """Attribute a SOAR case from its linked alerts' techniques + indicators."""
    from dashboard_api.attribution import attribute_case
    with get_conn() as conn:
        result = attribute_case(conn, case_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return result


@router.get("/enrichers")
def list_enrichers():
    """Available enrichers and whether each external provider is configured."""
    from dashboard_api.enrichment import provider_status
    return provider_status()


@router.post("/iocs/{ioc_id}/enrich")
def enrich_ioc(ioc_id: str, refresh: bool = False, user: dict = Depends(require_perm("cti.write"))):
    """Run the enrichment pipeline over an indicator (cached, with history)."""
    from dashboard_api.enrichment import enrich
    with get_conn() as conn:
        row = conn.execute("SELECT value, type FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="IOC not found")
        result = enrich(conn, row["value"], row["type"], refresh=refresh)
        audit(conn, user["email"], "ioc.enrich", ioc_id, f"verdict={result['verdict']}")
        conn.commit()
    return result


@router.get("/iocs/{ioc_id}/enrichment")
def ioc_enrichment(ioc_id: str):
    """Latest enrichment (from cache, no re-run) + the enrichment history."""
    from dashboard_api.enrichment import enrich, history
    with get_conn() as conn:
        row = conn.execute("SELECT value, type FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="IOC not found")
        current = enrich(conn, row["value"], row["type"])  # served from cache when fresh
        past = history(conn, row["value"])
        conn.commit()
    return {**current, "history": past}


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
def run_decay(user: dict = Depends(require_perm("cti.write"))):
    """Run IOC decay maintenance: expire stale indicators, reactivate refreshed."""
    with get_conn() as conn:
        result = decay_iocs(conn)
        audit(conn, user["email"], "ioc.decay", None,
              f"expired={result['expired']} reactivated={result['reactivated']}")
        conn.commit()
    return result


@router.get("/hunts")
def list_hunts(user: dict = Depends(current_user)):
    extra, params = "", []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        extra, params = " AND org_id=?", [tenancy.org_of(user)]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description AS hypothesis, author AS analyst, "
            "query, technique, last_run, hit_count AS artifacts, "
            "status, progress, domain "
            f"FROM saved_hunts WHERE domain='cti'{extra} ORDER BY last_run DESC", params
        ).fetchall()
    return rows_to_dicts(rows)


@router.post("/hunts", status_code=201)
def create_hunt(body: HuntCreate, user: dict = Depends(current_user)):
    from dashboard_api.hunting import create_saved_hunt
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Hunt name is required")
    return create_saved_hunt("cti", name, body.description, body.query, body.technique,
                             user["email"], org_id=tenancy.org_of(user))


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
            "INSERT INTO scans (id,ts,target,type,verdict,score,engines,actor,org_id) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, now, target, body.type, body.verdict, body.score, body.engines,
             user["email"], tenancy.org_of(user)),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return row_to_dict(row)


@router.get("/scans")
def list_scans(limit: int = Query(20, le=100), user: dict = Depends(current_user)):
    """Recent scans plus aggregate stats for the scanner header."""
    where, params = "", []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        where, params = "WHERE org_id=?", [tenancy.org_of(user)]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM scans {where} ORDER BY ts DESC LIMIT ?",
            params + [limit]).fetchall()
        today_count = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE ts >= ?", (today,)
        ).fetchone()["n"]
        malicious = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE verdict='malicious'"
        ).fetchone()["n"]
    return {"items": rows_to_dicts(rows), "scansToday": today_count, "malicious": malicious}
