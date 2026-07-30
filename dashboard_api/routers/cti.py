"""CTI routes: threat actors, IOCs, hunts, and a relationship graph."""
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user, require_perm
from dashboard_api.connectors import bulk_feed_source_ids
from dashboard_api.db import (audit, get_conn, host_of, ip_hex_of, row_to_dict,
                              rows_to_dicts)
from dashboard_api.webhooks import dispatch
from dashboard_api.ioc_lifecycle import (
    decay_iocs, effective_confidence, lifecycle_of, record_sighting, set_known_good)
from dashboard_api.intel_scoring import DEFAULT_RELIABILITY, score_indicator

router = APIRouter(prefix="/cti", tags=["cti"], dependencies=[Depends(current_user)])

_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "cve"}

# Values per chunk in the bulk `value IN (...)` existence probe on import. Kept
# well under SQLite's 999-bind ceiling, leaving headroom for the workspace-scope
# bind appended by tenancy.scope_sql; Postgres allows far more, so this is safe
# on both.
_IMPORT_PROBE_CHUNK = 800


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
    # Relevance first. The default stays last_seen (a feed view), but `score` is
    # what makes a 315k store usable: it ranks by how much an analyst should
    # care rather than by what happened to arrive most recently.
    "score": "intel_score",
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
    # id tie-breaker for a total order - same rationale as the alerts list:
    # tied sort keys (bulk imports share a last_seen second) otherwise come
    # back in arbitrary backend-dependent order, breaking offset pagination.
    #
    # Sorting by score needs a MEANINGFUL second key before that one. A store of
    # single-source blocklist entries has little to differentiate it - measured
    # here, 108,393 of 327,981 indicators share a five-point band - and breaking
    # those ties on a random UUID makes "page one, sorted by relevance" a random
    # sample of the tie. Recency is the one axis that still carries information
    # once the score has said all it can, so it goes first and `id` stays only
    # as the stable total order pagination needs.
    tie = "last_seen DESC, " if sort == "score" else ""
    order_sql = f"{_IOC_SORTS[sort]} {order.upper()}, {tie}id {order.upper()}"
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

    # Attach the campaign context an indicator came from. A bare report_id UUID
    # tells an analyst nothing; the pulse title/TLP is what makes the difference
    # between "an IP from a feed" and "infrastructure from campaign X". One
    # lookup for the whole page rather than a join over every row.
    # Corroboration: how many independent sources assert each value on this page.
    # One query for the page, in the same shape as the report lookup below - the
    # alternative is a query per row, which at 100 rows is 100 round trips.
    if items:
        vals = [i["value"] for i in items]
        with get_conn() as conn:
            by_value = corroboration(conn, vals)
            grades = reliability_grades(conn)
        for i in items:
            srcs = by_value.get(i["value"], [])
            # 1, not 0, when unrecorded: the row exists because SOMETHING
            # asserted it. Pre-corroboration rows would otherwise read as
            # "no source claims this", which is false.
            i["sourceCount"] = len(srcs) or 1
            i["sources"] = srcs
            scored = _score_of(i, srcs, grades)
            i["intelScore"] = scored["score"]
            i["scoreBand"] = scored["band"]

    rids = {i.get("report_id") for i in items if i.get("report_id")}
    if rids:
        ph = ",".join("?" * len(rids))
        with get_conn() as conn:
            reps = conn.execute(
                f"SELECT id, title, tlp, source FROM intel_reports WHERE id IN ({ph})",
                tuple(rids)).fetchall()
        by_id = {r["id"]: {"id": r["id"], "title": r["title"], "tlp": r["tlp"],
                           "source": r["source"]} for r in reps}
        for i in items:
            if i.get("report_id") in by_id:
                i["report"] = by_id[i["report_id"]]
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
    org = tenancy.org_of(user)
    # Dedup within the caller's workspace only: another tenant's indicators must
    # be neither an existence oracle nor a silent drop for this import.
    sc, sp = tenancy.scope_sql(org)
    conf = max(0, min(100, body.confidence))

    # Batch, not row-by-row: a large paste / CSV upload must not cost one SELECT
    # + one INSERT per indicator (O(N) round trips). Normalise + intra-batch
    # dedup in memory, resolve existing values with chunked workspace-scoped
    # `value IN (...)` probes, then write every new row with one bulk INSERT.
    seen: set[str] = set()
    candidates: list[tuple[str, str]] = []
    for item in body.indicators:
        val = item.value.strip()
        itype = item.type.strip().lower()
        if not val or itype not in _IOC_TYPES:
            skipped += 1
            continue
        if val in seen:
            duplicates += 1
            continue
        seen.add(val)
        candidates.append((val, itype))

    with get_conn() as conn:
        existing: set[str] = set()
        vals = [v for v, _ in candidates]
        # Keep each probe within SQLite's 999-bind ceiling, with headroom for the
        # scope param appended by scope_sql.
        for i in range(0, len(vals), _IMPORT_PROBE_CHUNK):
            part = vals[i:i + _IMPORT_PROBE_CHUNK]
            ph = ",".join("?" * len(part))
            found = conn.execute(
                f"SELECT value FROM iocs WHERE value IN ({ph}) {sc}", (*part, *sp)
            ).fetchall()
            existing.update(r["value"] for r in found)

        new = [(v, t) for v, t in candidates if v not in existing]
        duplicates += len(candidates) - len(new)
        if new:
            conn.executemany(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
                "first_seen,last_seen,tags,org_id,host,ip_hex) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(str(uuid.uuid4()), t, v, body.threat_type, conf, body.severity,
                  body.source, body.actor, now, now, tags_json, org, host_of(v, t),
                  ip_hex_of(v, t))
                 for v, t in new],
            )
            imported = len(new)
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
            "SELECT id, source, method, imported, duplicates, skipped, status, actor, ts, "
            "duration_ms FROM ioc_imports ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    out = rows_to_dicts(rows)
    # Throughput per import: analysts judge feed health by rate, not just a count.
    for r in out:
        ms = r.get("duration_ms") or 0
        r["ratePerSec"] = round(r["imported"] / (ms / 1000), 1) if ms and r["imported"] else None
    return out


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


def _match_indicator(conn, v: str):
    """Find the store row for a queried value, or None.

    Matching is exact-first, then *delimiter-bounded*: a URL query also tries
    its hostname, and a bare-domain query matches URL indicators hosted ON that
    domain (`://domain/...`). The old blind substring fallback (`LIKE %v%`)
    returned any IOC merely CONTAINING the query - scanning `linkedin.com`
    matched phishing URLs hosted elsewhere that embed the string, branding the
    legitimate domain malicious. False negatives beat fabricated positives.
    """
    row = conn.execute("SELECT * FROM iocs WHERE value=?", (v,)).fetchone()
    if row is not None:
        return row
    if "://" in v:
        # URL query → is its host itself a known indicator?
        from urllib.parse import urlparse
        host = (urlparse(v).hostname or "").strip(".")
        if host:
            return conn.execute("SELECT * FROM iocs WHERE value=?", (host,)).fetchone()
        return None
    if v and "/" not in v and "." in v:
        # Bare domain/IP query → URL indicators hosted ON it (host position
        # only, so `evil.com/linkedin.com/x` can never match linkedin.com).
        #
        # Matched against the indexed `host` column rather than three
        # leading-wildcard LIKEs. The LIKE form could not use any index, so every
        # MISS scanned the whole table: checking 1,000 lines against a
        # 310k-indicator store took 32 seconds, which is not a triage tool.
        return conn.execute(
            "SELECT * FROM iocs WHERE host=? ORDER BY confidence DESC LIMIT 1",
            (v.lower(),),
        ).fetchone()
    return None


def corroboration(conn, values: list[str]) -> dict[str, list[str]]:
    """Which sources assert each value. The answer an analyst needs before
    acting: one blocklist listing an IP is weak, five independent feeds agreeing
    is not, and until now the platform could not tell them apart."""
    if not values:
        return {}
    out: dict[str, list[str]] = {}
    for i in range(0, len(values), _IMPORT_PROBE_CHUNK):
        chunk = values[i:i + _IMPORT_PROBE_CHUNK]
        ph = ",".join("?" * len(chunk))
        for r in conn.execute(
                f"SELECT value, source_id FROM observable_sources WHERE value IN ({ph}) "
                f"ORDER BY first_seen", tuple(chunk)).fetchall():
            out.setdefault(r["value"], []).append(r["source_id"])
    return out


def reliability_grades(conn) -> dict[str, str]:
    """Admiralty grade per source id. One query - the table is tiny (one row per
    configured feed) and every scoring path needs the whole of it."""
    return {r["id"]: r["reliability"]
            for r in conn.execute("SELECT id, reliability FROM intel_sources").fetchall()}


def _score_of(row, sources: list[str], grades: dict[str, str],
              verdict_shift: int = 0, verdict_note: str = "") -> dict:
    """Score one matched indicator, using the BEST-graded source that asserts it.

    Taking the best rather than the row's own `source` matters: whichever feed
    happened to write the row first is an accident of scheduling, and a value a
    grade-A tracker also lists should not be weighted as if only the grade-D
    aggregator had it.
    """
    ioc = row if isinstance(row, dict) else row_to_dict(row)
    # Upper-cased before comparing: the ordering is lexical ("A" < "B" < ...) and
    # a lowercase grade from the DB would sort after every uppercase one, so a
    # stored "a" would read as the WORST source rather than the best.
    candidates = [str(g).upper()[:1] for g in (grades.get(s) for s in sources) if g]
    own = grades.get(ioc.get("source") or "")
    if own:
        candidates.append(str(own).upper()[:1])
    best = min(candidates, default=DEFAULT_RELIABILITY)
    return score_indicator(
        ioc, source_count=max(1, len(sources)), reliability=best,
        local_sightings=max(0, (ioc.get("sightings") or 1) - 1),
        verdict_shift=verdict_shift, verdict_note=verdict_note)


def _lookup_payload(v: str, row) -> dict:
    """The verdict for one queried value. Shared by the single and bulk lookups:
    two triage paths that disagreed about whether a value is malicious would be
    worse than not having the second one."""
    if row is None:
        return {"value": v, "found": False, "verdict": "unverified", "confidence": 0,
                "severity": None, "threatType": None, "actor": None, "source": None,
                "firstSeen": None, "lastSeen": None, "tags": []}
    ioc = row_to_dict(row)
    life = lifecycle_of(ioc)
    if ioc.get("status") == "known-good":
        verdict = "benign"
    elif life["status"] == "expired":
        verdict = "expired"
    else:
        # A row that EXISTS in the store is never "clean" - something asserted it
        # is bad, and returning "clean" for a listed indicator is the one wrong
        # answer a lookup can give. Low-impact activity is still suspicious; the
        # honest "we have nothing" answer is `unverified`, on the not-found path.
        verdict = "malicious" if ioc["severity"] in ("critical", "high") else "suspicious"
    return {
        "value": v, "matched": ioc["value"], "found": True, "verdict": verdict,
        "confidence": ioc["confidence"], "severity": ioc["severity"],
        "threatType": ioc["threat_type"], "actor": ioc["actor"], "source": ioc["source"],
        "firstSeen": ioc["first_seen"], "lastSeen": ioc["last_seen"], "tags": ioc["tags"],
        "status": life["status"], "effectiveConfidence": life["effectiveConfidence"],
        "sightings": life["sightings"], "knownGood": ioc.get("status") == "known-good",
    }


@router.get("/lookup")
def ioc_lookup(value: str):
    """Look an indicator up against the IOC store and return a verdict + enrichment."""
    v = value.strip()
    with get_conn() as conn:
        row = _match_indicator(conn, v)
        matched = row["value"] if row is not None else v
        srcs = corroboration(conn, [matched]).get(matched, [])
        scored = _score_of(row, srcs, reliability_grades(conn)) if row is not None else None
    out = _lookup_payload(v, row)
    out["sources"] = srcs
    out["sourceCount"] = len(srcs) or (1 if out["found"] else 0)
    if scored is not None:
        # WITH the components. A ranking an analyst cannot interrogate is one
        # they are right to ignore, so "why is this 84?" is answered here rather
        # than left for them to guess at from the number alone.
        out["intelScore"] = scored["score"]
        out["scoreBand"] = scored["band"]
        out["scoreComponents"] = scored["components"]
        out["reliability"] = scored["reliability"]
    # The single-value response has always keyed `value` to the MATCHED
    # indicator, not the query; keep that shape for existing callers.
    if out["found"]:
        out["value"] = out.pop("matched")
    else:
        out.pop("matched", None)
    return out


# An L1 pasting a firewall/proxy extract is the most common triage action there
# is, and one-at-a-time it is one HTTP round trip per line. Capped so a paste of
# a whole log cannot turn into an unbounded scan.
_BULK_LOOKUP_MAX = 1000


class BulkLookup(BaseModel):
    values: list[str]


@router.post("/lookup/bulk")
def ioc_lookup_bulk(body: BulkLookup):
    """Check many indicators against the store in one request.

    Exact matches - the overwhelming majority - are answered with chunked
    `value IN (...)` probes rather than a query per value, so checking 1,000
    lines costs a handful of queries. Only the values that miss fall through to
    the delimiter-bounded fallbacks, one query each.

    Results come back in the order submitted, including the misses: an analyst
    pasting 40 lines needs to see which 37 were clean, not just the 3 hits.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in body.values:
        v = (raw or "").strip()
        if v and v not in seen:
            seen.add(v)
            ordered.append(v)
    if len(ordered) > _BULK_LOOKUP_MAX:
        raise HTTPException(
            status_code=413,
            detail=f"Too many values: {len(ordered)} (max {_BULK_LOOKUP_MAX} per request)")
    if not ordered:
        return {"total": 0, "found": 0, "results": []}

    rows: dict[str, object] = {}
    with get_conn() as conn:
        for i in range(0, len(ordered), _IMPORT_PROBE_CHUNK):
            chunk = ordered[i:i + _IMPORT_PROBE_CHUNK]
            ph = ",".join("?" * len(chunk))
            # .fetchall(), not iteration: a sqlite3 cursor is iterable and the
            # Postgres wrapper's is not, so the loop form worked in every local
            # run and broke bulk lookup outright on Postgres.
            for r in conn.execute(f"SELECT * FROM iocs WHERE value IN ({ph})",
                                  chunk).fetchall():
                rows[r["value"]] = r
        for v in ordered:
            if v not in rows:
                hit = _match_indicator(conn, v)
                if hit is not None:
                    rows[v] = hit

    results = [_lookup_payload(v, rows.get(v)) for v in ordered]
    # Corroboration for the whole batch in one pass, keyed on the indicator each
    # query MATCHED (a domain query can hit a URL hosted on it).
    matched_values = [r.get("matched") or r["value"] for r in results if r["found"]]
    if matched_values:
        with get_conn() as conn:
            by_value = corroboration(conn, matched_values)
            grades = reliability_grades(conn)
        for r in results:
            if r["found"]:
                key = r.get("matched") or r["value"]
                srcs = by_value.get(key, [])
                r["sources"] = srcs
                r["sourceCount"] = len(srcs) or 1
                # Score but NOT its components: at 1,000 rows the per-row
                # reasoning is several hundred KB of JSON nobody reads. The
                # single lookup is where an analyst drills in.
                scored = _score_of(rows[r["value"]], srcs, grades)
                r["intelScore"] = scored["score"]
                r["scoreBand"] = scored["band"]
    return {"total": len(results),
            "found": sum(1 for r in results if r["found"]),
            "results": results}


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
        srcs = corroboration(conn, [ioc["value"]]).get(ioc["value"], [])
        from dashboard_api import verdicts as verdict_mod
        vsum = verdict_mod.summary(conn, ioc["value"], tenancy.org_of(user))
        note = ""
        if vsum["latest"]:
            note = (f"{vsum['total']} conclusion(s) from your team; most recently "
                    f"\"{vsum['latest']['verdict']}\" by {vsum['latest']['analyst']}")
        scored = _score_of(ioc, srcs, reliability_grades(conn),
                           verdict_shift=vsum["shift"], verdict_note=note)
        vhistory = verdict_mod.history(conn, ioc["value"], tenancy.org_of(user))
        # The governing decay rule, so the drawer can name the policy behind
        # "expires in 12 days" rather than presenting it as a law of nature.
        from dashboard_api.decay import rule_for
        rule = rule_for(conn, ioc.get("type"))
    return {**ioc, "lifecycle": lifecycle_of(ioc, rule=rule), "sightingsHistory": sightings,
            # The drawer is where an analyst decides whether to act, so it gets
            # the full derivation rather than a bare number.
            "sources": srcs, "sourceCount": len(srcs) or 1,
            "intelScore": scored["score"], "scoreBand": scored["band"],
            "scoreComponents": scored["components"], "reliability": scored["reliability"],
            "verdicts": vhistory, "verdictSummary": vsum}


@router.get("/iocs/{ioc_id}/fp-assessment")
def ioc_fp_assessment(ioc_id: str, user: dict = Depends(current_user)):
    """Evidence-based false-positive likelihood for one indicator (see
    dashboard_api/fp_scoring.py). Advisory only -- never changes the IOC."""
    from dashboard_api.fp_scoring import score_ioc
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row or tenancy.cross_org(row, user):
            raise HTTPException(status_code=404, detail="IOC not found")
        result = score_ioc(conn, row_to_dict(row), tenancy.org_of(user))
    return result


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
def list_reports(status: str | None = None, user: dict = Depends(current_user)):
    clauses, params = [], []
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
    if status:
        clauses.append("status=?"); params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
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
            "author,created_at,updated_at,org_id) VALUES (?,?,?,'draft',?,?,?,?,?,?,?,?,?)",
            (rid, title, body.tlp, body.summary, body.body, dumps(body.actors),
             dumps(body.iocs), dumps(body.tags), user["email"], now, now,
             tenancy.org_of(user)))
        audit(conn, user["email"], "intel.report_create", rid, f"title={title}")
        conn.commit()
        row = conn.execute("SELECT * FROM intel_reports WHERE id=?", (rid,)).fetchone()
    return row_to_dict(row)


@router.get("/reports/{report_id}")
def get_report(report_id: str, user: dict = Depends(current_user)):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM intel_reports WHERE id=?", (report_id,)).fetchone()
    if not row or tenancy.cross_org(row, user):
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
    # Org-scope the UPDATE so a cross-workspace id 404s without a write.
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE intel_reports SET {','.join(fields)} WHERE id=? {sc}",
                           values + sp)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Report not found")
        audit(conn, user["email"], "intel.report_update", report_id)
        conn.commit()
        row = conn.execute("SELECT * FROM intel_reports WHERE id=?", (report_id,)).fetchone()
    return row_to_dict(row)


@router.delete("/reports/{report_id}", status_code=204)
def delete_report(report_id: str, user: dict = Depends(require_perm("cti.write"))):
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        cur = conn.execute(f"DELETE FROM intel_reports WHERE id=? {sc}", (report_id, *sp))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Report not found")
        audit(conn, user["email"], "intel.report_delete", report_id)
        conn.commit()
    return None


@router.get("/reports/{report_id}/misp")
def export_report_misp(report_id: str, user: dict = Depends(current_user)):
    """Export an intel report (its referenced indicators) as a MISP Event."""
    from dashboard_api import misp
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM intel_reports WHERE id=?", (report_id,)).fetchone()
        if not row or tenancy.cross_org(row, user):
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
                "first_seen,last_seen,tags,org_id,host,ip_hex) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), a["type"], val, a.get("comment") or "misp-import",
                 70 if a.get("to_ids") else 50, sev, "MISP import", "", now, now,
                 dumps([f"tlp:{tlp}", "misp"]), tenancy.org_of(user),
                 host_of(val, a["type"]), ip_hex_of(val, a["type"])))
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
def attribute_case_endpoint(case_id: str, user: dict = Depends(current_user)):
    """Attribute a SOAR case from its linked alerts' techniques + indicators."""
    from dashboard_api.attribution import attribute_case
    with get_conn() as conn:
        # Cross-org guard on the parent case (attribute_case reads its alerts/IOCs).
        crow = conn.execute("SELECT org_id FROM cases WHERE id=?", (case_id,)).fetchone()
        if not crow or tenancy.cross_org(crow, user):
            raise HTTPException(status_code=404, detail="Case not found")
        result = attribute_case(conn, case_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return result


@router.get("/enrichers")
def list_enrichers():
    """Available enrichers and whether each external provider is configured."""
    from dashboard_api.enrichment import provider_status
    return provider_status()


class VerdictBody(BaseModel):
    verdict: str
    reason: str | None = None


@router.post("/iocs/{ioc_id}/verdict", status_code=201)
def record_verdict(ioc_id: str, body: VerdictBody,
                   user: dict = Depends(require_perm("cti.write"))):
    """Record an analyst conclusion, and feed it back into the score.

    Until this existed, nothing an analyst concluded ever reached the intel store:
    an L1 could spend twenty minutes establishing that an indicator is a false
    positive here, write it in a case note, and the store would score it the same
    way again next week for the next analyst.

    Appends rather than replaces - the history is the point, and two analysts
    disagreeing is a real state. Scoped to the caller's workspace, because one
    tenant's "false positive in our environment" must never suppress another's.
    """
    from dashboard_api import verdicts as verdict_mod
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row or tenancy.cross_org(row, user):
            raise HTTPException(status_code=404, detail="IOC not found")
        ioc = row_to_dict(row)
        try:
            rec = verdict_mod.record(
                conn, value=ioc["value"], verdict=body.verdict,
                analyst=user["email"], reason=body.reason,
                org_id=tenancy.org_of(user))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        summary = verdict_mod.summary(conn, ioc["value"], tenancy.org_of(user))
        # Rescored immediately, not at the next maintenance pass: an analyst who
        # has just concluded something needs to see the queue reflect it, or they
        # will reasonably assume the button did nothing.
        srcs = corroboration(conn, [ioc["value"]]).get(ioc["value"], [])
        scored = _score_of(ioc, srcs, reliability_grades(conn),
                           verdict_shift=summary["shift"])
        conn.execute("UPDATE iocs SET intel_score=? WHERE id=?",
                     (scored["score"], ioc_id))
        audit(conn, user["email"], "ioc.verdict", ioc_id,
              f"{rec['verdict']} (score {ioc.get('intel_score') or 0} -> {scored['score']})")
        conn.commit()
    return {"verdict": rec, "summary": summary, "intelScore": scored["score"],
            "scoreBand": scored["band"], "scoreComponents": scored["components"]}


@router.get("/iocs/{ioc_id}/verdicts")
def list_verdicts(ioc_id: str, user: dict = Depends(current_user)):
    """Every conclusion this workspace has recorded for the indicator."""
    from dashboard_api import verdicts as verdict_mod
    with get_conn() as conn:
        row = conn.execute("SELECT value, org_id FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row or tenancy.cross_org(row, user):
            raise HTTPException(status_code=404, detail="IOC not found")
        org = tenancy.org_of(user)
        return {"history": verdict_mod.history(conn, row["value"], org),
                "summary": verdict_mod.summary(conn, row["value"], org),
                "options": list(verdict_mod.VERDICTS)}


class DecayRuleUpdate(BaseModel):
    half_life_days: int | None = None
    revoke_score: int | None = None
    max_age_half_lives: int | None = None
    reaction_points: list[int] | None = None
    enabled: bool | None = None


class SourceGradeUpdate(BaseModel):
    reliability: str
    reason: str | None = None


@router.get("/sources")
def list_intel_sources(user: dict = Depends(current_user)):
    """Every source that has asserted a value, with its Admiralty grade.

    The grade is a MULTIPLIER on every score that source contributes, which
    makes it the single most consequential number an operator can set - and it
    was previously invisible, unchangeable, and identical for every feed. A
    weighting nobody can inspect is one an analyst is right to distrust.

    `values` is counted live from the assertion ledger rather than read from
    `intel_sources.value_count`, which nothing maintains.
    """
    from dashboard_api.intel_scoring import RELIABILITY_WEIGHT
    with get_conn() as conn:
        counts = {r["source_id"]: r["n"] for r in conn.execute(
            "SELECT source_id, COUNT(*) AS n FROM observable_sources "
            "GROUP BY source_id").fetchall()}
        rows = conn.execute(
            "SELECT id, name, kind, reliability, reliability_reason, "
            "reliability_set_by, first_seen, last_seen FROM intel_sources").fetchall()
    out = [{
        "id": r["id"], "name": r["name"], "kind": r["kind"],
        "reliability": r["reliability"],
        # What the grade actually does to a score, so the choice is not abstract.
        "weight": RELIABILITY_WEIGHT.get((r["reliability"] or "C").upper()[:1], 0.82),
        "reason": r["reliability_reason"],
        # Whose judgement is in force. An operator's own grading is never
        # overwritten by a shipped default, so this is load-bearing, not cosmetic.
        "gradedBy": r["reliability_set_by"] or "shipped default",
        "isDefault": not r["reliability_set_by"],
        "firstSeen": r["first_seen"], "lastSeen": r["last_seen"],
        "values": counts.get(r["id"], 0),
    } for r in rows]
    out.sort(key=lambda s: -s["values"])
    return {"items": out, "scale": [
        {"grade": g, "weight": w, "label": lbl} for g, w, lbl in [
            ("A", RELIABILITY_WEIGHT["A"], "completely reliable"),
            ("B", RELIABILITY_WEIGHT["B"], "usually reliable"),
            ("C", RELIABILITY_WEIGHT["C"], "fairly reliable"),
            ("D", RELIABILITY_WEIGHT["D"], "not usually reliable"),
            ("E", RELIABILITY_WEIGHT["E"], "unreliable"),
            ("F", RELIABILITY_WEIGHT["F"], "cannot be judged"),
        ]]}


@router.patch("/sources/{source_id:path}")
def grade_intel_source(source_id: str, body: SourceGradeUpdate,
                       user: dict = Depends(require_perm("cti.write"))):
    """Re-grade a source. Takes effect on the next maintenance pass.

    Recording WHO graded it is not bookkeeping: it is what stops a later upgrade
    from overwriting the operator's judgement with a revised shipped default.
    Ours is a starting assessment; theirs is knowledge of their own environment
    and of which feeds have burned them.
    """
    from dashboard_api.intel_scoring import RELIABILITY_WEIGHT
    grade = (body.reliability or "").strip().upper()[:1]
    if grade not in RELIABILITY_WEIGHT:
        raise HTTPException(
            status_code=400,
            detail=f"reliability must be one of {sorted(RELIABILITY_WEIGHT)} "
                   f"(Admiralty: A completely reliable .. F cannot be judged)")
    with get_conn() as conn:
        if not conn.execute("SELECT 1 FROM intel_sources WHERE id=?", (source_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Source not found")
        conn.execute(
            "UPDATE intel_sources SET reliability=?, reliability_reason=?, "
            "reliability_set_by=? WHERE id=?",
            (grade, (body.reason or "").strip()[:500] or None, user["email"], source_id))
        audit(conn, user["email"], "cti.source_grade", source_id, f"reliability={grade}")
        conn.commit()
        row = conn.execute(
            "SELECT id, name, reliability, reliability_reason, reliability_set_by "
            "FROM intel_sources WHERE id=?", (source_id,)).fetchone()
    return {"id": row["id"], "name": row["name"], "reliability": row["reliability"],
            "weight": RELIABILITY_WEIGHT[grade], "reason": row["reliability_reason"],
            "gradedBy": row["reliability_set_by"], "isDefault": False}


@router.get("/store-summary")
def store_summary(user: dict = Depends(current_user)):
    """What is actually IN this store - the question a 315k-row list cannot answer.

    "315,185 indicators" says nothing about whether they are worth having. This
    answers the questions that do: how much of it do we believe, how much is
    corroborated by more than one source, what kind of activity is it, which
    feeds are actually contributing, and what is about to be revoked.

    Every number is a live aggregate over the real tables - nothing is estimated
    or carried forward. Measured at ~400 ms over 315,185 indicators, so it is a
    page-load summary rather than something to poll on a timer.
    """
    with get_conn() as conn:
        bands = {r["b"]: r["n"] for r in conn.execute(
            "SELECT CASE WHEN intel_score>=75 THEN 'high' "
            "WHEN intel_score>=50 THEN 'moderate' "
            "WHEN intel_score>=25 THEN 'low' ELSE 'weak' END AS b, COUNT(*) AS n "
            "FROM iocs GROUP BY b").fetchall()}
        # Corroboration is the signal a multi-feed platform exists to produce, so
        # "how much of the store is backed by more than one source" is the single
        # most honest quality measure available.
        corr = {"1": 0, "2": 0, "3+": 0}
        for r in conn.execute(
                "SELECT n_src, COUNT(*) AS n FROM (SELECT value, COUNT(*) AS n_src "
                "FROM observable_sources GROUP BY value) GROUP BY n_src").fetchall():
            key = "1" if r["n_src"] <= 1 else ("2" if r["n_src"] == 2 else "3+")
            corr[key] += r["n"]
        activities = [{"activity": r["threat_type"] or "unclassified", "count": r["n"]}
                      for r in conn.execute(
                          "SELECT threat_type, COUNT(*) AS n FROM iocs "
                          "GROUP BY threat_type ORDER BY n DESC LIMIT 8").fetchall()]
        sources_all = conn.execute(
            "SELECT source_id, COUNT(*) AS n FROM observable_sources "
            "GROUP BY source_id ORDER BY n DESC").fetchall()
        sources = [{"source": r["source_id"], "values": r["n"]} for r in sources_all[:8]]
        now = datetime.now(timezone.utc)
        week = (now + timedelta(days=7)).replace(microsecond=0).isoformat()
        expiring = conn.execute(
            "SELECT COUNT(*) AS n FROM iocs WHERE valid_until IS NOT NULL "
            "AND valid_until BETWEEN ? AND ?",
            (now.replace(microsecond=0).isoformat(), week)).fetchone()["n"]
        verdicts = {r["verdict"]: r["n"] for r in conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM ioc_verdicts WHERE org_id=? "
            "GROUP BY verdict", (tenancy.org_of(user),)).fetchall()}
        # Indicators this deployment has actually OBSERVED, and how many times.
        # The only figure on this panel a public CTI library structurally cannot
        # produce: everything else here describes what someone else published,
        # this describes what happened on your network. Counted from the sighting
        # ledger rather than `iocs.sightings`, because that column starts at 1 for
        # every import and a count of "1" means nothing was ever seen.
        seen = conn.execute(
            "SELECT COUNT(DISTINCT ioc_id) AS values_seen, COUNT(*) AS observations "
            "FROM ioc_sightings").fetchone()
        total = sum(bands.values())
    # How many feeds are CONFIGURED versus how many have actually contributed a
    # value. A low corroboration share means very different things depending on
    # this ratio: feeds that genuinely do not overlap, or feeds that never
    # fetched. Leaving the reader to deduce which is how a number gets misread -
    # it happened here, on a development environment whose egress policy could
    # reach 9 of the 16.
    #
    # Counted against the configured feed list rather than "distinct source_ids
    # seen", because the store also carries sources that are not bulk feeds at
    # all (OTX, NVD, TAXII, hand-entered indicators). Those belong in `sources`
    # but not in a feed-coverage ratio, where they would inflate the numerator
    # past the denominator and read as full coverage.
    feed_ids = bulk_feed_source_ids()
    contributing = sum(1 for r in sources_all if r["source_id"] in feed_ids)
    return {
        "total": total,
        "bands": {k: bands.get(k, 0) for k in ("high", "moderate", "low", "weak")},
        "corroboration": corr,
        # Stated as a share because the absolute number means nothing without it:
        # 4,000 corroborated out of 315,185 is a very different store from 4,000
        # out of 6,000.
        "corroboratedShare": round(100 * (corr["2"] + corr["3+"]) / total, 1) if total else 0.0,
        "activities": activities,
        "sources": sources,
        "expiringWithin7Days": expiring,
        "verdicts": verdicts,
        "seenLocally": seen["values_seen"] or 0,
        "localObservations": seen["observations"] or 0,
        "sourcesContributing": contributing,
        "sourcesConfigured": len(feed_ids),
        # Everything asserting values, feeds or otherwise - so a store fed
        # entirely by OTX does not look empty next to "0 of 16 feeds".
        "sourcesTotal": len(sources_all),
    }


@router.get("/decay-rules")
def list_decay_rules():
    """The decay policy governing every indicator type.

    How fast intel stops being actionable is a policy decision that differs per
    deployment, so it is a record an operator can read and change rather than a
    constant in the source."""
    from dashboard_api.decay import rules
    with get_conn() as conn:
        return rules(conn)


@router.patch("/decay-rules/{rule_id}")
def update_decay_rule(rule_id: str, body: DecayRuleUpdate,
                      user: dict = Depends(require_perm("cti.write"))):
    """Tune one decay rule. Takes effect on the next maintenance pass.

    Validated rather than trusted: a zero half-life would make every indicator
    expire instantly, and a revoke score at or above 100 would expire everything
    the moment it was imported. Both are easy to type and impossible to notice
    until the store is empty.
    """
    from dashboard_api.decay import invalidate_cache
    sets, params = [], []
    if body.half_life_days is not None:
        if not 1 <= body.half_life_days <= 3650:
            raise HTTPException(status_code=400,
                                detail="half_life_days must be between 1 and 3650")
        sets.append("half_life_days=?"); params.append(body.half_life_days)
    if body.revoke_score is not None:
        if not 1 <= body.revoke_score <= 99:
            raise HTTPException(
                status_code=400,
                detail="revoke_score must be between 1 and 99 - at 100 every "
                       "indicator is revoked on import, at 0 none ever is")
        sets.append("revoke_score=?"); params.append(body.revoke_score)
    if body.max_age_half_lives is not None:
        if not 1 <= body.max_age_half_lives <= 20:
            raise HTTPException(status_code=400,
                                detail="max_age_half_lives must be between 1 and 20")
        sets.append("max_age_half_lives=?"); params.append(body.max_age_half_lives)
    if body.reaction_points is not None:
        pts = sorted({int(p) for p in body.reaction_points if 1 <= int(p) <= 99},
                     reverse=True)
        sets.append("reaction_points=?"); params.append(json.dumps(pts))
    if body.enabled is not None:
        sets.append("enabled=?"); params.append(1 if body.enabled else 0)
    if not sets:
        raise HTTPException(status_code=400, detail="No fields to update")
    with get_conn() as conn:
        row = conn.execute("SELECT id FROM decay_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Decay rule not found")
        conn.execute(f"UPDATE decay_rules SET {', '.join(sets)} WHERE id=?",
                     params + [rule_id])
        audit(conn, user["email"], "cti.decay_rule", rule_id, ", ".join(sets))
        conn.commit()
        # The rule table is cached in-process for the hot decay path; a write that
        # skipped this would keep serving the old policy until a restart.
        invalidate_cache()
        from dashboard_api.decay import rules
        return next((r for r in rules(conn) if r["id"] == rule_id), None)


@router.get("/iocs/{ioc_id}/related")
def ioc_related(ioc_id: str, limit: int = Query(8, ge=1, le=50),
                user: dict = Depends(current_user)):
    """What else this deployment holds that is part of the same thing.

    An indicator an analyst cannot pivot from is a dead end, and 315k dead ends
    is a list rather than intelligence. Every group states the evidence for the
    link so an analyst can judge whether to trust the edge; nothing here invents
    a relationship, so "no relations" is a legitimate answer.
    """
    from dashboard_api.relations import related
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row or tenancy.cross_org(row, user):
            raise HTTPException(status_code=404, detail="IOC not found")
        groups = related(conn, row_to_dict(row), limit=limit)
    return {"groups": groups,
            "total": sum(g["total"] for g in groups)}


@router.get("/asn/status")
def asn_status():
    """State of the local BGP ownership table: how many ranges and how fresh.

    Reported honestly - an unsynced deployment sees zero ranges and no
    timestamp, not an empty-looking success."""
    from dashboard_api import asn as asn_mod
    with get_conn() as conn:
        return asn_mod.status(conn)


@router.post("/asn/sync")
def asn_sync(force: bool = True, user: dict = Depends(require_perm("cti.write"))):
    """Refresh the network-ownership table from iptoasn.com now.

    `force` by default: an operator pressing this has decided the table should
    be refreshed, and answering "not due yet" to an explicit request is the
    behaviour that makes people stop trusting a button.
    """
    from dashboard_api import asn as asn_mod
    with get_conn() as conn:
        try:
            res = asn_mod.sync(conn, force=force)
            conn.commit()
        except Exception as e:                     # noqa: BLE001
            # The reason, not a generic failure: "which upstream, and what went
            # wrong" is what an operator needs to fix it.
            raise HTTPException(
                status_code=502,
                detail=f"Could not refresh from {asn_mod.DATASET_URL}: "
                       f"{e.__class__.__name__}: {e}"[:300])
        audit(conn, user["email"], "asn.sync", "asn_ranges", f"ranges={res.get('ranges')}")
        conn.commit()
    return res


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
def ioc_enrichment(ioc_id: str, user: dict = Depends(current_user)):
    """Latest enrichment (from cache, no re-run) + the enrichment history."""
    from dashboard_api.enrichment import enrich, history
    with get_conn() as conn:
        row = conn.execute("SELECT value, type, org_id FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row or tenancy.cross_org(row, user):
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
def create_hunt(body: HuntCreate, user: dict = Depends(require_perm("cti.write"))):
    from dashboard_api.hunting import create_saved_hunt
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Hunt name is required")
    return create_saved_hunt("cti", name, body.description, body.query, body.technique,
                             user["email"], org_id=tenancy.org_of(user))


@router.post("/hunts/{hunt_id}/run")
def run_hunt(hunt_id: str, user: dict = Depends(require_perm("cti.write"))):
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


# -- Scanner history ------------------------------------------------------------

def _context_host(v: str) -> str | None:
    """The hostname to pivot on alongside the raw value: a URL query also
    relates through its host; a bare value relates only through itself."""
    if "://" in v:
        from urllib.parse import urlparse
        host = (urlparse(v).hostname or "").strip(".")
        return host or None
    return None


@router.get("/scan/context")
def scan_context(value: str, user: dict = Depends(current_user)):
    """Everything this deployment actually knows around an indicator: the IOC
    record, sibling indicators (same actor / same host), SIEM alerts, SOAR
    cases, dark-web findings, assets, raw-event volume, graph neighbours and
    prior analyst scans. Every relation is a real stored record (deep-linkable
    by id) - an indicator we know nothing about honestly returns empty lists,
    not invented context."""
    v = value.strip()
    if not v:
        raise HTTPException(status_code=400, detail="value is required")
    host = _context_host(v)
    keys = [v] + ([host] if host and host != v else [])
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        # The indicator itself (same delimiter-bounded matching as /lookup).
        row = conn.execute(f"SELECT * FROM iocs WHERE value=? {sc}", (v, *sp)).fetchone()
        if row is None and host:
            row = conn.execute(f"SELECT * FROM iocs WHERE value=? {sc}",
                               (host, *sp)).fetchone()
        if row is None and "/" not in v and "." in v:
            row = conn.execute(
                f"SELECT * FROM iocs WHERE (value LIKE ? OR value LIKE ? OR value LIKE ?) {sc} "
                "ORDER BY confidence DESC LIMIT 1",
                (f"%://{v}/%", f"%://{v}", f"%://{v}?%", *sp)).fetchone()
        indicator = row_to_dict(row) if row else None

        # Sibling indicators: same attributed actor, then same host family.
        related_iocs: list[dict] = []
        seen_ids = {indicator["id"]} if indicator else set()
        if indicator and indicator.get("actor"):
            for r in conn.execute(
                    f"SELECT id, value, type, severity, confidence, actor FROM iocs "
                    f"WHERE actor=? AND id != ? {sc} ORDER BY confidence DESC LIMIT 6",
                    (indicator["actor"], indicator["id"], *sp)).fetchall():
                related_iocs.append(row_to_dict(r)); seen_ids.add(r["id"])
        pivot_host = host or (v if "/" not in v and "." in v else None)
        if pivot_host and len(related_iocs) < 6:
            for r in conn.execute(
                    f"SELECT id, value, type, severity, confidence, actor FROM iocs "
                    f"WHERE (value LIKE ? OR value LIKE ? OR value LIKE ?) {sc} "
                    "ORDER BY confidence DESC LIMIT 8",
                    (f"%://{pivot_host}/%", f"%://{pivot_host}", f"%://{pivot_host}?%",
                     *sp)).fetchall():
                if r["id"] not in seen_ids and len(related_iocs) < 6:
                    related_iocs.append(row_to_dict(r)); seen_ids.add(r["id"])

        # SIEM alerts touching the indicator (src/dest/hostname, exact match).
        ph = ",".join("?" * len(keys))
        alert_where = (f"(src_ip IN ({ph}) OR dest_ip IN ({ph}) OR hostname IN ({ph})) {sc}")
        aparams = keys * 3 + sp
        alert_total = conn.execute(
            f"SELECT COUNT(*) FROM alerts WHERE {alert_where}", aparams).fetchone()[0]
        alerts = rows_to_dicts(conn.execute(
            f"SELECT id, ts, title, severity, status, src_ip, dest_ip, hostname, username "
            f"FROM alerts WHERE {alert_where} ORDER BY ts DESC LIMIT 5", aparams).fetchall())

        # SOAR cases holding the indicator as an entity (exact JSON element).
        case_clause = " OR ".join(["entities LIKE ?"] * len(keys))
        cparams = [f'%"{k}"%' for k in keys] + sp
        cases = rows_to_dicts(conn.execute(
            f"SELECT id, title, severity, status, owner, created FROM cases "
            f"WHERE ({case_clause}) {sc} ORDER BY created DESC LIMIT 5", cparams).fetchall())

        # Dark-web findings: exact entity match, or a mention inside the detail.
        dw_where = (f"(entity IN ({ph}) OR " + " OR ".join(["detail LIKE ?"] * len(keys))
                    + f") {sc}")
        dwparams = keys + [f"%{k}%" for k in keys] + sp
        dw_total = conn.execute(
            f"SELECT COUNT(*) FROM dark_web_findings WHERE {dw_where}", dwparams).fetchone()[0]
        dark_web = rows_to_dicts(conn.execute(
            f"SELECT id, ts, category, severity, source, title, entity FROM dark_web_findings "
            f"WHERE {dw_where} ORDER BY ts DESC LIMIT 5", dwparams).fetchall())

        # Inventory assets that ARE the indicator (address or name).
        assets = rows_to_dicts(conn.execute(
            f"SELECT id, name, type, value, criticality, status, risk_score FROM assets "
            f"WHERE (value IN ({ph}) OR name IN ({ph})) {sc} LIMIT 5",
            keys * 2 + sp).fetchall())

        # Raw-event volume, bounded so a hot indicator can't trigger a full scan.
        ev_cap = 500
        ev_count = conn.execute(
            f"SELECT COUNT(*) FROM (SELECT 1 FROM events "
            f"WHERE (src_ip IN ({ph}) OR dest_ip IN ({ph}) OR hostname IN ({ph})) {sc} "
            f"LIMIT {ev_cap}) capped", keys * 3 + sp).fetchone()[0]

        # Related entities observed alongside it in those alerts.
        rel: dict[str, list[str]] = {"ips": [], "hostnames": [], "usernames": [], "emails": []}
        for a in alerts:
            for k, col in (("ips", "src_ip"), ("ips", "dest_ip"),
                           ("hostnames", "hostname"), ("usernames", "username")):
                val = a.get(col)
                if val and val not in keys and val not in rel[k] and len(rel[k]) < 8:
                    rel[k].append(val)
        for f in dark_web:
            ent = f.get("entity")
            if ent and "@" in ent and ent not in rel["emails"] and len(rel["emails"]) < 8:
                rel["emails"].append(ent)

        # Prior analyst activity on this exact target - the honest "community"
        # signal: what THIS SOC's analysts concluded before, not invented votes.
        scan_rows = conn.execute(
            f"SELECT verdict, COUNT(*) AS n, MAX(ts) AS last_ts FROM scans "
            f"WHERE target=? {sc} GROUP BY verdict", (v, *sp)).fetchall()
        analyst = {"scans": sum(r["n"] for r in scan_rows),
                   "byVerdict": {r["verdict"]: r["n"] for r in scan_rows},
                   "lastScan": max((r["last_ts"] for r in scan_rows), default=None)}

        # Intelligence-graph neighbourhood (actors/malware/techniques/sectors).
        graph = None
        if indicator:
            from dashboard_api import cti_graph
            g = cti_graph.neighbours(conn, f"ioc:{indicator['value']}")
            if g.get("node") is not None:
                graph = g["neighbours"]
    return {
        "value": v, "host": host, "indicator": indicator,
        "relatedIocs": related_iocs,
        "alerts": {"total": alert_total, "items": alerts},
        "cases": cases,
        "darkWeb": {"total": dw_total, "items": dark_web},
        "assets": assets,
        "events": {"count": ev_count, "capped": ev_count >= ev_cap},
        "relatedEntities": rel,
        "analystActivity": analyst,
        "graph": graph,
    }


@router.get("/scan/enrich")
def scan_enrich(value: str, type: str = "", refresh: bool = False,
                user: dict = Depends(require_perm("cti.write"))):
    """Run the enrichment pipeline over an arbitrary value (no stored IOC
    required) - the IntelScope scanner's provider panel. Same engine as
    /iocs/{id}/enrich: builtin providers plus OTX/VirusTotal when configured,
    cached with TTL, and every provider row carries an honest `available`
    flag - nothing is fabricated for unconfigured providers.
    """
    from dashboard_api.enrichment import enrich
    v = value.strip()
    if not v:
        raise HTTPException(status_code=400, detail="value is required")
    with get_conn() as conn:
        result = enrich(conn, v, type.strip().lower(), refresh=refresh)
        conn.commit()   # persist provider cache rows
    return result


_SCAN_TYPES = {"url", "ip", "hash", "domain", "file", "cve"}
_VERDICTS = {"malicious", "suspicious", "clean", "unverified"}


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
