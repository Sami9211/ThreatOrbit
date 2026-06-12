"""SIEM routes: alerts (list/detail/update), rules, log sources, hunts, KPIs."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user, require_perm
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.hunting import run_alert_hunt
from dashboard_api.webhooks import dispatch

router = APIRouter(prefix="/siem", tags=["siem"], dependencies=[Depends(current_user)])

SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class AlertUpdate(BaseModel):
    status: str | None = None
    disposition: str | None = None
    owner: str | None = None


class AlertCreate(BaseModel):
    title: str
    severity: str = "medium"
    description: str | None = None
    src_ip: str | None = None
    src_country: str | None = None
    mitre_tactic: str | None = None
    mitre_tactic_id: str | None = None
    mitre_tech: str | None = None
    mitre_tech_id: str | None = None
    rule_name: str = "Manual escalation"
    hostname: str | None = None
    username: str | None = None
    ti_hits: int = 0


class RuleUpdate(BaseModel):
    status: str | None = None
    severity_override: str | None = None
    suppression_window: int | None = None
    definition: dict | None = None


class RuleCreate(BaseModel):
    name: str
    category: str = "Custom"
    severity: str = "medium"
    mitre_tactic: str | None = None
    mitre_tech_id: str | None = None
    mitre_tech: str | None = None
    description: str | None = None
    kql: str | None = None
    definition: dict = {}
    tags: list[str] = []


class RuleTest(BaseModel):
    definition: dict


class IngestBody(BaseModel):
    lines: list[str]
    format: str = "auto"
    source: str = "collector"


class SourceCreate(BaseModel):
    name: str
    type: str = "Syslog"
    host: str | None = None
    format: str | None = None
    tags: list[str] = []


class HuntCreate(BaseModel):
    name: str
    description: str | None = None
    query: str | None = None
    technique: str | None = None


class HuntQuery(BaseModel):
    query: str
    time_range: str = "24h"


class EventSearch(BaseModel):
    query: str = ""
    time_range: str = "24h"


# ── Alerts ────────────────────────────────────────────────────────────────────

# Whitelisted sort columns → SQL ORDER BY expressions. Severity sorts by
# operational priority (critical first), not alphabetically. Anything not in
# this map is rejected, so the sort parameter can never inject SQL.
_ALERT_SORTS = {
    "ts": "ts",
    "risk_score": "risk_score",
    "event_count": "event_count",
    "ti_hits": "ti_hits",
    "severity": "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
                "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END",
}


@router.get("/alerts")
def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    tactic: str | None = None,
    disposition: str | None = None,
    owner: str | None = None,
    q: str | None = None,
    sort: str = Query("ts", description=f"one of {sorted(_ALERT_SORTS)}"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(50, le=500),
    offset: int = 0,
    user: dict = Depends(current_user),
):
    if sort not in _ALERT_SORTS:
        raise HTTPException(status_code=400, detail=f"sort must be one of {sorted(_ALERT_SORTS)}")
    clauses, params = [], []
    # Tenant isolation (reference pattern): scoped only when the deployment
    # flips DASHBOARD_MULTI_TENANT on — default installs see everything.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
    for col, val in (("severity", severity), ("status", status),
                     ("mitre_tactic", tactic), ("disposition", disposition), ("owner", owner)):
        if val:
            clauses.append(f"{col}=?"); params.append(val)
    if q:
        clauses.append("(title LIKE ? OR rule_name LIKE ? OR src_ip LIKE ? OR hostname LIKE ?)")
        params += [f"%{q}%"] * 4
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order_sql = f"{_ALERT_SORTS[sort]} {order.upper()}"
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY {order_sql} LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {"total": total, "items": rows_to_dicts(rows)}


@router.post("/alerts", status_code=201)
def create_alert(body: AlertCreate, user: dict = Depends(require_perm("siem.write"))):
    """Raise a SIEM alert manually or from escalated threat intelligence."""
    title = body.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")
    if body.severity not in SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Severity must be one of {sorted(SEVERITIES)}")
    risk = {"critical": 92, "high": 75, "medium": 50, "low": 25, "info": 10}[body.severity]
    aid = str(uuid.uuid4())
    now = _now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,rule_id,"
            "rule_name,mitre_tactic,mitre_tactic_id,mitre_tech,mitre_tech_id,src_ip,src_country,"
            "src_port,src_hostname,src_asn,dest_ip,dest_port,dest_service,username,hostname,"
            "host_criticality,process_name,cmd_line,description,raw_log,event_count,ti_hits,bytes_out,"
            "detect_latency_sec,ack_latency_sec,respond_latency_sec) "
            "VALUES (?,?,?,?,'new','undetermined','',?,'R-MANUAL',?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,"
            "NULL,NULL,?,?,NULL,NULL,NULL,?,?,1,?,0,0,NULL,NULL)",
            (aid, now, title, body.severity, risk, body.rule_name,
             body.mitre_tactic, body.mitre_tactic_id, body.mitre_tech, body.mitre_tech_id,
             body.src_ip, body.src_country, body.username, body.hostname,
             body.description or title, f"{now} {body.rule_name}: {title}", body.ti_hits),
        )
        audit(conn, user["email"], "alert.create", aid, f"title={title} severity={body.severity}")
        conn.commit()
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    dispatch("alert.created", {"id": aid, "title": title, "severity": body.severity,
                               "srcIp": body.src_ip, "raisedBy": user["email"]})
    return row_to_dict(row)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row_to_dict(row)


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: str, body: AlertUpdate, user: dict = Depends(require_perm("siem.write"))):
    fields, values = [], []
    for col in ("status", "disposition", "owner"):
        v = getattr(body, col)
        if v is not None:
            fields.append(f"{col}=?"); values.append(v)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    values.append(alert_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE alerts SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        changed = ",".join(f.split("=")[0] for f in fields)
        # FP feedback loop: marking an alert false-positive bumps its rule's FP rate.
        if body.disposition == "false-positive":
            row = conn.execute("SELECT rule_id, rule_name FROM alerts WHERE id=?", (alert_id,)).fetchone()
            rid = row["rule_id"] if row else None
            if rid:
                conn.execute(
                    "UPDATE detection_rules SET fp_rate=MIN(100, fp_rate+2) "
                    "WHERE id=? OR name=?", (rid, row["rule_name"]))
        audit(conn, user["email"], "alert.update", alert_id, f"fields={changed}")
        conn.commit()
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    return row_to_dict(row)


class SuppressionCreate(BaseModel):
    value: str
    field: str = "src_ip"
    rule_id: str = "*"
    mode: str = "suppress"
    reason: str | None = None


@router.get("/suppressions")
def list_suppressions(user: dict = Depends(current_user)):
    where, params = "", []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        where, params = "WHERE org_id=?", [tenancy.org_of(user)]
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM suppressions {where} ORDER BY created_at DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.post("/suppressions", status_code=201)
def create_suppression(body: SuppressionCreate, user: dict = Depends(require_perm("siem.write"))):
    if body.field not in ("src_ip", "username", "hostname"):
        raise HTTPException(status_code=400, detail="field must be src_ip|username|hostname")
    if body.mode not in ("suppress", "allow"):
        raise HTTPException(status_code=400, detail="mode must be suppress|allow")
    value = body.value.strip()
    if not value:
        raise HTTPException(status_code=400, detail="value is required")
    sid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO suppressions (id,rule_id,field,value,mode,reason,created_at,created_by,org_id) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, body.rule_id or "*", body.field, value, body.mode, body.reason,
             _now_iso(), user["email"], tenancy.org_of(user)),
        )
        # retro-close any currently-open alerts this suppression covers
        clause = f"{body.field}=?"
        params = [value]
        if body.rule_id and body.rule_id != "*":
            clause += " AND rule_id=?"; params.append(body.rule_id)
        conn.execute(
            f"UPDATE alerts SET status='closed', disposition='false-positive' "
            f"WHERE {clause} AND status NOT IN ('resolved','closed')", params)
        audit(conn, user["email"], "suppression.create", sid, f"{body.field}={value} mode={body.mode}")
        conn.commit()
        row = conn.execute("SELECT * FROM suppressions WHERE id=?", (sid,)).fetchone()
    return row_to_dict(row)


@router.delete("/suppressions/{suppression_id}", status_code=204)
def delete_suppression(suppression_id: str, user: dict = Depends(require_perm("siem.write"))):
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM suppressions WHERE id=?", (suppression_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Suppression not found")
        audit(conn, user["email"], "suppression.delete", suppression_id)
        conn.commit()
    return None


# ── KPIs ──────────────────────────────────────────────────────────────────────

@router.get("/kpis")
def siem_kpis():
    with get_conn() as conn:
        rows = conn.execute("SELECT severity, status, risk_score, disposition FROM alerts").fetchall()
        sources = conn.execute("SELECT eps_avg, status FROM log_sources").fetchall()
        retention = conn.execute("SELECT value FROM settings WHERE key='data_retention_days'").fetchone()
        # SOC response metrics, in minutes, from per-alert latency telemetry.
        lat = conn.execute(
            "SELECT AVG(detect_latency_sec) AS d, AVG(ack_latency_sec) AS a, "
            "AVG(respond_latency_sec) AS r FROM alerts"
        ).fetchone()
    total = len(rows)
    by_sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    fp = closed = 0
    for r in rows:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        if r["disposition"] == "false-positive":
            fp += 1
        if r["status"] in ("resolved", "closed"):
            closed += 1
    total_eps = round(sum(s["eps_avg"] for s in sources), 1)
    mttd = round((lat["d"] or 0) / 60, 1)
    mtta = round((lat["a"] or 0) / 60, 1)
    mttr = round((lat["r"] or 0) / 60, 1)
    return {
        "totalAlerts": total,
        "critical": by_sev["critical"], "high": by_sev["high"], "medium": by_sev["medium"],
        "mttd": mttd, "mttr": mttr, "mtta": mtta,
        "fpRate": round((fp / total * 100) if total else 0, 1),
        "automationRate": round((closed / total * 100) if total else 0, 1),
        "totalEps": total_eps,
        "daysData": int(retention["value"]) if retention else 90,
    }


# ── MITRE distribution ────────────────────────────────────────────────────────

_SEV_WEIGHT = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 1}
_ENTITY_FIELD = {"user": "username", "host": "hostname", "ip": "src_ip"}


@router.get("/entities")
def list_entities(type: str = Query("all", pattern="^(all|user|host|ip)$"),
                  limit: int = Query(25, le=100)):
    """UEBA: rank users/hosts/IPs by behavioural risk derived from their alert
    history — severity-weighted volume plus ATT&CK technique diversity."""
    types = [type] if type != "all" else ["user", "host", "ip"]
    out = []
    with get_conn() as conn:
        for etype in types:
            field = _ENTITY_FIELD[etype]
            rows = conn.execute(
                f"SELECT {field} AS entity, severity, mitre_tech_id, ts, status "
                f"FROM alerts WHERE {field} IS NOT NULL AND {field} != ''"
            ).fetchall()
            agg: dict[str, dict] = {}
            for r in rows:
                e = agg.setdefault(r["entity"], {
                    "value": r["entity"], "type": etype, "alerts": 0, "score": 0,
                    "techniques": set(), "open": 0, "lastSeen": None,
                    "bySeverity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                })
                e["alerts"] += 1
                e["score"] += _SEV_WEIGHT.get(r["severity"], 1)
                if r["mitre_tech_id"]:
                    e["techniques"].add(r["mitre_tech_id"])
                if r["severity"] in e["bySeverity"]:
                    e["bySeverity"][r["severity"]] += 1
                if r["status"] not in ("resolved", "closed"):
                    e["open"] += 1
                if e["lastSeen"] is None or (r["ts"] or "") > e["lastSeen"]:
                    e["lastSeen"] = r["ts"]
            for e in agg.values():
                tdiv = len(e["techniques"])
                e["techniqueCount"] = tdiv
                e["techniques"] = sorted(e["techniques"])[:6]
                # risk: severity-weighted volume + technique-diversity bonus, capped.
                e["risk"] = min(100, e["score"] + tdiv * 4)
                e["band"] = ("critical" if e["risk"] >= 70 else "high" if e["risk"] >= 45
                             else "elevated" if e["risk"] >= 20 else "normal")
                out.append(e)
    out.sort(key=lambda x: -x["risk"])
    return {"entities": out[:limit],
            "summary": {"tracked": len(out),
                        "highRisk": sum(1 for e in out if e["risk"] >= 45)}}


@router.get("/entities/detail")
def entity_detail(type: str = Query(..., pattern="^(user|host|ip)$"), value: str = Query(...)):
    """Per-entity risk timeline + contributing alerts (the UEBA drill-down)."""
    field = _ENTITY_FIELD[type]
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT id,title,severity,risk_score,mitre_tech_id,mitre_tactic,ts,status,rule_name "
            f"FROM alerts WHERE {field}=? ORDER BY ts DESC LIMIT 200", (value,)
        ).fetchall()
    alerts = [dict(r) for r in rows]
    # day-bucketed timeline of alert counts
    timeline: dict[str, int] = {}
    for a in alerts:
        day = (a["ts"] or "")[:10]
        if day:
            timeline[day] = timeline.get(day, 0) + 1
    techniques: dict[str, int] = {}
    for a in alerts:
        if a["mitre_tech_id"]:
            techniques[a["mitre_tech_id"]] = techniques.get(a["mitre_tech_id"], 0) + 1
    score = min(100, sum(_SEV_WEIGHT.get(a["severity"], 1) for a in alerts) + len(techniques) * 4)
    return {
        "value": value, "type": type, "risk": score, "alertCount": len(alerts),
        "timeline": [{"day": k, "count": v} for k, v in sorted(timeline.items())],
        "topTechniques": [{"technique": k, "count": v}
                          for k, v in sorted(techniques.items(), key=lambda x: -x[1])[:8]],
        "baseline": _entity_baseline(timeline),
        "alerts": alerts[:50],
    }


def _entity_baseline(timeline: dict[str, int]) -> dict:
    """Learned baseline: the entity's own daily-volume norm (mean + stddev over
    its prior days) and how far its latest day deviates (z-score). This is
    deviation-from-self anomaly scoring, not just raw volume."""
    import math
    days = sorted(timeline.items())
    if len(days) < 3:
        return {"mean": 0.0, "stdDev": 0.0, "current": days[-1][1] if days else 0,
                "zScore": 0.0, "deviating": False, "confidence": "insufficient-history"}
    history = [c for _, c in days[:-1]]          # all but the latest day
    current = days[-1][1]
    mean = sum(history) / len(history)
    var = sum((x - mean) ** 2 for x in history) / len(history)
    std = math.sqrt(var)
    z = round((current - mean) / std, 2) if std > 0 else (0.0 if current <= mean else 4.0)
    return {"mean": round(mean, 2), "stdDev": round(std, 2), "current": current,
            "zScore": z, "deviating": z >= 2.0,
            "confidence": "high" if len(history) >= 7 else "moderate"}


@router.get("/mitre-distribution")
def mitre_distribution():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT mitre_tactic AS tactic, COUNT(*) AS count FROM alerts "
            "WHERE mitre_tactic IS NOT NULL GROUP BY mitre_tactic ORDER BY count DESC"
        ).fetchall()
    from dashboard_api.seed import TACTIC_COLOR
    return [{"tactic": r["tactic"], "count": r["count"],
             "color": TACTIC_COLOR.get(r["tactic"], "#7A3CFF")} for r in rows]


# ── Rules ─────────────────────────────────────────────────────────────────────

@router.get("/rules")
def list_rules(category: str | None = None, status: str | None = None,
               user: dict = Depends(current_user)):
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
    if category:
        clauses.append("category=?"); params.append(category)
    if status:
        clauses.append("status=?"); params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM detection_rules {where} ORDER BY hits_24h DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.post("/rules", status_code=201)
def create_rule(body: RuleCreate, user: dict = Depends(require_perm("siem.write"))):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Rule name is required")
    if body.severity not in SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Severity must be one of {sorted(SEVERITIES)}")
    rid = f"R-{uuid.uuid4().hex[:6].upper()}"
    now = _now_iso()
    from dashboard_api.db import dumps
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO detection_rules (id,name,category,severity,mitre_tactic,mitre_tech_id,"
            "mitre_tech,hits_24h,fired_last_7d,fp_rate,status,source,last_fired,created,updated_by,"
            "description,kql,suppression_window,severity_override,tags,definition,org_id) "
            "VALUES (?,?,?,?,?,?,?,0,0,0,'enabled','custom',NULL,?,?,?,?,0,NULL,?,?,?)",
            (rid, name, body.category, body.severity, body.mitre_tactic, body.mitre_tech_id,
             body.mitre_tech, now, user["email"],
             body.description or f"Custom detection: {name}.", body.kql, dumps(body.tags),
             dumps(body.definition or {}), tenancy.org_of(user)),
        )
        audit(conn, user["email"], "rule.create", rid, f"name={name} severity={body.severity}")
        conn.commit()
        row = conn.execute("SELECT * FROM detection_rules WHERE id=?", (rid,)).fetchone()
    return row_to_dict(row)


class SigmaImport(BaseModel):
    yaml: str


@router.post("/rules/import-sigma", status_code=201)
def import_sigma_rule(body: SigmaImport, user: dict = Depends(require_perm("siem.write"))):
    """Import a Sigma YAML rule as a live, evaluable detection rule."""
    from dashboard_api.sigma import sigma_to_rule
    if not body.yaml.strip():
        raise HTTPException(status_code=400, detail="Sigma YAML is required")
    try:
        mapped = sigma_to_rule(body.yaml)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    rid = f"R-{uuid.uuid4().hex[:6].upper()}"
    now = _now_iso()
    from dashboard_api.db import dumps
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO detection_rules (id,name,category,severity,mitre_tactic,mitre_tactic_id,"
            "mitre_tech_id,mitre_tech,hits_24h,fired_last_7d,fp_rate,status,source,last_fired,"
            "created,updated_by,description,kql,suppression_window,severity_override,tags,definition,"
            "org_id) "
            "VALUES (?,?,?,?,?,?,?,NULL,0,0,0,'enabled','sigma',NULL,?,?,?,?,0,NULL,?,?,?)",
            (rid, mapped["name"], mapped["category"], mapped["severity"], mapped["mitre_tactic"],
             mapped["mitre_tactic_id"], mapped["mitre_tech_id"], now, user["email"],
             mapped["description"], body.yaml, dumps(mapped["tags"]), dumps(mapped["definition"]),
             tenancy.org_of(user)),
        )
        audit(conn, user["email"], "rule.import_sigma", rid, f"name={mapped['name']}")
        conn.commit()
        row = conn.execute("SELECT * FROM detection_rules WHERE id=?", (rid,)).fetchone()
    return {**row_to_dict(row), "importNotes": mapped["notes"]}


@router.get("/rules/{rule_id}/sigma")
def export_sigma_rule(rule_id: str):
    """Export a rule as Sigma YAML — the original document for Sigma-imported
    rules, generated Sigma for natively-authored ones."""
    from dashboard_api.sigma import rule_to_sigma
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM detection_rules WHERE id=?", (rule_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule = row_to_dict(row)
    if rule.get("source") == "sigma" and "detection" in (rule.get("kql") or ""):
        return {"yaml": rule["kql"], "source": "original"}
    if not (rule.get("definition") or {}).get("conditions"):
        raise HTTPException(status_code=400, detail="Rule has no evaluable definition to export")
    return {"yaml": rule_to_sigma(rule), "source": "generated"}


@router.post("/ingest")
def ingest(body: IngestBody, user: dict = Depends(current_user)):
    """Native log collector: POST raw log lines (syslog/apache/json/kv/auto),
    they're parsed into events and the detection rules + threat-intel matching
    fire on them. This is how production logs stream into the SIEM."""
    if not body.lines:
        raise HTTPException(status_code=400, detail="No log lines supplied")
    if len(body.lines) > 5000:
        raise HTTPException(status_code=400, detail="Max 5000 lines per request")
    if body.format not in ("auto", "json", "apache", "nginx", "kv", "syslog", "generic"):
        raise HTTPException(status_code=400, detail="Unsupported format")
    from dashboard_api.ingest import ingest_lines
    result = ingest_lines(body.lines, body.format, body.source.strip() or "collector")
    with get_conn() as conn:
        audit(conn, user["email"], "siem.ingest", body.source,
              f"lines={result['parsed']} alerts={result['alerts']}")
        conn.commit()
    return result


@router.get("/log-listeners")
def log_listeners_status():
    """Status of the long-running log collectors (syslog UDP listener + file/dir
    watcher) — what's enabled and where."""
    from dashboard_api.log_listeners import listener_status
    return listener_status()


@router.get("/attack-coverage")
def attack_coverage():
    """ATT&CK navigator data: per-technique rule coverage + observed alert
    volume, grouped by tactic, with coverage gaps highlighted."""
    import json as _json
    # MITRE technique → human name (the subset our rules/alerts use, extensible).
    TECH_NAME = {
        "T1110": "Brute Force", "T1078": "Valid Accounts", "T1059.001": "PowerShell",
        "T1190": "Exploit Public-Facing App", "T1083": "File & Directory Discovery",
        "T1071.001": "Web Protocols", "T1041": "Exfiltration Over C2", "T1566.002": "Spearphishing Link",
        "T1046": "Network Service Discovery", "T1204": "User Execution", "T1505.003": "Web Shell",
        "T1003": "OS Credential Dumping", "T1021": "Remote Services", "T1486": "Data Encrypted for Impact",
    }
    TACTIC = {
        "T1110": "Credential Access", "T1003": "Credential Access", "T1078": "Defense Evasion",
        "T1059.001": "Execution", "T1204": "Execution", "T1190": "Initial Access",
        "T1566.002": "Initial Access", "T1505.003": "Persistence", "T1083": "Discovery",
        "T1046": "Discovery", "T1071.001": "Command and Control", "T1041": "Exfiltration",
        "T1021": "Lateral Movement", "T1486": "Impact",
    }
    with get_conn() as conn:
        rules = conn.execute(
            "SELECT mitre_tech_id, status FROM detection_rules WHERE mitre_tech_id IS NOT NULL"
        ).fetchall()
        alerts = conn.execute(
            "SELECT mitre_tech_id, COUNT(*) AS n FROM alerts WHERE mitre_tech_id IS NOT NULL GROUP BY mitre_tech_id"
        ).fetchall()
    rule_cov: dict[str, int] = {}
    for r in rules:
        if r["status"] == "enabled":
            rule_cov[r["mitre_tech_id"]] = rule_cov.get(r["mitre_tech_id"], 0) + 1
    alert_cnt = {a["mitre_tech_id"]: a["n"] for a in alerts}
    techniques = set(TECH_NAME) | set(rule_cov) | set(alert_cnt)
    by_tactic: dict[str, list] = {}
    for t in sorted(techniques):
        tactic = TACTIC.get(t.split(".")[0]) or TACTIC.get(t) or "Other"
        by_tactic.setdefault(tactic, []).append({
            "technique": t, "name": TECH_NAME.get(t, t),
            "rules": rule_cov.get(t, 0), "alerts": alert_cnt.get(t, 0),
            "covered": rule_cov.get(t, 0) > 0,
        })
    covered = sum(1 for t in techniques if rule_cov.get(t, 0) > 0)
    return {
        "tactics": [{"tactic": k, "techniques": v} for k, v in by_tactic.items()],
        "summary": {"techniques": len(techniques), "covered": covered,
                    "gaps": len(techniques) - covered,
                    "coveragePct": round(covered / len(techniques) * 100) if techniques else 0},
    }


@router.get("/rule-schema")
def rule_schema():
    """Fields + operators the rule editor offers, with sample event types.

    `ecsAliases` maps Elastic Common Schema names to native fields so rules and
    searches authored in vendor-neutral ECS resolve transparently.
    """
    from dashboard_api.rule_engine import ECS_ALIASES, FIELDS, OPERATORS
    return {"fields": FIELDS, "operators": OPERATORS,
            "ecsAliases": ECS_ALIASES,
            "eventTypes": ["failed_login", "beacon", "process_start", "web_request",
                           "large_egress", "proxy_request", "group_change"],
            "groupByFields": ["src_ip", "dest_ip", "username", "hostname"]}


@router.post("/rules/test")
def test_rule(body: RuleTest):
    """Backtest a rule definition against recent events — returns matches without
    creating any alerts, so analysts can tune before enabling."""
    if not (body.definition.get("conditions")):
        raise HTTPException(status_code=400, detail="Rule needs at least one condition")
    from dashboard_api.engine import run_detection
    with get_conn() as conn:
        return run_detection(conn, preview_rule={"id": "preview", "name": "preview",
                                                 "severity": "medium", "definition": body.definition})


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, user: dict = Depends(current_user)):
    valid_statuses = {"enabled", "disabled", "suppressed"}
    if body.status and body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(valid_statuses)}")
    fields, values = [], []
    if body.status is not None:
        fields.append("status=?"); values.append(body.status)
    if body.severity_override is not None:
        fields.append("severity_override=?"); values.append(body.severity_override)
    if body.suppression_window is not None:
        fields.append("suppression_window=?"); values.append(body.suppression_window)
    if body.definition is not None:
        from dashboard_api.db import dumps
        fields.append("definition=?"); values.append(dumps(body.definition))
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    fields.append("updated_by=?"); values.append(user["email"])
    values.append(rule_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE detection_rules SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
        audit(conn, user["email"], "rule.update", rule_id,
              f"fields={','.join(f.split('=')[0] for f in fields[:-1])}")
        conn.commit()
        row = conn.execute("SELECT * FROM detection_rules WHERE id=?", (rule_id,)).fetchone()
    return row_to_dict(row)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str, user: dict = Depends(require_perm("siem.write"))):
    with get_conn() as conn:
        row = conn.execute("SELECT name FROM detection_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        conn.execute("DELETE FROM detection_rules WHERE id=?", (rule_id,))
        audit(conn, user["email"], "rule.delete", rule_id, f"name={row['name']}")
        conn.commit()
    return None


# ── Log sources ───────────────────────────────────────────────────────────────

@router.get("/sources")
def list_sources(user: dict = Depends(current_user)):
    where, params = "", []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        where, params = "WHERE org_id=?", [tenancy.org_of(user)]
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM log_sources {where} ORDER BY eps_avg DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.post("/sources", status_code=201)
def create_source(body: SourceCreate, user: dict = Depends(current_user)):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Source name is required")
    sid = str(uuid.uuid4())
    from dashboard_api.db import dumps
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO log_sources (id,name,type,host,status,eps_avg,eps_peak,last_event,"
            "total_events_24h,latency_ms,parse_success,format,tags,org_id) "
            "VALUES (?,?,?,?,'healthy',0,0,NULL,0,0,100,?,?,?)",
            (sid, name, body.type, body.host, body.format or body.type, dumps(body.tags),
             tenancy.org_of(user)),
        )
        audit(conn, user["email"], "source.create", sid, f"name={name} type={body.type}")
        conn.commit()
        row = conn.execute("SELECT * FROM log_sources WHERE id=?", (sid,)).fetchone()
    return row_to_dict(row)


# ── Correlations ──────────────────────────────────────────────────────────────

@router.get("/correlations")
def correlations(min_alerts: int = Query(2, ge=2, le=50)):
    """Group unresolved alerts by shared pivot (src_ip, hostname, username).

    Returns clusters with >1 member ordered by alert count descending.
    Each cluster includes the aggregated severity (highest in group) and
    the contributing alert IDs so the UI can link through.
    """
    SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, title, severity, src_ip, hostname, username, ts "
            "FROM alerts WHERE status NOT IN ('resolved','closed')"
        ).fetchall()

    # Build per-pivot buckets
    buckets: dict[tuple, list] = {}
    for r in rows:
        for pivot_key, pivot_val in (
            ("src_ip", r["src_ip"]),
            ("hostname", r["hostname"]),
            ("username", r["username"]),
        ):
            if not pivot_val:
                continue
            key = (pivot_key, pivot_val)
            buckets.setdefault(key, []).append(row_to_dict(r))

    clusters = []
    for (pivot_key, pivot_val), alerts in buckets.items():
        if len(alerts) < min_alerts:
            continue
        top_sev = max(alerts, key=lambda a: SEV_ORDER.get(a["severity"], 0))["severity"]
        clusters.append({
            "pivot": pivot_key,
            "value": pivot_val,
            "alertCount": len(alerts),
            "severity": top_sev,
            "alerts": [{"id": a["id"], "title": a["title"],
                        "severity": a["severity"], "ts": a["ts"]} for a in alerts],
        })

    clusters.sort(key=lambda c: c["alertCount"], reverse=True)
    return clusters


# ── Saved hunts ───────────────────────────────────────────────────────────────

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
            f"FROM saved_hunts WHERE domain='siem'{extra} ORDER BY last_run DESC", params
        ).fetchall()
    return rows_to_dicts(rows)


@router.post("/hunts", status_code=201)
def create_hunt(body: HuntCreate, user: dict = Depends(current_user)):
    from dashboard_api.hunting import create_saved_hunt
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Hunt name is required")
    return create_saved_hunt("siem", name, body.description, body.query, body.technique,
                             user["email"], org_id=tenancy.org_of(user))


@router.post("/hunts/{hunt_id}/run")
def run_hunt(hunt_id: str, user: dict = Depends(current_user)):
    from dashboard_api.hunting import run_saved_hunt
    result = run_saved_hunt("siem", hunt_id, user["email"])
    if result is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return result


class HuntSchedule(BaseModel):
    schedule_minutes: int = 0
    auto_alert: bool = True


@router.post("/hunts/{hunt_id}/schedule")
def schedule_hunt(hunt_id: str, body: HuntSchedule, user: dict = Depends(require_perm("siem.write"))):
    """Schedule a saved hunt to run on an interval (0 = off). When it runs and
    finds events, it raises a SIEM alert (auto_alert) — a detection over time."""
    if body.schedule_minutes < 0 or body.schedule_minutes > 10080:
        raise HTTPException(status_code=400, detail="schedule_minutes must be 0..10080")
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE saved_hunts SET schedule_minutes=?, auto_alert=?, "
            "status=CASE WHEN ?>0 THEN 'scheduled' ELSE 'idle' END WHERE id=? AND domain='siem'",
            (body.schedule_minutes, 1 if body.auto_alert else 0, body.schedule_minutes, hunt_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Hunt not found")
        audit(conn, user["email"], "hunt.schedule", hunt_id, f"every={body.schedule_minutes}m")
        conn.commit()
        row = conn.execute(
            "SELECT id, name, description AS hypothesis, query, technique, schedule_minutes, "
            "auto_alert, last_scheduled, status FROM saved_hunts WHERE id=?", (hunt_id,)).fetchone()
    return row_to_dict(row)


@router.post("/hunts/run-scheduled")
def run_scheduled_hunts_now(user: dict = Depends(require_perm("siem.write"))):
    """Run all due scheduled hunts immediately (also runs on the engine tick)."""
    from dashboard_api.hunting import run_due_scheduled_hunts
    with get_conn() as conn:
        result = run_due_scheduled_hunts(conn)
        conn.commit()
    return result


@router.post("/hunt-query")
def hunt_query(body: HuntQuery):
    """Run an ad-hoc hunt query against the live alert store."""
    if body.time_range not in ("1h", "6h", "24h", "7d"):
        raise HTTPException(status_code=400, detail="time_range must be 1h|6h|24h|7d")
    if not body.query.strip():
        raise HTTPException(status_code=400, detail="Query is required")
    return run_alert_hunt(body.query, body.time_range)


@router.post("/search")
def event_stream_search(body: EventSearch):
    """Field-operator search over the raw event stream (Splunk/KQL-style).

    Supports `field=value`, `!= > < >= <=`, `~regex`, `:contains`,
    `field in a,b,c`, bare full-text tokens, and `| stats count by <field>`.
    """
    if body.time_range not in ("1h", "6h", "24h", "7d"):
        raise HTTPException(status_code=400, detail="time_range must be 1h|6h|24h|7d")
    from dashboard_api.hunting import event_search
    return event_search(body.query, body.time_range)
