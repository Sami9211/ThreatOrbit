"""SIEM routes: alerts (list/detail/update), rules, log sources, saved hunts, KPIs."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/siem", tags=["siem"], dependencies=[Depends(current_user)])


class AlertUpdate(BaseModel):
    status: str | None = None
    disposition: str | None = None
    owner: str | None = None


class RuleUpdate(BaseModel):
    status: str | None = None
    severity_override: str | None = None
    suppression_window: int | None = None


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
):
    if sort not in _ALERT_SORTS:
        raise HTTPException(status_code=400, detail=f"sort must be one of {sorted(_ALERT_SORTS)}")
    clauses, params = [], []
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


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row_to_dict(row)


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: str, body: AlertUpdate, user: dict = Depends(current_user)):
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
        audit(conn, user["email"], "alert.update", alert_id, f"fields={changed}")
        conn.commit()
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    return row_to_dict(row)


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
def list_rules(category: str | None = None, status: str | None = None):
    clauses, params = [], []
    if category:
        clauses.append("category=?"); params.append(category)
    if status:
        clauses.append("status=?"); params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM detection_rules {where} ORDER BY hits_24h DESC", params).fetchall()
    return rows_to_dicts(rows)


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


# ── Log sources ───────────────────────────────────────────────────────────────

@router.get("/sources")
def list_sources():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM log_sources ORDER BY eps_avg DESC").fetchall()
    return rows_to_dicts(rows)


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
def list_hunts():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, description AS hypothesis, author AS analyst, "
            "query, technique, last_run, hit_count AS artifacts, "
            "status, progress, domain "
            "FROM saved_hunts WHERE domain='siem' ORDER BY last_run DESC"
        ).fetchall()
    return rows_to_dicts(rows)
