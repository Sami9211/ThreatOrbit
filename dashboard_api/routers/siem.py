"""SIEM routes: alerts (list/detail/update), rules, log sources, saved hunts, KPIs."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api.auth import current_user
from dashboard_api.db import get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/siem", tags=["siem"], dependencies=[Depends(current_user)])


class AlertUpdate(BaseModel):
    status: str | None = None
    disposition: str | None = None
    owner: str | None = None


@router.get("/alerts")
def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    q: str | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    clauses, params = [], []
    if severity:
        clauses.append("severity=?"); params.append(severity)
    if status:
        clauses.append("status=?"); params.append(status)
    if q:
        clauses.append("(title LIKE ? OR rule_name LIKE ? OR src_ip LIKE ? OR hostname LIKE ?)")
        params += [f"%{q}%"] * 4
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY ts DESC LIMIT ? OFFSET ?",
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
def update_alert(alert_id: str, body: AlertUpdate):
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
        conn.commit()
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    return row_to_dict(row)


@router.get("/kpis")
def siem_kpis():
    with get_conn() as conn:
        rows = conn.execute("SELECT severity, status, risk_score, disposition FROM alerts").fetchall()
        sources = conn.execute("SELECT eps_avg, status FROM log_sources").fetchall()
        retention = conn.execute("SELECT value FROM settings WHERE key='data_retention_days'").fetchone()
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
    return {
        "totalAlerts": total,
        "critical": by_sev["critical"], "high": by_sev["high"], "medium": by_sev["medium"],
        "mttd": 142, "mttr": 3.8, "mtta": 7,
        "fpRate": round((fp / total * 100) if total else 0, 1),
        "automationRate": round((closed / total * 100) if total else 0, 1),
        "totalEps": total_eps,
        "daysData": int(retention["value"]) if retention else 90,
    }


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


@router.get("/sources")
def list_sources():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM log_sources ORDER BY eps_avg DESC").fetchall()
    return rows_to_dicts(rows)


@router.get("/hunts")
def list_hunts():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM saved_hunts WHERE domain='siem' ORDER BY last_run DESC").fetchall()
    return rows_to_dicts(rows)
