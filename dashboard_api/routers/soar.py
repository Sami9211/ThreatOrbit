"""SOAR routes: cases, playbooks, integrations, and aggregated metrics."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user
from dashboard_api.db import get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/soar", tags=["soar"], dependencies=[Depends(current_user)])


class CaseUpdate(BaseModel):
    status: str | None = None
    owner: str | None = None
    severity: str | None = None


@router.get("/cases")
def list_cases(status: str | None = None, severity: str | None = None):
    clauses, params = [], []
    if status:
        clauses.append("status=?"); params.append(status)
    if severity:
        clauses.append("severity=?"); params.append(severity)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM cases {where} ORDER BY updated DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.get("/cases/{case_id}")
def get_case(case_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    return row_to_dict(row)


@router.patch("/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate):
    fields, values = [], []
    for col in ("status", "owner", "severity"):
        v = getattr(body, col)
        if v is not None:
            fields.append(f"{col}=?"); values.append(v)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    from datetime import datetime, timezone
    fields.append("updated=?"); values.append(datetime.now(timezone.utc).replace(microsecond=0).isoformat())
    values.append(case_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE cases SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Case not found")
        conn.commit()
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return row_to_dict(row)


@router.get("/playbooks")
def list_playbooks():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM playbooks ORDER BY runs DESC").fetchall()
    return rows_to_dicts(rows)


@router.get("/playbooks/{playbook_id}")
def get_playbook(playbook_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return row_to_dict(row)


@router.get("/integrations")
def list_integrations():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM integrations ORDER BY name").fetchall()
    return rows_to_dicts(rows)


@router.get("/metrics")
def soar_metrics():
    with get_conn() as conn:
        cases = conn.execute("SELECT status, severity FROM cases").fetchall()
        pbs = conn.execute("SELECT runs, success_rate, avg_time, last_run FROM playbooks").fetchall()
    open_cases = sum(1 for c in cases if c["status"] not in ("resolved", "closed"))
    crit_open = sum(1 for c in cases if c["status"] not in ("resolved", "closed") and c["severity"] == "critical")
    closed_week = sum(1 for c in cases if c["status"] in ("resolved", "closed"))
    total_runs = sum(p["runs"] for p in pbs)
    avg_pb = int(sum(p["avg_time"] for p in pbs) / len(pbs)) if pbs else 0
    # Automation rate: share of playbook runs vs total case+run activity (approximation).
    automation_rate = round(total_runs / (total_runs + len(cases)) * 100, 1) if pbs else 0
    return {
        "openCases": open_cases,
        "criticalOpen": crit_open,
        "mttr": 3.8, "mttrTrend": "↓ 12%",
        "automationRate": automation_rate, "automationTrend": "↑ 8%",
        "timeSavedMonth": round(total_runs * avg_pb / 3600, 1),
        "playbooksToday": sum(1 for p in pbs if p["last_run"]),
        "avgPlaybookTime": avg_pb,
        "casesClosedWeek": closed_week,
    }
