"""Dark Web monitoring: external-exposure findings (credentials, data sales,
brand mentions, threat-actor chatter, initial-access listings).

Distinct from SIEM (internal detections) and CTI (indicator intelligence):
this is what's being said about you *outside* your perimeter. Findings are
produced live by the engine and can be triaged through a status lifecycle.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/darkweb", tags=["darkweb"], dependencies=[Depends(current_user)])

_STATUSES = {"new", "investigating", "mitigated", "dismissed"}
_CATEGORIES = {"credential-leak", "data-for-sale", "brand-mention", "actor-chatter", "infrastructure"}


class FindingUpdate(BaseModel):
    status: str


@router.get("/findings")
def list_findings(category: str | None = None, severity: str | None = None,
                  status: str | None = None, q: str | None = None,
                  limit: int = Query(100, le=500), offset: int = 0):
    clauses, params = [], []
    for col, val in (("category", category), ("severity", severity), ("status", status)):
        if val:
            clauses.append(f"{col}=?"); params.append(val)
    if q:
        clauses.append("(title LIKE ? OR entity LIKE ? OR actor LIKE ?)")
        params += [f"%{q}%"] * 3
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM dark_web_findings {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM dark_web_findings {where} ORDER BY ts DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {"total": total, "items": rows_to_dicts(rows)}


@router.get("/summary")
def summary():
    with get_conn() as conn:
        rows = conn.execute("SELECT category, severity, status FROM dark_web_findings").fetchall()
    total = len(rows)
    by_cat = {c: 0 for c in _CATEGORIES}
    for r in rows:
        if r["category"] in by_cat:
            by_cat[r["category"]] += 1
    return {
        "total": total,
        "critical": sum(1 for r in rows if r["severity"] == "critical"),
        "credentialLeaks": by_cat["credential-leak"],
        "open": sum(1 for r in rows if r["status"] in ("new", "investigating")),
        "byCategory": by_cat,
        "last24h": total,  # engine-produced, all recent
    }


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: str, body: FindingUpdate, user: dict = Depends(current_user)):
    if body.status not in _STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(_STATUSES)}")
    with get_conn() as conn:
        cur = conn.execute("UPDATE dark_web_findings SET status=? WHERE id=?", (body.status, finding_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Finding not found")
        audit(conn, user["email"], "darkweb.update", finding_id, f"status={body.status}")
        conn.commit()
        row = conn.execute("SELECT * FROM dark_web_findings WHERE id=?", (finding_id,)).fetchone()
    return row_to_dict(row)
