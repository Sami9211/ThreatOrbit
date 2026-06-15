"""Dark Web monitoring: external-exposure findings (credentials, data sales,
brand mentions, threat-actor chatter, initial-access listings).

Distinct from SIEM (internal detections) and CTI (indicator intelligence):
this is what's being said about you *outside* your perimeter. Findings are
produced live by the engine and can be triaged through a status lifecycle.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api.auth import current_user, require_perm
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.webhooks import dispatch

router = APIRouter(prefix="/darkweb", tags=["darkweb"], dependencies=[Depends(current_user)])

_STATUSES = {"new", "investigating", "takedown-requested", "mitigated", "dismissed"}
_CATEGORIES = {"credential-leak", "data-for-sale", "brand-mention", "actor-chatter", "infrastructure"}


class FindingUpdate(BaseModel):
    status: str


@router.get("/findings")
def list_findings(category: str | None = None, severity: str | None = None,
                  status: str | None = None, q: str | None = None,
                  limit: int = Query(100, le=500), offset: int = 0,
                  user: dict = Depends(current_user)):
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
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
def summary(user: dict = Depends(current_user)):
    # Workspace clause for the rollups - a no-op until multi-tenancy is on.
    from dashboard_api import tenancy
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT category, severity, status, matched_user FROM dark_web_findings WHERE 1=1 {sc}",
            sp).fetchall()
    total = len(rows)
    by_cat = {c: 0 for c in _CATEGORIES}
    for r in rows:
        if r["category"] in by_cat:
            by_cat[r["category"]] += 1
    return {
        "total": total,
        "critical": sum(1 for r in rows if r["severity"] == "critical"),
        "credentialLeaks": by_cat["credential-leak"],
        "workforceMatches": sum(1 for r in rows if r["matched_user"]),
        "takedownsRequested": sum(1 for r in rows if r["status"] == "takedown-requested"),
        "open": sum(1 for r in rows if r["status"] in ("new", "investigating", "takedown-requested")),
        "byCategory": by_cat,
        "last24h": total,  # engine-produced, all recent
    }


@router.post("/match-credentials")
def run_credential_matching(user: dict = Depends(require_perm("darkweb.write"))):
    """Match credential-leak findings against the org's user directory; matches
    are stamped, escalated to critical, and notified (force-reset events)."""
    from dashboard_api.darkweb_logic import match_credential_leaks
    with get_conn() as conn:
        result = match_credential_leaks(conn)
        audit(conn, user["email"], "darkweb.match_credentials", None,
              f"matched={result['matched']}")
        conn.commit()
    return result


@router.post("/findings/{finding_id}/takedown")
def takedown(finding_id: str, user: dict = Depends(require_perm("darkweb.write"))):
    """Start the takedown workflow for a finding: stamps the request and emits
    a `darkweb.takedown` webhook for external takedown/ticketing services."""
    from dashboard_api.darkweb_logic import request_takedown
    with get_conn() as conn:
        updated = request_takedown(conn, finding_id, user["email"])
        if updated is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        audit(conn, user["email"], "darkweb.takedown", finding_id)
        conn.commit()
    dispatch("darkweb.takedown", {"id": finding_id, "title": updated["title"],
                                  "source": updated["source"], "url": updated["url"],
                                  "requestedBy": user["email"]},
             org=user.get("org_id"))
    return updated


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: str, body: FindingUpdate, user: dict = Depends(require_perm("darkweb.write"))):
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
