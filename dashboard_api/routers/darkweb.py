"""Dark Web monitoring: external-exposure findings (credentials, data sales,
brand mentions, threat-actor chatter, initial-access listings).

Distinct from SIEM (internal detections) and CTI (indicator intelligence):
this is what's being said about you *outside* your perimeter. Findings are
produced live by the engine and can be triaged through a status lifecycle.
"""
from datetime import datetime, timedelta, timezone

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
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with get_conn() as conn:
        # One grouped pass instead of fetching every finding into Python - the
        # rollup was a full-table read on a store that grows for its whole
        # retention window. `matched_user != ''` mirrors the old truthiness
        # check; the 24h window rides the same scan via SUM(CASE).
        rows = conn.execute(
            "SELECT category, COUNT(*) AS n, "
            "SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS crit, "
            "SUM(CASE WHEN matched_user IS NOT NULL AND matched_user != '' THEN 1 ELSE 0 END) AS matched, "
            "SUM(CASE WHEN status='takedown-requested' THEN 1 ELSE 0 END) AS takedown, "
            "SUM(CASE WHEN status IN ('new','investigating','takedown-requested') THEN 1 ELSE 0 END) AS open_n, "
            "SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS h24 "
            f"FROM dark_web_findings WHERE 1=1 {sc} GROUP BY category",
            [cutoff] + sp).fetchall()
    by_cat = {c: 0 for c in _CATEGORIES}
    for r in rows:
        if r["category"] in by_cat:
            by_cat[r["category"]] += r["n"]
    return {
        "total": sum(r["n"] for r in rows),
        "critical": sum(int(r["crit"] or 0) for r in rows),
        "credentialLeaks": by_cat["credential-leak"],
        "workforceMatches": sum(int(r["matched"] or 0) for r in rows),
        "takedownsRequested": sum(int(r["takedown"] or 0) for r in rows),
        "open": sum(int(r["open_n"] or 0) for r in rows),
        "byCategory": by_cat,
        "last24h": sum(int(r["h24"] or 0) for r in rows),
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
