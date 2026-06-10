"""Report routes: structured, sectioned reports per domain and date range."""
from fastapi import APIRouter, Depends, HTTPException, Query

from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn
from dashboard_api.reports import REPORT_KINDS, build_report

router = APIRouter(prefix="/reports", tags=["reports"], dependencies=[Depends(current_user)])


@router.get("/kinds")
def list_kinds():
    labels = {
        "executive": "Executive Summary", "siem": "SIEM Detection",
        "soar": "SOAR Incident Response", "cti": "Threat Intelligence",
        "assets": "Asset Risk & Exposure", "darkweb": "Dark Web Exposure",
    }
    return [{"kind": k, "label": labels.get(k, k)} for k in REPORT_KINDS]


@router.get("/incident")
def incident_report(case_id: str = Query(..., description="SOAR case id"),
                    user: dict = Depends(current_user)):
    """Post-incident report for one case: MITRE-mapped timeline, response
    actions, SLA verdict, lessons-learned scaffold."""
    from dashboard_api.reports import build_incident_report
    try:
        report = build_incident_report(case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    with get_conn() as conn:
        audit(conn, user["email"], "report.generate", "incident", f"case={case_id}")
        conn.commit()
    return report


@router.get("/{kind}")
def generate(kind: str,
             period: str = Query("weekly", pattern="^(daily|weekly|monthly|custom)$"),
             frm: str | None = Query(None, alias="from"),
             to: str | None = None,
             user: dict = Depends(current_user)):
    if kind not in REPORT_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {REPORT_KINDS}")
    if period == "custom" and not frm:
        raise HTTPException(status_code=400, detail="custom period requires a 'from' date")
    try:
        report = build_report(kind, period, frm, to)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    with get_conn() as conn:
        audit(conn, user["email"], "report.generate", kind, f"period={period}")
        conn.commit()
    return report
