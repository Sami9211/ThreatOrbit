"""Report routes: structured, sectioned reports per domain and date range."""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn
from dashboard_api.report_render import render
from dashboard_api.reports import REPORT_KINDS, build_report

_AUDIENCE_RE = "^(technical|executive|compliance)$"
_FORMAT_RE = "^(json|csv|markdown|html)$"


def _as_file(report: dict, kind: str, audience: str, period: str, fmt: str) -> Response:
    """Render a report to a downloadable attachment (CSV / Markdown / HTML)."""
    content, media, ext = render(report, fmt)
    filename = f"threatorbit-{kind}-{audience}-{period}.{ext}"
    return Response(content, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

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
                    audience: str = Query("technical", pattern=_AUDIENCE_RE),
                    fmt: str = Query("json", alias="format", pattern=_FORMAT_RE),
                    user: dict = Depends(current_user)):
    """Post-incident report for one case: MITRE-mapped timeline, response
    actions, SLA verdict, lessons-learned scaffold."""
    from dashboard_api.reports import apply_audience, build_incident_report
    try:
        report = apply_audience(build_incident_report(case_id), audience)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    with get_conn() as conn:
        audit(conn, user["email"], "report.generate", "incident", f"case={case_id} fmt={fmt}")
        conn.commit()
    return report if fmt == "json" else _as_file(report, "incident", audience, case_id, fmt)


@router.get("/{kind}")
def generate(kind: str,
             period: str = Query("weekly", pattern="^(daily|weekly|monthly|custom)$"),
             audience: str = Query("technical", pattern=_AUDIENCE_RE),
             fmt: str = Query("json", alias="format", pattern=_FORMAT_RE),
             frm: str | None = Query(None, alias="from"),
             to: str | None = None,
             user: dict = Depends(current_user)):
    if kind not in REPORT_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {REPORT_KINDS}")
    if period == "custom" and not frm:
        raise HTTPException(status_code=400, detail="custom period requires a 'from' date")
    try:
        report = build_report(kind, period, frm, to, audience)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    with get_conn() as conn:
        audit(conn, user["email"], "report.generate", kind, f"period={period} audience={audience} fmt={fmt}")
        conn.commit()
    return report if fmt == "json" else _as_file(report, kind, audience, period, fmt)
