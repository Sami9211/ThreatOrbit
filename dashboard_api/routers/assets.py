"""Asset surface routes: inventory, detail, vulnerability rollup, summary KPIs."""
from fastapi import APIRouter, Depends, HTTPException, Query

from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.scoring import fleet_risk_distribution, recompute_asset_risk, risk_breakdown

router = APIRouter(prefix="/assets", tags=["assets"], dependencies=[Depends(current_user)])


@router.get("")
def list_assets(type: str | None = None, criticality: str | None = None,
                status: str | None = None, q: str | None = None,
                limit: int = Query(100, le=500), offset: int = 0):
    clauses, params = [], []
    for col, val in (("type", type), ("criticality", criticality), ("status", status)):
        if val:
            clauses.append(f"{col}=?"); params.append(val)
    if q:
        clauses.append("(name LIKE ? OR value LIKE ?)"); params += [f"%{q}%"] * 2
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM assets {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM assets {where} ORDER BY risk_score DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {"total": total, "items": rows_to_dicts(rows)}


@router.get("/summary")
def assets_summary():
    with get_conn() as conn:
        rows = conn.execute("SELECT criticality, status, risk_score, cves, alerts FROM assets").fetchall()
    import json
    total = len(rows)
    crit = sum(1 for r in rows if r["criticality"] == "critical")
    at_risk = sum(1 for r in rows if r["status"] in ("at-risk", "critical"))
    avg_risk = round(sum(r["risk_score"] for r in rows) / total, 1) if total else 0
    cve_tot = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        c = json.loads(r["cves"]) if isinstance(r["cves"], str) else r["cves"]
        for k in cve_tot:
            cve_tot[k] += c.get(k, 0)
    return {
        "totalAssets": total, "criticalAssets": crit, "atRisk": at_risk,
        "avgRiskScore": avg_risk, "openAlerts": sum(r["alerts"] for r in rows),
        "cves": cve_tot,
    }


@router.get("/risk-distribution")
def risk_distribution():
    """Fleet-wide risk: band counts plus mean per-axis contribution (top driver)."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT criticality, patch_age, cves, open_ports, tags, alerts FROM assets"
        ).fetchall()
    return fleet_risk_distribution(rows_to_dicts(rows))


@router.get("/vulns")
def vulnerabilities():
    """Vulnerability rollup per asset, highest CVE burden first."""
    import json
    with get_conn() as conn:
        rows = conn.execute("SELECT id,name,type,criticality,cves,patch_age,risk_score FROM assets").fetchall()
    out = []
    for r in rows:
        c = json.loads(r["cves"]) if isinstance(r["cves"], str) else r["cves"]
        weighted = c["critical"] * 25 + c["high"] * 10 + c["medium"] * 3 + c["low"]
        out.append({**row_to_dict(r), "cveTotal": sum(c.values()), "cveWeighted": weighted})
    out.sort(key=lambda x: x["cveWeighted"], reverse=True)
    return out


@router.post("/recompute-risk")
def recompute_risk(user: dict = Depends(current_user)):
    """Recalculate every asset's risk from current CVEs and live alert pressure."""
    with get_conn() as conn:
        count = recompute_asset_risk(conn)
        audit(conn, user["email"], "asset.recompute_risk", None, f"assets={count}")
        conn.commit()
    return {"updated": count}


@router.get("/{asset_id}")
def get_asset(asset_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset = row_to_dict(row)
    # Attach a transparent per-axis explanation of the stored risk score.
    asset["riskBreakdown"] = risk_breakdown(
        cves=asset["cves"], criticality=asset["criticality"],
        patch_age=asset["patch_age"], open_alerts=asset["alerts"],
        open_ports=asset["open_ports"], tags=asset["tags"],
    )
    return asset
