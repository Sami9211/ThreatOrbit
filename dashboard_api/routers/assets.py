"""Asset surface routes: inventory, create, detail, vulnerability rollup, summary KPIs."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api.auth import current_user
from dashboard_api.db import audit, dumps, get_conn, record_job, row_to_dict, rows_to_dicts
from dashboard_api.scoring import fleet_risk_distribution, recompute_asset_risk, risk_breakdown

router = APIRouter(prefix="/assets", tags=["assets"], dependencies=[Depends(current_user)])

_ASSET_TYPES = {"domain", "ip", "server", "cloud", "database", "endpoint"}
_CRITICALITIES = {"critical", "high", "medium", "low"}


class AssetCreate(BaseModel):
    name: str
    type: str = "server"
    value: str
    criticality: str = "medium"
    os: str | None = None
    owner: str | None = None
    tags: list[str] = []


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


@router.post("", status_code=201)
def create_asset(body: AssetCreate, user: dict = Depends(current_user)):
    name = body.name.strip()
    value = body.value.strip()
    if not name or not value:
        raise HTTPException(status_code=400, detail="name and value are required")
    if body.type not in _ASSET_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {sorted(_ASSET_TYPES)}")
    if body.criticality not in _CRITICALITIES:
        raise HTTPException(status_code=400, detail=f"criticality must be one of {sorted(_CRITICALITIES)}")
    aid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO assets (id,name,type,value,criticality,status,risk_score,last_scan,"
            "alerts,cves,open_ports,os,owner,patch_age,tags,uptime,created_at) "
            "VALUES (?,?,?,?,?,'unscanned',0,NULL,0,?,?,?,?,0,?,100.0,?)",
            (aid, name, body.type, value, body.criticality,
             dumps({"critical": 0, "high": 0, "medium": 0, "low": 0}), dumps([]),
             body.os, body.owner or user["email"], dumps(body.tags or ["new"]), now),
        )
        audit(conn, user["email"], "asset.create", aid, f"name={name} type={body.type}")
        conn.commit()
        row = conn.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    return row_to_dict(row)


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
        record_job(conn, "assets.recompute_risk", "completed",
                   {"updated": count, "actor": user["email"]})
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
