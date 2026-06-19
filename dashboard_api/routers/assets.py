"""Asset surface routes: inventory, create, detail, vulnerability rollup, summary KPIs."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user, require_perm
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
    software: list[dict] = []


@router.get("")
def list_assets(type: str | None = None, criticality: str | None = None,
                status: str | None = None, q: str | None = None,
                limit: int = Query(100, le=500), offset: int = 0,
                user: dict = Depends(current_user)):
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
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
        tenancy.enforce_quota(conn, tenancy.org_of(user), "assets")   # per-tenant asset cap
        conn.execute(
            "INSERT INTO assets (id,name,type,value,criticality,status,risk_score,last_scan,"
            "alerts,cves,open_ports,os,owner,patch_age,tags,uptime,created_at,software,org_id) "
            "VALUES (?,?,?,?,?,'unscanned',0,NULL,0,?,?,?,?,0,?,100.0,?,?,?)",
            (aid, name, body.type, value, body.criticality,
             dumps({"critical": 0, "high": 0, "medium": 0, "low": 0}), dumps([]),
             body.os, body.owner or user["email"], dumps(body.tags or ["new"]), now,
             dumps(body.software or []), tenancy.org_of(user)),
        )
        audit(conn, user["email"], "asset.create", aid, f"name={name} type={body.type}")
        conn.commit()
        row = conn.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    return row_to_dict(row)


@router.get("/summary")
def assets_summary(user: dict = Depends(current_user)):
    # Workspace clause for the rollups - a no-op until multi-tenancy is on.
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT criticality, status, risk_score, cves, alerts FROM assets WHERE 1=1 {sc}",
            sp).fetchall()
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
def risk_distribution(user: dict = Depends(current_user)):
    """Fleet-wide risk: band counts plus mean per-axis contribution (top driver)."""
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT criticality, patch_age, cves, open_ports, tags, alerts FROM assets WHERE 1=1 {sc}",
            sp
        ).fetchall()
    return fleet_risk_distribution(rows_to_dicts(rows))


@router.get("/vulns/summary")
def vuln_summary():
    """Fleet vulnerability KPIs from real scanner findings + asset state."""
    from dashboard_api.attack_surface import exposure_inventory
    with get_conn() as conn:
        findings = conn.execute(
            "SELECT cve, severity, cvss, kev, exploit FROM vuln_findings WHERE status='open'").fetchall()
        patch = conn.execute("SELECT AVG(patch_age) AS a FROM assets").fetchone()
        exposure = exposure_inventory(conn)["summary"]
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f["severity"] in by_sev:
            by_sev[f["severity"]] += 1
    distinct = {f["cve"] for f in findings}
    # Actively exploited = CISA-KEV-listed findings (a documented fact per CVE).
    exploited = len({f["cve"] for f in findings if f["kev"]})
    return {
        "totalFindings": len(findings),
        "distinctCves": len(distinct),
        "bySeverity": by_sev,
        "criticalAndHigh": by_sev["critical"] + by_sev["high"],
        "activelyExploited": exploited,
        "kevListed": exploited,
        "withExploit": len({f["cve"] for f in findings if f["exploit"]}),
        "avgPatchAge": round(patch["a"] or 0),
        "exposureScore": exposure["avgExposure"],
        "internetFacing": exposure["internetFacing"],
    }


@router.get("/vuln-findings")
def fleet_vuln_findings(limit: int = Query(200, le=1000)):
    """Fleet-wide CVE findings grouped per CVE: which assets are affected,
    KEV/exploit status, CVSS, fix version - the real Vulnerabilities list."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT v.cve, v.product, v.version, v.severity, v.cvss, v.fixed_in, v.summary, "
            "v.status, v.found_at, v.kev, v.exploit, a.name AS asset_name, a.owner AS asset_owner "
            "FROM vuln_findings v LEFT JOIN assets a ON a.id = v.asset_id "
            "WHERE v.status='open' ORDER BY v.cvss DESC, v.found_at DESC LIMIT ?",
            (limit,)).fetchall()
    grouped: dict[str, dict] = {}
    for r in rows:
        g = grouped.setdefault(r["cve"], {
            "cve": r["cve"], "cvss": r["cvss"], "severity": r["severity"],
            "summary": r["summary"], "fixedIn": r["fixed_in"],
            "kev": bool(r["kev"]), "exploit": bool(r["exploit"]),
            "products": set(), "affectedAssets": set(), "owners": set(),
            "firstFound": r["found_at"],
        })
        g["products"].add(f"{r['product']} {r['version']}")
        if r["asset_name"]:
            g["affectedAssets"].add(r["asset_name"])
        if r["asset_owner"]:
            g["owners"].add(r["asset_owner"])
        if r["found_at"] < g["firstFound"]:
            g["firstFound"] = r["found_at"]
    out = []
    for g in grouped.values():
        out.append({**g, "products": sorted(g["products"]),
                    "affectedAssets": sorted(g["affectedAssets"]),
                    "owners": sorted(g["owners"]),
                    "reference": f"https://nvd.nist.gov/vuln/detail/{g['cve']}"})
    out.sort(key=lambda x: -x["cvss"])
    return out


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


@router.get("/exposure")
def attack_surface_exposure():
    """Internet-facing inventory: every asset's transparent exposure score
    (public address, risky ports, plaintext web, CVEs on the exposed surface),
    ranked, with a fleet summary."""
    from dashboard_api.attack_surface import exposure_inventory
    with get_conn() as conn:
        return exposure_inventory(conn)


@router.get("/discovered")
def discovered_assets(limit: int = Query(50, le=1000)):
    """Passive attack-surface discovery: hosts emitting telemetry that are NOT
    in the asset inventory (shadow IT), with observed activity for vetting."""
    from dashboard_api.attack_surface import discover_unmanaged
    with get_conn() as conn:
        return {"items": discover_unmanaged(conn, limit=min(limit, 200))}


class PromoteBody(BaseModel):
    hostname: str
    criticality: str = "medium"
    type: str = "endpoint"


@router.post("/discovered/promote", status_code=201)
def promote_discovered(body: PromoteBody, user: dict = Depends(require_perm("assets.write"))):
    """Register a discovered host into the managed inventory."""
    name = body.hostname.strip()
    if not name:
        raise HTTPException(status_code=400, detail="hostname is required")
    if body.criticality not in _CRITICALITIES:
        raise HTTPException(status_code=400, detail=f"criticality must be one of {sorted(_CRITICALITIES)}")
    if body.type not in _ASSET_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {sorted(_ASSET_TYPES)}")
    aid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM assets WHERE name=?", (name,)).fetchone():
            raise HTTPException(status_code=409, detail="Asset already in the inventory")
        conn.execute(
            "INSERT INTO assets (id,name,type,value,criticality,status,risk_score,last_scan,"
            "alerts,cves,open_ports,os,owner,patch_age,tags,uptime,created_at,software,org_id) "
            "VALUES (?,?,?,?,?,'unscanned',0,NULL,0,?,?,NULL,?,0,?,100.0,?,'[]',?)",
            (aid, name, body.type, name, body.criticality,
             dumps({"critical": 0, "high": 0, "medium": 0, "low": 0}), dumps([]),
             user["email"], dumps(["discovered"]), now, tenancy.org_of(user)),
        )
        audit(conn, user["email"], "asset.promote_discovered", aid, f"hostname={name}")
        conn.commit()
        row = conn.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    return row_to_dict(row)


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


@router.post("/{asset_id}/scan")
def scan_asset_vulns(asset_id: str, user: dict = Depends(require_perm("assets.write"))):
    """Run a real vulnerability scan: match the asset's installed software
    against the CVE catalogue → concrete findings + refreshed risk."""
    from dashboard_api.vuln_scanner import scan_asset
    with get_conn() as conn:
        result = scan_asset(conn, asset_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        recompute_asset_risk(conn)
        audit(conn, user["email"], "asset.vuln_scan", asset_id,
              f"findings={len(result['findings'])}")
        conn.commit()
    return result


@router.post("/scan-all")
def scan_all_vulns(user: dict = Depends(require_perm("assets.write"))):
    """Scan every asset's software for known CVEs."""
    from dashboard_api.vuln_scanner import scan_all
    with get_conn() as conn:
        result = scan_all(conn)
        recompute_asset_risk(conn)
        record_job(conn, "assets.vuln_scan", "completed", {**result, "actor": user["email"]})
        audit(conn, user["email"], "asset.vuln_scan_all", None, f"findings={result['findings']}")
        conn.commit()
    return result


@router.delete("/{asset_id}", status_code=204)
def delete_asset(asset_id: str, user: dict = Depends(require_perm("assets.write"))):
    """Delete an asset (org-scoped). Refreshes fleet risk afterwards."""
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        cur = conn.execute(f"DELETE FROM assets WHERE id=? {sc}", (asset_id, *sp))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Asset not found")
        recompute_asset_risk(conn)
        audit(conn, user["email"], "asset.delete", asset_id)
        conn.commit()
    return Response(status_code=204)


@router.get("/{asset_id}/vulns")
def asset_vuln_findings(asset_id: str):
    """The concrete CVE findings for one asset (highest CVSS first)."""
    with get_conn() as conn:
        if not conn.execute("SELECT 1 FROM assets WHERE id=?", (asset_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Asset not found")
        rows = conn.execute(
            "SELECT * FROM vuln_findings WHERE asset_id=? ORDER BY cvss DESC, found_at DESC",
            (asset_id,)).fetchall()
    return rows_to_dicts(rows)


@router.get("/{asset_id}/activity")
def asset_activity(asset_id: str):
    """Everything tied to this asset, one click away: its alerts, the cases
    whose entities reference it, recent raw events, open CVE findings, and the
    playbook runs that responded - the asset↔alert↔case linkage."""
    with get_conn() as conn:
        row = conn.execute("SELECT id, name, value FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Asset not found")
        keys = [k for k in {row["name"], row["value"]} if k]
        ph = ",".join("?" * len(keys))
        alerts = rows_to_dicts(conn.execute(
            f"SELECT id, ts, title, severity, status, rule_name, mitre_tech_id, src_ip "
            f"FROM alerts WHERE hostname IN ({ph}) OR src_ip IN ({ph}) OR dest_ip IN ({ph}) "
            f"ORDER BY ts DESC LIMIT 50", keys * 3).fetchall())
        like_clauses = " OR ".join(["entities LIKE ?"] * len(keys))
        cases = rows_to_dicts(conn.execute(
            f"SELECT id, title, severity, status, created, playbook FROM cases "
            f"WHERE {like_clauses} ORDER BY created DESC LIMIT 20",
            [f'%"{k}"%' for k in keys]).fetchall())
        events = rows_to_dicts(conn.execute(
            f"SELECT id, ts, event_type, src_ip, dest_ip, raw FROM events "
            f"WHERE hostname IN ({ph}) OR src_ip IN ({ph}) OR dest_ip IN ({ph}) "
            f"ORDER BY ts DESC LIMIT 30", keys * 3).fetchall())
        vulns = rows_to_dicts(conn.execute(
            "SELECT cve, severity, cvss, product, version, status FROM vuln_findings "
            "WHERE asset_id=? AND status='open' ORDER BY cvss DESC LIMIT 30",
            (asset_id,)).fetchall())
        alert_ids = [a["id"] for a in alerts]
        runs = []
        if alert_ids:
            ph2 = ",".join("?" * len(alert_ids))
            runs = rows_to_dicts(conn.execute(
                f"SELECT id, playbook_name, ts, status, trigger FROM playbook_runs "
                f"WHERE alert_id IN ({ph2}) ORDER BY ts DESC LIMIT 10", alert_ids).fetchall())
    open_alerts = sum(1 for a in alerts if a["status"] not in ("resolved", "closed"))
    return {"assetId": asset_id, "name": row["name"],
            "alerts": alerts, "cases": cases, "events": events,
            "vulnFindings": vulns, "playbookRuns": runs,
            "summary": {"alerts": len(alerts), "openAlerts": open_alerts,
                        "cases": len(cases), "events": len(events),
                        "openVulns": len(vulns), "responses": len(runs)}}


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
