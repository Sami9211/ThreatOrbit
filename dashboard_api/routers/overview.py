"""Overview dashboard: top-level KPIs, charts, and recent-activity rollups.

Everything here is derived from the live tables so the overview stays consistent
with the detail pages (the same alerts that drive SIEM also drive these counts).
"""
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query

from dashboard_api import tenancy
from dashboard_api.auth import current_user
from dashboard_api.db import get_conn, rows_to_dicts

router = APIRouter(prefix="/overview", tags=["overview"], dependencies=[Depends(current_user)])


def _scope(user: dict) -> tuple[str, list]:
    """Workspace clause for the rollup queries - a no-op until multi-tenancy
    is switched on, then the same isolation the list endpoints enforce."""
    return tenancy.scope_sql(tenancy.org_of(user))


@router.get("/kpis")
def kpis(user: dict = Depends(current_user)):
    from dashboard_api.scoring import org_risk
    sc, sp = _scope(user)
    with get_conn() as conn:
        iocs = conn.execute(f"SELECT COUNT(*) FROM iocs WHERE 1=1 {sc}", sp).fetchone()[0]
        feeds = conn.execute(f"SELECT COUNT(*) FROM feeds WHERE status='active' {sc}", sp).fetchone()[0]
        threats = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity IN ('critical','high') "
            f"AND status NOT IN ('resolved','closed') {sc}", sp
        ).fetchone()[0]
        assets = conn.execute(f"SELECT risk_score, criticality FROM assets WHERE 1=1 {sc}", sp).fetchall()
    # Criticality-weighted org risk - crown jewels move the needle more than endpoints.
    return {"threats": threats, "iocs": iocs, "sources": feeds, "score": org_risk(assets)}


@router.get("/threat-vectors")
def threat_vectors(user: dict = Depends(current_user)):
    from dashboard_api.seed import TACTIC_COLOR
    sc, sp = _scope(user)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT mitre_tactic AS label, COUNT(*) AS n FROM alerts WHERE 1=1 {sc} "
            "GROUP BY mitre_tactic", sp
        ).fetchall()
    total = sum(r["n"] for r in rows) or 1
    vectors = [{"label": r["label"], "pct": round(r["n"] / total * 100),
                "color": TACTIC_COLOR.get(r["label"], "#7A3CFF")} for r in rows]
    vectors.sort(key=lambda v: v["pct"], reverse=True)
    return vectors[:6]


@router.get("/hourly-volume")
def hourly_volume(user: dict = Depends(current_user)):
    """24-bucket alert volume for the last 24h based on alert timestamps."""
    now = datetime.now(timezone.utc)
    buckets = [0] * 24
    sc, sp = _scope(user)
    with get_conn() as conn:
        rows = conn.execute(f"SELECT ts FROM alerts WHERE 1=1 {sc}", sp).fetchall()
    for r in rows:
        try:
            ts = datetime.fromisoformat(r["ts"])
            delta = (now - ts).total_seconds() / 3600
            if 0 <= delta < 24:
                buckets[23 - int(delta)] += 1
        except (ValueError, TypeError):
            continue
    return buckets


@router.get("/mitre-heatmap")
def mitre_heatmap(user: dict = Depends(current_user)):
    """Tactic x 6-time-bucket heatmap of alert counts."""
    now = datetime.now(timezone.utc)
    grid = defaultdict(lambda: [0] * 6)
    sc, sp = _scope(user)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT mitre_tactic, ts FROM alerts WHERE mitre_tactic IS NOT NULL {sc}", sp).fetchall()
    for r in rows:
        try:
            ts = datetime.fromisoformat(r["ts"])
            hrs = (now - ts).total_seconds() / 3600
            bucket = min(5, int(hrs / 28))  # ~168h / 6
            grid[r["mitre_tactic"]][5 - bucket] += 1
        except (ValueError, TypeError):
            continue
    return [{"label": tactic, "vals": vals} for tactic, vals in sorted(grid.items())]


@router.get("/recent-alerts")
def recent_alerts(limit: int = Query(8, le=200), user: dict = Depends(current_user)):
    sc, sp = _scope(user)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT id, title, severity, ts AS time, rule_name AS src FROM alerts WHERE 1=1 {sc} "
            "ORDER BY ts DESC LIMIT ?", sp + [limit]
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/recent-incidents")
def recent_incidents(limit: int = Query(6, le=200), user: dict = Depends(current_user)):
    sc, sp = _scope(user)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, title, severity, status, type AS category, owner AS assigned, updated AS age "
            f"FROM cases WHERE 1=1 {sc} ORDER BY updated DESC LIMIT ?", sp + [limit]
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/top-actors")
def top_actors(limit: int = Query(5, le=100), user: dict = Depends(current_user)):
    sc, sp = _scope(user)
    with get_conn() as conn:
        # Rank by indicators REALLY attributed to each actor in the store (a
        # live LEFT JOIN, so it is accurate between engine ticks too), falling
        # back to sophistication for actors with no observed activity yet.
        rows = conn.execute(
            "SELECT a.name, a.origin, a.sophistication AS score, a.threat_level, "
            "COALESCE(ic.n, 0) AS attacks "
            "FROM threat_actors a "
            "LEFT JOIN (SELECT actor, COUNT(*) AS n FROM iocs "
            "           WHERE actor IS NOT NULL AND actor != '' GROUP BY actor) ic "
            "  ON ic.actor = a.name "
            f"WHERE 1=1 {sc.replace('org_id', 'a.org_id')} "
            "ORDER BY attacks DESC, a.sophistication DESC, a.name LIMIT ?", sp + [limit]
        ).fetchall()
    return rows_to_dicts(rows)


# ISO 3166 alpha-2 → display name, so geo rows from different producers
# (seeded alerts use codes, engine telemetry uses names) merge consistently.
_CC = {"RU": "Russia", "CN": "China", "KP": "North Korea", "IR": "Iran",
       "US": "United States", "BR": "Brazil", "NL": "Netherlands", "RO": "Romania",
       "VN": "Vietnam", "NG": "Nigeria", "IN": "India", "GB": "United Kingdom",
       "DE": "Germany", "UA": "Ukraine", "EG": "Egypt", "AU": "Australia",
       "JP": "Japan", "KR": "South Korea", "SG": "Singapore", "AE": "UAE",
       "FR": "France", "IT": "Italy", "ES": "Spain", "TR": "Turkey", "PK": "Pakistan",
       "ID": "Indonesia", "MX": "Mexico", "CA": "Canada", "PL": "Poland", "BY": "Belarus"}
# Reverse lookup so we can also emit the ISO-2 code (the frontend choropleth
# joins it to country polygons), whether a row stored a code or a display name.
_NAME_TO_CC = {v: k for k, v in _CC.items()}


@router.get("/geo")
def geo_distribution(limit: int = Query(20, le=500), user: dict = Depends(current_user)):
    """Observed attack origins, by country, from the platform's OWN alert
    store (src_country on alerts) - real measurement, not global statistics.
    Includes per-country severity mix and the latest observation time."""
    sc, sp = _scope(user)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT src_country AS country, COUNT(*) AS observed, "
            "SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical, "
            "SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high, "
            "MAX(ts) AS last_seen "
            f"FROM alerts WHERE src_country IS NOT NULL AND src_country != '' {sc} "
            "GROUP BY src_country", sp
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts WHERE src_country IS NOT NULL AND src_country != '' {sc}",
            sp
        ).fetchone()["n"]
    merged: dict[str, dict] = {}
    for r in rows_to_dicts(rows):
        raw = str(r["country"])
        if len(raw) == 2:
            iso2 = raw.upper()
            name = _CC.get(iso2, iso2)
        else:
            name = raw
            iso2 = _NAME_TO_CC.get(name)
        g = merged.setdefault(name, {"country": name, "iso2": iso2, "observed": 0,
                                     "critical": 0, "high": 0, "last_seen": r["last_seen"]})
        if iso2 and not g.get("iso2"):
            g["iso2"] = iso2
        g["observed"] += r["observed"]
        g["critical"] += r["critical"]
        g["high"] += r["high"]
        if r["last_seen"] and r["last_seen"] > (g["last_seen"] or ""):
            g["last_seen"] = r["last_seen"]
    out = sorted(merged.values(), key=lambda x: -x["observed"])[:limit]
    return {"countries": out, "totalGeolocated": total}


@router.get("/live-feed")
def live_feed(limit: int = Query(10, le=200), user: dict = Depends(current_user)):
    """Latest IOCs presented as a live threat feed."""
    sc, sp = _scope(user)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, type, severity, value AS ip, threat_type AS detail, source AS region "
            f"FROM iocs WHERE 1=1 {sc} ORDER BY last_seen DESC LIMIT ?", sp + [limit]
        ).fetchall()
    return rows_to_dicts(rows)
