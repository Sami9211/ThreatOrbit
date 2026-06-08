"""Overview dashboard: top-level KPIs, charts, and recent-activity rollups.

Everything here is derived from the live tables so the overview stays consistent
with the detail pages (the same alerts that drive SIEM also drive these counts).
"""
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from dashboard_api.auth import current_user
from dashboard_api.db import get_conn, rows_to_dicts

router = APIRouter(prefix="/overview", tags=["overview"], dependencies=[Depends(current_user)])


@router.get("/kpis")
def kpis():
    with get_conn() as conn:
        iocs = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        feeds = conn.execute("SELECT COUNT(*) FROM feeds WHERE status='active'").fetchone()[0]
        threats = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity IN ('critical','high') "
            "AND status NOT IN ('resolved','closed')"
        ).fetchone()[0]
        risk = conn.execute("SELECT AVG(risk_score) FROM assets").fetchone()[0] or 0
    return {"threats": threats, "iocs": iocs, "sources": feeds, "score": round(risk)}


@router.get("/threat-vectors")
def threat_vectors():
    from dashboard_api.seed import TACTIC_COLOR
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT mitre_tactic AS label, COUNT(*) AS n FROM alerts GROUP BY mitre_tactic"
        ).fetchall()
    total = sum(r["n"] for r in rows) or 1
    vectors = [{"label": r["label"], "pct": round(r["n"] / total * 100),
                "color": TACTIC_COLOR.get(r["label"], "#7A3CFF")} for r in rows]
    vectors.sort(key=lambda v: v["pct"], reverse=True)
    return vectors[:6]


@router.get("/hourly-volume")
def hourly_volume():
    """24-bucket alert volume for the last 24h based on alert timestamps."""
    now = datetime.now(timezone.utc)
    buckets = [0] * 24
    with get_conn() as conn:
        rows = conn.execute("SELECT ts FROM alerts").fetchall()
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
def mitre_heatmap():
    """Tactic x 6-time-bucket heatmap of alert counts."""
    now = datetime.now(timezone.utc)
    grid = defaultdict(lambda: [0] * 6)
    with get_conn() as conn:
        rows = conn.execute("SELECT mitre_tactic, ts FROM alerts WHERE mitre_tactic IS NOT NULL").fetchall()
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
def recent_alerts(limit: int = 8):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, title, severity, ts AS time, rule_name AS src FROM alerts "
            "ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/recent-incidents")
def recent_incidents(limit: int = 6):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, title, severity, status, type AS category, owner AS assigned, updated AS age "
            "FROM cases ORDER BY updated DESC LIMIT ?", (limit,)
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/top-actors")
def top_actors(limit: int = 5):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT name, origin, sophistication AS score, ioc_count AS attacks, threat_level "
            "FROM threat_actors ORDER BY ioc_count DESC LIMIT ?", (limit,)
        ).fetchall()
    return rows_to_dicts(rows)


@router.get("/live-feed")
def live_feed(limit: int = 10):
    """Latest IOCs presented as a live threat feed."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, type, severity, value AS ip, threat_type AS detail, source AS region "
            "FROM iocs ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
    return rows_to_dicts(rows)
