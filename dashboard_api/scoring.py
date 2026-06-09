"""Risk scoring — a transparent, CVSS-inspired model for asset and org risk.

Asset risk (0–100) blends four bounded signals, each on its own 0–100 axis:

  • Vulnerability burden   — CVE counts weighted by severity
  • Exposure               — internet-facing + risky service ports
  • Patch hygiene          — risk rises with days-since-patch (saturating at 180d)
  • Active threat pressure — unresolved alerts currently firing on the asset

The four axes are combined with weights that sum to 1.0, then lifted by a
business-criticality factor so a crown-jewel asset always outranks a throwaway
endpoint with the same technical posture. The model is intentionally legible:
every term is bounded, so a score of 100 means "maxed on every axis".
"""
from __future__ import annotations

# Severity → points per CVE. Roughly tracks CVSS bands (a critical is ~20x a low).
CVE_WEIGHTS = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5}

# Business-impact multiplier per asset criticality (0–1).
CRITICALITY_MULTIPLIER = {"critical": 1.0, "high": 0.8, "medium": 0.55, "low": 0.35}

# Ports that materially raise exposure when reachable (RDP, telnet, ftp, SMB, DBs).
RISKY_PORTS = {21, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017}

# Axis weights (must sum to 1.0).
_W_VULN, _W_EXPOSURE, _W_PATCH, _W_ALERTS = 0.40, 0.25, 0.20, 0.15

_PATCH_FULL_DECAY_DAYS = 180   # patch risk saturates at/after this age
_ALERTS_SATURATE = 8           # this many open alerts pins the alert axis at 100


def vuln_burden(cves: dict) -> float:
    """0–100 from severity-weighted CVE counts (saturating)."""
    raw = sum(CVE_WEIGHTS.get(sev, 0.0) * (n or 0) for sev, n in cves.items())
    return min(100.0, raw)


def exposure_score(open_ports, tags) -> float:
    """0–100 from internet exposure and the count of risky open ports."""
    score = 50.0 if "internet-facing" in (tags or []) else 0.0
    risky = sum(1 for p in (open_ports or []) if p in RISKY_PORTS)
    score += min(50.0, risky * 15.0)
    return min(100.0, score)


def asset_risk(*, cves: dict, criticality: str, patch_age: int,
               open_alerts: int, open_ports=None, tags=None) -> int:
    """Composite 0–100 risk for a single asset."""
    vuln = vuln_burden(cves)
    exposure = exposure_score(open_ports, tags)
    patch = min(100.0, (patch_age or 0) / _PATCH_FULL_DECAY_DAYS * 100.0)
    alerts = min(100.0, (open_alerts or 0) / _ALERTS_SATURATE * 100.0)

    base = vuln * _W_VULN + exposure * _W_EXPOSURE + patch * _W_PATCH + alerts * _W_ALERTS
    # Criticality lifts the score by a factor in [0.6, 1.0] so it never zeroes out
    # a technically-risky low-value host, but crown jewels reach the full range.
    mult = CRITICALITY_MULTIPLIER.get(criticality, 0.5)
    scaled = base * (0.6 + 0.4 * mult)
    return max(0, min(100, round(scaled)))


def risk_band(score: int) -> str:
    """Map a 0–100 score to the asset status band used across the UI."""
    if score >= 75:
        return "critical"
    if score >= 45:
        return "at-risk"
    return "clean"


def risk_breakdown(*, cves: dict, criticality: str, patch_age: int,
                   open_alerts: int, open_ports=None, tags=None) -> dict:
    """Explain a risk score: each axis's 0–100 value, its weight, and the points
    it contributes to the final (criticality-scaled) score. Lets the UI render a
    transparent "why is this risky?" panel.
    """
    axes = {
        "vulnerability": (vuln_burden(cves), _W_VULN),
        "exposure": (exposure_score(open_ports, tags), _W_EXPOSURE),
        "patch": (min(100.0, (patch_age or 0) / _PATCH_FULL_DECAY_DAYS * 100.0), _W_PATCH),
        "alerts": (min(100.0, (open_alerts or 0) / _ALERTS_SATURATE * 100.0), _W_ALERTS),
    }
    mult = CRITICALITY_MULTIPLIER.get(criticality, 0.5)
    scale = 0.6 + 0.4 * mult
    components = [
        {
            "axis": name,
            "value": round(value, 1),                       # 0–100 on its own axis
            "weight": weight,                                # share of the base score
            "contribution": round(value * weight * scale, 1),  # points added to the total
        }
        for name, (value, weight) in axes.items()
    ]
    components.sort(key=lambda c: c["contribution"], reverse=True)
    score = max(0, min(100, round(sum(c["contribution"] for c in components))))
    return {
        "score": score,
        "band": risk_band(score),
        "criticalityMultiplier": round(scale, 3),
        "components": components,
    }


def org_risk(assets) -> int:
    """Criticality-weighted mean asset risk — crown jewels dominate the org score.

    ``assets`` is any iterable of mappings with ``risk_score`` and ``criticality``.
    """
    num = den = 0.0
    for a in assets:
        w = CRITICALITY_MULTIPLIER.get(a["criticality"], 0.5)
        num += (a["risk_score"] or 0) * w
        den += w
    return round(num / den) if den else 0


def recompute_asset_risk(conn) -> int:
    """Recompute every asset's alert pressure, risk score and status band from
    the live alerts table, persisting the results. Returns the count updated.

    Alert pressure is the number of unresolved alerts whose ``hostname`` matches
    the asset name — so triaging alerts visibly lowers an asset's risk.
    """
    import json

    open_by_host: dict[str, int] = {}
    for row in conn.execute(
        "SELECT hostname, COUNT(*) AS n FROM alerts "
        "WHERE status NOT IN ('resolved','closed') AND hostname IS NOT NULL "
        "GROUP BY hostname"
    ).fetchall():
        open_by_host[row["hostname"]] = row["n"]

    assets = conn.execute(
        "SELECT id, name, criticality, patch_age, cves, open_ports, tags FROM assets"
    ).fetchall()

    updated = 0
    for a in assets:
        cves = json.loads(a["cves"]) if isinstance(a["cves"], str) else (a["cves"] or {})
        ports = json.loads(a["open_ports"]) if isinstance(a["open_ports"], str) else (a["open_ports"] or [])
        tags = json.loads(a["tags"]) if isinstance(a["tags"], str) else (a["tags"] or [])
        open_alerts = open_by_host.get(a["name"], 0)
        score = asset_risk(
            cves=cves, criticality=a["criticality"], patch_age=a["patch_age"],
            open_alerts=open_alerts, open_ports=ports, tags=tags,
        )
        conn.execute(
            "UPDATE assets SET risk_score=?, status=?, alerts=? WHERE id=?",
            (score, risk_band(score), open_alerts, a["id"]),
        )
        updated += 1
    return updated
