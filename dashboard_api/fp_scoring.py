"""Evidence-based false-positive likelihood scoring for SIEM alerts and CTI
indicators.

Produces an explainable, weighted score in [0,100] plus the list of signals
that produced it -- never a black-box classification, and never an automatic
action on its own. Every signal is derived from data already collected
elsewhere in the app (rule fp-rate history, asset criticality, suppression
rules, alert correlation, IOC lifecycle/enrichment); this module adds no new
data source, only a transparent way to weigh what's already there.

Scoring starts at a neutral midpoint (50) and each applicable signal shifts it
by a signed, capped weight -- so no single weak signal can dominate several
strong ones. Bands: >=70 "likely-fp", <=30 "likely-real", else "uncertain".
A wrong likely-fp call that leads an analyst to skip a real incident is the
worst failure mode this module can cause, so weights are deliberately
conservative and every result carries its full evidence trail for the
analyst to judge. See plan.md for the design rationale and testing
discipline this module is held to.
"""
import ipaddress
from datetime import datetime, timedelta

from dashboard_api import tenancy

_NEUTRAL = 50
_LIKELY_FP_AT = 70
_LIKELY_REAL_AT = 30

_CORRELATION_WINDOW_MINUTES = 15

# Well-known cloud/CDN ranges (representative subset, not exhaustive). A hit
# here doesn't clear an IP -- attackers use cloud infra too -- it's only a
# mild signal, meaningful in combination with other benign-leaning evidence.
_CLOUD_NETS = [ipaddress.ip_network(c) for c in (
    "3.0.0.0/8", "13.32.0.0/15", "18.130.0.0/16", "52.0.0.0/8",   # AWS (subset)
    "34.64.0.0/10", "35.184.0.0/13",                               # GCP (subset)
    "20.0.0.0/8", "40.64.0.0/10",                                  # Azure (subset)
    "104.16.0.0/13", "172.64.0.0/13",                              # Cloudflare
)]


def _clamp(score: float) -> int:
    return max(0, min(100, round(score)))


def _band(score: int) -> str:
    if score >= _LIKELY_FP_AT:
        return "likely-fp"
    if score <= _LIKELY_REAL_AT:
        return "likely-real"
    return "uncertain"


def _assess(evidence: list) -> dict:
    score = _clamp(_NEUTRAL + sum(e["weight"] for e in evidence))
    return {"score": score, "band": _band(score), "evidence": evidence}


def _is_cloud_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in _CLOUD_NETS)


def score_alert(conn, alert: dict, org_id: str = "org-default") -> dict:
    """Evidence-weighted false-positive likelihood for one SIEM alert.

    High score = likely noise; low score = likely real -- treat as an
    incident until an analyst says otherwise. Advisory only."""
    evidence = []
    sc, sp = tenancy.scope_sql(org_id)
    rule_id, rule_name = alert.get("rule_id"), alert.get("rule_name")
    pivots = [v for v in (alert.get("hostname"), alert.get("src_ip"), alert.get("dest_ip")) if v]

    # 1. The firing rule's own historical FP rate (fed by analysts marking
    #    alerts false-positive -- see routers/siem.py::update_alert).
    if rule_id or rule_name:
        row = conn.execute(
            "SELECT fp_rate FROM detection_rules WHERE (id=? OR name=?)",
            (rule_id, rule_name)).fetchone()
        if row and row["fp_rate"]:
            w = min(20, round(row["fp_rate"] / 5))
            if w:
                evidence.append({"signal": "rule_fp_history", "weight": w,
                                  "detail": f"Rule has a {row['fp_rate']:.0f}% historical FP rate"})

    # 2. Asset criticality -- alerts.host_criticality is never populated at
    #    insert time (see detections.py::_insert_alert), so join live
    #    against `assets` by hostname/ip instead of trusting that column.
    if pivots:
        placeholders = ",".join("?" for _ in pivots)
        row = conn.execute(
            f"SELECT criticality FROM assets WHERE value IN ({placeholders}) {sc} "
            "ORDER BY CASE criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END LIMIT 1",
            pivots + sp).fetchone()
        if row:
            if row["criticality"] in ("critical", "high"):
                evidence.append({"signal": "asset_criticality", "weight": -15,
                                  "detail": f"Involves a {row['criticality']}-criticality asset"})
            elif row["criticality"] == "low":
                evidence.append({"signal": "asset_criticality", "weight": 10,
                                  "detail": "Involves only a low-criticality asset"})

    # 3. Standing suppression rules against this rule/pivot are an operator
    #    signal that this traffic pattern is already known-noisy.
    if pivots and rule_id:
        placeholders = ",".join("?" for _ in pivots)
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM suppressions "
            f"WHERE (rule_id=? OR rule_id='*') AND value IN ({placeholders}) {sc}",
            [rule_id] + pivots + sp).fetchone()
        if row and row["n"]:
            w = min(10, row["n"] * 3)
            evidence.append({"signal": "suppression_proximity", "weight": w,
                              "detail": f"{row['n']} suppression rule(s) already cover this source"})

    # 4. Correlation: is this alert part of a cluster of other high/critical
    #    alerts sharing a pivot in a tight time window, or isolated? Mirrors
    #    engine.py::_maybe_escalate_case's grouping logic, read-only (doesn't
    #    re-trigger escalation), without needing to parse cases.entities.
    # corr_count stays None (not checked) unless the alert actually has a
    # pivot and a parseable ts -- an alert with nothing to correlate on isn't
    # "isolated" evidence, it's simply uncheckable, and must not be scored
    # as if it were.
    corr_count, ts = None, alert.get("ts")
    if ts:
        try:
            center = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            center = None
        if center:
            lo = (center - timedelta(minutes=_CORRELATION_WINDOW_MINUTES)).isoformat()
            hi = (center + timedelta(minutes=_CORRELATION_WINDOW_MINUTES)).isoformat()
            clauses, params = [], []
            for col in ("src_ip", "username", "hostname"):
                v = alert.get(col)
                if v:
                    clauses.append(f"{col}=?")
                    params.append(v)
            if clauses:
                # Alerts already confirmed false-positive don't corroborate a
                # real incident -- excluding them keeps a cluster of
                # already-dismissed noise from masquerading as correlation.
                row = conn.execute(
                    f"SELECT COUNT(*) AS n FROM alerts "
                    f"WHERE id != ? AND severity IN ('critical','high') "
                    f"AND disposition != 'false-positive' "
                    f"AND ts BETWEEN ? AND ? AND ({' OR '.join(clauses)}) {sc}",
                    [alert.get("id", "")] + [lo, hi] + params + sp).fetchone()
                corr_count = row["n"] if row else 0
    if corr_count is not None:
        if corr_count >= 2:
            evidence.append({"signal": "correlated_activity", "weight": -20,
                              "detail": f"{corr_count} other high/critical alerts share a pivot nearby in time"})
        elif corr_count == 0:
            evidence.append({"signal": "isolated_alert", "weight": 8,
                              "detail": "No other high/critical alerts nearby in time or pivot"})

    # 5. Direct IOC cross-reference on the alert's own IPs.
    ips = [v for v in (alert.get("src_ip"), alert.get("dest_ip")) if v]
    if ips:
        placeholders = ",".join("?" for _ in ips)
        rows = conn.execute(
            f"SELECT status, severity FROM iocs WHERE type='ip' AND value IN ({placeholders}) {sc}",
            ips + sp).fetchall()
        if any(r["status"] == "known-good" for r in rows):
            evidence.append({"signal": "known_good_ioc", "weight": 25,
                              "detail": "Source/destination IP is an explicitly known-good indicator"})
        elif any(r["status"] == "active" and r["severity"] in ("critical", "high") for r in rows):
            evidence.append({"signal": "malicious_ioc_match", "weight": -25,
                              "detail": "Source/destination IP matches an active high-severity threat indicator"})

    # 6. Same rule + same pivot previously marked false-positive by an analyst.
    if rule_id and pivots:
        placeholders = ",".join("?" for _ in pivots)
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts WHERE rule_id=? AND disposition='false-positive' "
            f"AND (hostname IN ({placeholders}) OR src_ip IN ({placeholders}) OR dest_ip IN ({placeholders})) {sc}",
            [rule_id] + pivots + pivots + pivots + sp).fetchone()
        if row and row["n"]:
            w = min(20, row["n"] * 8)
            evidence.append({"signal": "entity_fp_history", "weight": w,
                              "detail": f"Same rule already marked false-positive {row['n']} time(s) for this source"})

    return _assess(evidence)


def score_ioc(conn, ioc: dict, org_id: str = "org-default") -> dict:
    """Evidence-weighted false-positive likelihood for one CTI indicator."""
    evidence = []
    sc, sp = tenancy.scope_sql(org_id)
    value, ioc_type = ioc.get("value"), ioc.get("type")

    # 1. Enrichment provider verdicts (cached lookups, see enrichment.py).
    #    ioc_enrichments has no org_id column -- it's keyed purely by the
    #    indicator value, which is org-agnostic (a malicious IP is malicious
    #    regardless of which workspace is looking at it).
    if value:
        rows = conn.execute(
            "SELECT provider, verdict FROM ioc_enrichments WHERE ioc_value=? ORDER BY ts DESC",
            (value,)).fetchall()
        latest_by_provider = {}
        for r in rows:
            latest_by_provider.setdefault(r["provider"], r["verdict"])
        malicious = sum(1 for v in latest_by_provider.values() if v == "malicious")
        if malicious >= 2:
            evidence.append({"signal": "multi_source_malicious", "weight": -25,
                              "detail": f"{malicious} enrichment providers flag this as malicious"})
        elif malicious == 1:
            evidence.append({"signal": "single_source_malicious", "weight": -10,
                              "detail": "One enrichment provider flags this as malicious"})
        elif latest_by_provider:
            evidence.append({"signal": "enrichment_benign", "weight": 20,
                              "detail": "No enrichment provider flags this as malicious"})

    # 2. Cloud/CDN-range IP -- mild FP-leaning signal only in combination.
    if ioc_type == "ip" and value and _is_cloud_ip(value):
        evidence.append({"signal": "cloud_cdn_range", "weight": 15,
                          "detail": "IP falls within a known cloud/CDN provider range"})

    # 3. Sighting/impact mismatch: repeatedly "sighted" but never actually
    #    produced a SIEM alert here -- suggests the indicator is stale or
    #    noisy rather than an active threat against this environment. Only
    #    meaningful for IP indicators -- alerts has no domain/hash column to
    #    cross-reference, so other types can't be checked either way.
    sightings, severity = ioc.get("sightings") or 0, ioc.get("severity")
    if ioc_type == "ip" and value and sightings >= 3 and severity in ("critical", "high"):
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts WHERE (src_ip=? OR dest_ip=?) {sc}",
            [value, value] + sp).fetchone()
        if row and row["n"] == 0:
            evidence.append({"signal": "no_alert_correlation", "weight": 15,
                              "detail": f"Sighted {sightings} times but never matched a SIEM alert here"})

    return _assess(evidence)
