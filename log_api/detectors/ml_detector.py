"""Unsupervised outlier RANKING (Isolation Forest) for analyst triage.

This is deliberately *not* a ground-truth detector: there is no trained baseline
of "normal", so a flagged source means "statistically unusual within this file",
not "confirmed malicious". To keep it from labelling ~N% of every (even benign)
log as anomalous, a statistical outlier is only surfaced when a CONCRETE signal
corroborates it (real auth failures, a genuine rate/scan spike, a high error
rate, off-hours bulk transfer), and the MITRE technique is derived from that
signal rather than hardcoded. Treat the output as a ranked triage list.
"""
from collections import defaultdict
from typing import List, Dict, Any
from log_api.models import ParsedLogEntry, AnomalyFinding, MitreTag, Severity
from log_api.config import (
    ML_N_ESTIMATORS,
    BUSINESS_HOURS_START, BUSINESS_HOURS_END,
    SEVERITY_CRITICAL_THRESHOLD, SEVERITY_HIGH_THRESHOLD, SEVERITY_MEDIUM_THRESHOLD, ENABLE_ML_DETECTOR
)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


AUTH_FAILURE_KEYWORDS = {"failed", "failure", "invalid", "denied"}
AUTH_PROCESSES = {"sshd", "su", "sudo", "login", "passwd", "pam"}


def run_ml_detector(entries: List[ParsedLogEntry]) -> List[AnomalyFinding]:
    if not ENABLE_ML_DETECTOR:
        return []

    if not ML_AVAILABLE:
        return [AnomalyFinding(
            detector="ML Detector",
            finding_type="ml_unavailable",
            description="scikit-learn not installed. Run: pip install scikit-learn numpy",
            severity_score=0,
            severity=Severity.INFO,
            count=0,
        )]

    features, ip_list, ip_entries = _build_feature_matrix(entries)
    if len(features) < 5:
        return []

    X = np.array(features, dtype=float)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # `contamination='auto'` instead of a fixed fraction: a fixed fraction would
    # force ~N% of sources to be labelled "anomalous" even on a perfectly clean
    # log. Even with 'auto', an isolation-forest outlier is only *statistical*, so
    # we additionally require a CONCRETE corroborating signal (real auth failures,
    # a true rate/scan spike, etc.) before surfacing it - so a benign log yields
    # nothing, and the MITRE technique is derived from that signal rather than
    # hardcoded. This is unsupervised outlier RANKING for triage, not a detection
    # verdict (see the module docstring / report wording).
    model = IsolationForest(
        n_estimators=ML_N_ESTIMATORS,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    predictions = model.fit_predict(X_scaled)
    anomaly_scores = model.score_samples(X_scaled)

    min_score = anomaly_scores.min()
    max_score = anomaly_scores.max()
    score_range = max_score - min_score if max_score != min_score else 1.0

    findings: List[AnomalyFinding] = []
    for idx, (pred, raw_score) in enumerate(zip(predictions, anomaly_scores)):
        if pred != -1:
            continue

        feat = features[idx]
        tag, reason = _classify(feat)
        if tag is None:
            continue   # statistical outlier with no concrete signal → not surfaced

        ip = ip_list[idx]
        ev = ip_entries[ip]
        normalised = int(((raw_score - min_score) / score_range) * 100)
        sev_score = max(25, 100 - normalised)

        findings.append(AnomalyFinding(
            detector="ML Detector (Isolation Forest)",
            finding_type="behavioural_outlier",
            description=_build_description(ip, feat, sev_score, reason),
            severity_score=sev_score,
            severity=_score_to_severity(sev_score),
            source_ip=ip if ip != "unknown" else None,
            timestamp=ev[0].timestamp if ev else None,
            evidence=[e.raw[:200] for e in ev[:5]],
            mitre_tags=[tag],
            count=int(feat[0]),
            extra=_feature_dict(feat),
        ))

    # Highest-ranked (most unusual + corroborated) first — this is a triage
    # ranking, not a ground-truth detection list.
    findings.sort(key=lambda f: f.severity_score, reverse=True)
    return findings


# Feature index map (see _build_feature_matrix): 0 total, 1 unique_paths,
# 2 error_rate_pct, 3 avg_bytes, 4 unique_agents, 5 rpm, 6 auth_failures,
# 7 off_hours_pct, 8 post_ratio_pct.
def _mitre(tech_id: str, name: str, tactic: str) -> MitreTag:
    return MitreTag(technique_id=tech_id, technique_name=name, tactic=tactic,
                    url=f"https://attack.mitre.org/techniques/{tech_id}/")


def _classify(feat: list):
    """Map a flagged source's dominant concrete signal to a MITRE technique, or
    return (None, None) when nothing concrete corroborates the outlier (so a
    purely statistical wobble on benign data is not reported as a finding)."""
    auth_fail, rpm, paths = feat[6], feat[5], feat[1]
    err_pct, off_pct, avg_bytes = feat[2], feat[7], feat[3]
    if auth_fail >= 5:
        return _mitre("T1110", "Brute Force", "Credential Access"), f"{int(auth_fail)} authentication failures"
    if rpm >= 120 or paths >= 100:
        return _mitre("T1595", "Active Scanning", "Reconnaissance"), f"{int(rpm)} req/min over {int(paths)} paths"
    if err_pct >= 40:
        return _mitre("T1190", "Exploit Public-Facing Application", "Initial Access"), f"{err_pct:.0f}% error rate"
    if off_pct >= 50 and avg_bytes >= 1_000_000:
        return _mitre("T1041", "Exfiltration Over C2 Channel", "Exfiltration"), "off-hours high-volume transfer"
    return None, None


def _build_feature_matrix(entries: List[ParsedLogEntry]):
    stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "total": 0, "errors": 0, "bytes": [], "paths": set(), "agents": set(),
        "timestamps": [], "auth_fail": 0, "post": 0, "off_hours": 0,
    })
    ip_entries: Dict[str, List[ParsedLogEntry]] = defaultdict(list)

    for e in entries:
        key = e.source_ip or "unknown"
        s = stats[key]
        ip_entries[key].append(e)

        s["total"] += 1
        if e.http_status and e.http_status >= 400:
            s["errors"] += 1
        if e.bytes_sent:
            s["bytes"].append(e.bytes_sent)
        if e.http_path:
            s["paths"].add(e.http_path)
        if e.user_agent:
            s["agents"].add(e.user_agent)
        if e.timestamp:
            s["timestamps"].append(e.timestamp)
            hour = e.timestamp.hour
            if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
                s["off_hours"] += 1
        if e.http_method == "POST":
            s["post"] += 1

        is_auth_proc = (e.process or "").lower() in AUTH_PROCESSES
        is_fail_msg = any(w in (e.message or "").lower() for w in AUTH_FAILURE_KEYWORDS)
        if (is_auth_proc and is_fail_msg) or e.event_id == "4625":
            s["auth_fail"] += 1

    features, ip_list = [], []
    for ip, s in stats.items():
        total = s["total"]
        if total < 3:
            continue

        ts_list = sorted(s["timestamps"])
        if len(ts_list) >= 2:
            duration_minutes = max((ts_list[-1] - ts_list[0]).total_seconds() / 60.0, 0.01)
            rpm = total / duration_minutes
        else:
            rpm = 0.0

        feat = [
            total,
            len(s["paths"]),
            (s["errors"] / total * 100) if total > 0 else 0,
            (sum(s["bytes"]) / len(s["bytes"])) if s["bytes"] else 0,
            len(s["agents"]),
            rpm,
            s["auth_fail"],
            (s["off_hours"] / total * 100) if total > 0 else 0,
            (s["post"] / total * 100) if total > 0 else 0,
        ]
        features.append(feat)
        ip_list.append(ip)

    return features, ip_list, ip_entries


def _build_description(ip: str, feat: list, score: int, reason: str = "") -> str:
    parts = [f"Unusual activity ranked from source {ip} (outlier score: {score}/100)."]
    if reason:
        parts.append(f"Corroborating signal: {reason}.")
    if feat[1] > 50:
        parts.append(f"Accessed {int(feat[1])} unique paths.")
    if feat[2] > 30:
        parts.append(f"High error rate: {feat[2]:.0f}%.")
    if feat[5] > 60:
        parts.append(f"High request rate: {feat[5]:.0f} RPM.")
    if feat[6] > 3:
        parts.append(f"{int(feat[6])} authentication failures.")
    parts.append("(Unsupervised outlier ranking for triage — not a confirmed detection.)")
    return " ".join(parts)


def _feature_dict(feat: list) -> dict:
    keys = ["total_requests", "unique_paths", "error_rate_pct", "avg_bytes",
            "unique_user_agents", "rpm", "auth_failures", "off_hours_pct", "post_ratio_pct"]
    return {k: round(v, 2) for k, v in zip(keys, feat)}


def _score_to_severity(score: int) -> Severity:
    if score >= SEVERITY_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= SEVERITY_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= SEVERITY_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW
