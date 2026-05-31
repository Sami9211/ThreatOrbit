from collections import defaultdict
from typing import List, Dict, Tuple
from log_api.models import AnomalyFinding, Severity


def process_findings(raw_findings: List[AnomalyFinding]) -> List[AnomalyFinding]:
    if not raw_findings:
        return []

    deduped = _deduplicate(raw_findings)
    correlated = _correlate(deduped)
    correlated.sort(key=lambda f: f.severity_score, reverse=True)
    return correlated


def _deduplicate(findings: List[AnomalyFinding]) -> List[AnomalyFinding]:
    seen: Dict[Tuple, AnomalyFinding] = {}

    for f in findings:
        key = (f.finding_type, f.source_ip or "", f.username or "")
        if key not in seen:
            seen[key] = f
        else:
            existing = seen[key]
            if f.severity_score > existing.severity_score:
                seen[key] = f
                seen[key].evidence = list(dict.fromkeys(f.evidence + existing.evidence))[:10]
            else:
                existing.evidence = list(dict.fromkeys(existing.evidence + f.evidence))[:10]
            seen[key].count = max(seen[key].count, f.count)

    return list(seen.values())


def _correlate(findings: List[AnomalyFinding]) -> List[AnomalyFinding]:
    detector_count_by_ip: Dict[str, set] = defaultdict(set)

    for f in findings:
        if f.source_ip:
            detector_count_by_ip[f.source_ip].add(f.detector)

    boosted = []
    for f in findings:
        if not f.source_ip:
            boosted.append(f)
            continue

        num_detectors = len(detector_count_by_ip.get(f.source_ip, set()))
        boost = 0
        if num_detectors >= 2:
            boost = 10
        if num_detectors >= 3:
            boost = 20
        if num_detectors >= 4:
            boost = 30

        if boost:
            new_score = min(100, f.severity_score + boost)
            f = f.model_copy(update={
                "severity_score": new_score,
                "severity": _score_to_severity(new_score),
                "description": f.description + f" [Corroborated by {num_detectors} detectors, score boosted]",
            })

        boosted.append(f)

    return boosted


def summarise(findings: List[AnomalyFinding]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def top_source_ips(findings: List[AnomalyFinding], n: int = 10) -> List[Dict]:
    ip_scores: Dict[str, Dict] = defaultdict(lambda: {"count": 0, "max_score": 0, "finding_types": set()})
    for f in findings:
        if not f.source_ip:
            continue
        ip_scores[f.source_ip]["count"] += 1
        ip_scores[f.source_ip]["max_score"] = max(ip_scores[f.source_ip]["max_score"], f.severity_score)
        ip_scores[f.source_ip]["finding_types"].add(f.finding_type)

    result = [
        {
            "ip": ip,
            "finding_count": d["count"],
            "max_score": d["max_score"],
            "finding_types": list(d["finding_types"]),
        }
        for ip, d in ip_scores.items()
    ]
    result.sort(key=lambda x: x["max_score"], reverse=True)
    return result[:n]


def _score_to_severity(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 25:
        return Severity.MEDIUM
    return Severity.LOW
