"""ML detector: unsupervised outlier ranking that must NOT flag benign logs by
construction, and must map the MITRE technique from the real signal (not a
hardcoded T1595). Covers audit findings C1 + C2.
"""
from datetime import datetime, timedelta

import pytest

from log_api.detectors.ml_detector import ML_AVAILABLE, run_ml_detector
from log_api.models import ParsedLogEntry

pytestmark = pytest.mark.skipif(not ML_AVAILABLE, reason="scikit-learn not installed")
_BASE = datetime(2026, 6, 1, 12, 0, 0)


def _benign(n_sources=30, per=10):
    out = []
    for ip in range(n_sources):
        for j in range(per):
            out.append(ParsedLogEntry(raw="ok", timestamp=_BASE + timedelta(seconds=j),
                                      source_ip=f"10.0.0.{ip}", http_status=200,
                                      http_method="GET", http_path="/index"))
    return out


def test_clean_log_yields_no_findings():
    # A uniform, benign log must NOT produce anomalies just because IsolationForest
    # is asked to find some (the old fixed-contamination bug, C1).
    assert run_ml_detector(_benign()) == []


def test_bruteforce_maps_to_t1110_not_hardcoded_t1595():
    logs = _benign()
    for j in range(40):  # one source hammering auth → genuine brute force
        logs.append(ParsedLogEntry(raw="Failed password for invalid user",
                                   timestamp=_BASE + timedelta(seconds=j), source_ip="10.0.0.99",
                                   process="sshd", message="failed password invalid"))
    findings = run_ml_detector(logs)
    assert findings, "a real brute-force source should be surfaced"
    hit = next((f for f in findings if f.source_ip == "10.0.0.99"), None)
    assert hit is not None
    assert hit.mitre_tags[0].technique_id == "T1110"          # derived from the signal
    assert hit.mitre_tags[0].technique_id != "T1595"          # not the old hardcoded tag
    assert hit.finding_type == "behavioural_outlier"
