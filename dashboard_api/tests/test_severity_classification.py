"""Severity must describe what an indicator would DO, not restate confidence.

It used to be `critical if conf>=85 else high if conf>=70 else ...`, which meant
the column carried no information the confidence column did not already have.
The damage was measurable on a real 315k store: `malware-distribution` held
50,181 rows at "medium" and 50,024 at "high" - one activity, two severities,
separated by nothing but the number beside them - and 81% of every indicator in
the store read "high".

These pin the properties that make the field worth reading again.
"""
import pytest

from dashboard_api.connectors import UNCLASSIFIED_SEVERITY, severity_for


def test_severity_does_not_move_with_confidence():
    """The whole point. severity_for cannot even see confidence, so this is a
    structural guarantee rather than a behavioural one - assert it anyway, so
    that reintroducing the coupling fails here."""
    import inspect
    params = inspect.signature(severity_for).parameters
    assert "confidence" not in params, "severity must not be derived from confidence"


def test_same_activity_always_gets_the_same_severity():
    """The concrete defect: 100k rows of one activity split across two
    severities because different feeds asserted different confidences."""
    variants = ["malware-distribution", "malware_distribution", "Malware Distribution",
                "MALWARE-DISTRIBUTION"]
    assert len({severity_for(v) for v in variants}) == 1


@pytest.mark.parametrize("activity,expected", [
    ("ransomware", "critical"),
    ("c2", "critical"),
    ("command-and-control", "critical"),
    ("Cobalt Strike", "critical"),
    ("Exfil", "critical"),
    ("phishing", "high"),
    ("malware-distribution", "high"),
    ("CVE-2024-1234", "high"),
    ("web-attack", "medium"),
    ("scam", "medium"),
    ("Scanning", "medium"),
    ("tor-exit-node", "medium"),
    ("suspicious", "low"),
])
def test_activity_classes(activity, expected):
    assert severity_for(activity) == expected


def test_short_acronyms_must_be_whole_tokens():
    """A plain substring test classified "attack-source" and "brute-force-source"
    as exploitation, because both contain the letters of "rce". Scanning and
    brute-forcing are noise-floor activity, not an active intrusion."""
    assert severity_for("attack-source") == "medium"
    assert severity_for("brute-force-source") == "medium"
    assert severity_for("password-spray") == "medium"
    # ...while the acronym itself still classifies when it IS the activity.
    assert severity_for("rce") == "high"
    assert severity_for("apt") == "critical"


def test_unstated_activity_is_not_guessed():
    """A bare blocklist row says "this is bad" and nothing more. Inventing a
    severity for it is what produced a store that was 81% high."""
    for unstated in ("", None, "malicious-activity", "imported-indicator"):
        assert severity_for(unstated) == UNCLASSIFIED_SEVERITY


def test_tags_are_read_when_the_threat_type_says_nothing():
    """Feeds routinely put the useful classification in tags and leave
    threat_type generic."""
    assert severity_for("malicious-activity", ["ransomware", "tlp:white"]) == "critical"
    assert severity_for("malicious-activity", ["scanner"]) == "medium"


def test_most_specific_activity_wins():
    """A ransomware C2 is ransomware infrastructure; both are critical here, but
    the ordering has to hold for the cases where the classes differ."""
    assert severity_for("phishing-c2") == "critical"      # C2 outranks delivery
    assert severity_for("malware-scan") == "high"         # delivery outranks noise


def test_a_feeds_own_severity_is_not_overridden(monkeypatch):
    """NVD publishes a CVSS band. That is a real external judgement and must
    survive import untouched - classification is only for feeds that state an
    activity but no severity."""
    from dashboard_api import connectors
    normalised = connectors._apply_field_map(
        {"v": "1.2.3.4", "sev": "critical", "tt": "scanning"},
        {"value": "v", "severity": "sev", "threat_type": "tt"})
    assert normalised["severity"] == "critical"
