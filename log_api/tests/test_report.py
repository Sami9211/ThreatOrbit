"""HTML report escaping: every interpolated value - including the MITRE fields -
is escaped, so a crafted log line (or a future data-driven technique mapping)
can't inject markup. Audit finding C5.
"""
from log_api.models import AnomalyFinding, MitreTag, Severity
from log_api.reporter.report import _esc, _finding_card


def test_esc_escapes_all_html_metacharacters():
    assert _esc("a'b\"<>&") == "a&#39;b&quot;&lt;&gt;&amp;"   # incl. the single quote


def test_finding_card_escapes_mitre_fields():
    evil = MitreTag(technique_id="T1", technique_name="x'><script>alert(1)</script>",
                    tactic="t", url="https://evil/'><script>")
    card = _finding_card(
        AnomalyFinding(detector="d", finding_type="t", description="x", severity_score=50,
                       severity=Severity.MEDIUM, count=1, mitre_tags=[evil]),
        0)
    assert "<script>alert(1)</script>" not in card   # raw payload not emitted
    assert "&lt;script&gt;" in card                   # it was escaped
    assert "'>" not in card.split("href='")[1][:60]   # can't break out of the single-quoted href
