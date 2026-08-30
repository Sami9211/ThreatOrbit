"""The report for somebody who does not work here.

An executive or a customer is not reading to triage. They are reading to answer
three questions - did anything happen to us, did the team handle it, and is
there anything only I can decide - and the "executive" audience answered none of
them. It truncated the findings list and glued "Executive summary -" onto the
technical narrative: the same sentences about alert counts and CVE totals, with
a label on top.

The property these tests exist to hold is the first paragraph. **A quiet week
and a broken collector produce the same small numbers**, and a report that does
not say which one it is describing is worse than no report - it is a false
assurance with a logo on it. So coverage comes first, and when no telemetry
arrived the narrative says so before anything else.

Everything else here is the same rule in other clothes: every clause is bound to
a number the function just read, and a paragraph with nothing to say is dropped
rather than padded.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from dashboard_api.db import get_conn
from dashboard_api.reports import build_report, outsider_narrative


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _window(days=7):
    now = _now()
    return (now - timedelta(days=days)).isoformat(), now.isoformat(), "Last 7 days"


@pytest.fixture()
def quiet_store():
    """No telemetry, no alerts, no cases - the state that must NOT read as calm."""
    with get_conn() as conn:
        since, until, _ = _window()
        saved = {}
        for table, col in (("events", "ts"), ("alerts", "ts"), ("cases", "created"),
                           ("playbook_runs", "ts"), ("dark_web_findings", "ts")):
            saved[table] = conn.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE {col} BETWEEN ? AND ?",
                (since, until)).fetchone()["n"]
        yield saved


def test_no_telemetry_is_the_headline_not_a_footnote():
    """The single most important line in an outsider report."""
    with get_conn() as conn:
        since, until, label = _window()
        # A window nothing could possibly fall into.
        far = (_now() - timedelta(days=4000)).isoformat()
        paras = outsider_narrative(conn, far, (_now() - timedelta(days=3990)).isoformat(), label)
    first = paras[0]
    assert "No telemetry" in first
    assert "quiet period cannot be told apart from a collector that stopped" in first, (
        "the report must distinguish 'nothing happened' from 'we did not look' - "
        "they produce identical numbers")
    # And it must not then talk about what happened on the network.
    assert not any("traffic on your network" in p for p in paras[1:])


def test_a_busy_window_reports_what_happened(client, auth):
    marker = uuid.uuid4().hex[:8]
    now = _now()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (id,ts,category,event_type,src_ip,raw,source,processed) "
            "VALUES (?,?,'network','beacon','10.1.2.3','x','pytest',1)",
            (f"ev-{marker}", now.isoformat()))
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
            "rule_id,rule_name,ti_value) VALUES (?,?,?,'critical','new','undetermined','',90,"
            "'R-TIMATCH','ThreatIntel · IOC match','203.0.113.77')",
            (f"al-{marker}", now.isoformat(), f"Threat intel match {marker}"))
        conn.commit()
    try:
        since, until, label = _window()
        with get_conn() as conn:
            paras = outsider_narrative(conn, since, until, label)
        text = " ".join(paras)
        assert "examined" in paras[0] and "event" in paras[0]
        assert "traffic on your network reached" in text, (
            "a match on the deployment's own traffic is the strongest signal the "
            "platform produces and has to be called out as such")
        assert "critical" in text
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM events WHERE id=?", (f"ev-{marker}",))
            conn.execute("DELETE FROM alerts WHERE id=?", (f"al-{marker}",))
            conn.commit()


def test_alerts_that_are_only_rule_hits_say_so():
    """"We saw known-bad traffic" and "a rule fired on your logs" are different
    claims, and a customer reading the second as the first is being misled."""
    marker = uuid.uuid4().hex[:8]
    # Past-dated for the same reason as the orphan-alert test: a window around
    # "now" is a window every other test writes into.
    when = _now() - timedelta(days=400)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (id,ts,category,event_type,raw,source,processed) "
            "VALUES (?,?,'auth','failed_login','x','pytest',1)", (f"ev2-{marker}", when.isoformat()))
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
            "rule_id,rule_name) VALUES (?,?,?,'high','new','undetermined','',70,'R-ENGINE','rule')",
            (f"al2-{marker}", when.isoformat(), f"Rule hit {marker}"))
        conn.commit()
    try:
        with get_conn() as conn:
            paras = outsider_narrative(conn, (when - timedelta(hours=1)).isoformat(),
                                       (when + timedelta(hours=1)).isoformat(), "Last 7 days")
        text = " ".join(paras)
        assert "None were caused by your own traffic" in text
        assert "detection rules on the logs themselves" in text
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM events WHERE id=?", (f"ev2-{marker}",))
            conn.execute("DELETE FROM alerts WHERE id=?", (f"al2-{marker}",))
            conn.commit()


def test_nothing_is_padded_when_there_is_nothing_to_say():
    """A paragraph with no number behind it is filler, and filler is what makes
    a recurring report stop being read."""
    with get_conn() as conn:
        far = (_now() - timedelta(days=4000)).isoformat()
        paras = outsider_narrative(conn, far, (_now() - timedelta(days=3990)).isoformat(),
                                   "Last 7 days")
    # Coverage, the library, and the ask. No invented "the team responded well".
    assert len(paras) <= 4
    assert all(p.strip().endswith(".") for p in paras)


def test_the_last_word_is_what_the_reader_must_decide():
    with get_conn() as conn:
        since, until, label = _window()
        paras = outsider_narrative(conn, since, until, label)
    last = paras[-1]
    assert last.startswith("Needing a decision from you:") or \
        last == "Nothing in this window needs a decision from you.", last


def test_the_executive_audience_uses_it(client, auth):
    """It used to prefix the technical narrative and call that an executive
    summary."""
    r = client.get("/reports/executive?period=weekly&audience=executive", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["plainNarrative"], "no plain narrative on an executive report"
    assert "Executive summary - " not in body["summary"]["narrative"]
    assert body["summary"]["narrative"] == " ".join(body["plainNarrative"])


def test_every_audience_carries_it_for_api_consumers(client, auth):
    for audience in ("technical", "compliance"):
        body = client.get(f"/reports/executive?period=weekly&audience={audience}",
                          headers=auth).json()
        assert body["plainNarrative"], audience
        # ...but does not replace the technical narrative for those readers.
        assert body["summary"]["narrative"] != " ".join(body["plainNarrative"])


def test_the_renderers_break_it_into_paragraphs(client, auth):
    from dashboard_api.report_render import to_html, to_markdown
    body = client.get("/reports/executive?period=weekly&audience=executive",
                      headers=auth).json()
    md = to_markdown(body)
    html = to_html(body)
    for para in body["plainNarrative"]:
        assert para in md
    assert html.count("<p>") >= len(body["plainNarrative"])


def test_the_reader_facing_view_renders_the_paragraphs():
    import pathlib
    btn = (pathlib.Path(__file__).resolve().parents[2]
           / "frontend/components/dashboard/ReportButton.tsx").read_text()
    assert "plainNarrative" in btn, "the UI still shows one run-together block"


def test_alerts_without_events_is_named_rather_than_contradicted():
    """A real and specific state: something raised the alerts, so the platform
    was not blind, but the evidence behind them is not in the event store for
    this window. Saying "no telemetry" there contradicts the very next
    paragraph; saying nothing hides a question an operator should be asked."""
    marker = uuid.uuid4().hex[:8]
    # Dated well into the past, and the window drawn tightly around it. Every
    # other test writes at "now", so a window around now is a window other tests
    # keep walking into - which is how an assertion about THIS row becomes an
    # assertion about whatever else happened in the same minute.
    when = _now() - timedelta(days=500)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
            "rule_id,rule_name) VALUES (?,?,?,'high','new','undetermined','',70,'R-ENGINE','r')",
            (f"al3-{marker}", when.isoformat(), f"Orphan alert {marker}"))
        conn.commit()
    try:
        with get_conn() as conn:
            paras = outsider_narrative(conn, (when - timedelta(hours=1)).isoformat(),
                                       (when + timedelta(hours=1)).isoformat(), "Last 7 days")
        first = paras[0]
        assert "event store holds nothing" in first
        assert "trimmed by retention" in first
        assert "No telemetry reached the platform" not in first, (
            "that wording contradicts the alerts reported in the next paragraph")
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM alerts WHERE id=?", (f"al3-{marker}",))
            conn.commit()
