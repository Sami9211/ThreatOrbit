"""Background report scheduler - delivery parity, honest outcomes, isolation.

`run_due_report_schedules` used to diverge from the manual /run endpoint in
three ways this file fences: it skipped the email target entirely, announced
"delivered" even when delivery failed, and let one broken schedule abort the
whole loop.
"""
import uuid

from dashboard_api.db import get_conn
from dashboard_api.routers import platform
from dashboard_api.tenancy import DEFAULT_ORG_ID


def _mk_schedule(*, webhook=None, email=None, kind="executive"):
    sid = str(uuid.uuid4())
    with get_conn() as conn:
        # Same-second notification timestamps make "latest" ambiguous across
        # tests - each test starts from a clean report-notification slate.
        conn.execute("DELETE FROM notifications WHERE type='report'")
        conn.execute(
            "INSERT INTO report_schedules (id,kind,period,cadence,webhook_url,email,enabled,"
            "created_at,created_by,org_id) VALUES (?,?,?,?,?,?,1,?,?,?)",
            (sid, kind, "weekly", "weekly", webhook, email, platform._now(),
             "pytest@threatorbit.space", DEFAULT_ORG_ID),
        )
        conn.commit()
    return sid


def _cleanup(*sids):
    with get_conn() as conn:
        for sid in sids:
            conn.execute("DELETE FROM report_schedules WHERE id=?", (sid,))
        conn.commit()


def _last_report_notification():
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM notifications WHERE type='report' ORDER BY ts DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


def test_scheduled_run_delivers_to_email_target(monkeypatch):
    """The email target must be honoured on cadence, not only on manual /run."""
    sent = []
    monkeypatch.setattr(platform, "_email_report",
                        lambda email, report: (sent.append(email), {"sent": True})[1])
    sid = _mk_schedule(email="soc-lead@example.com")
    try:
        platform.run_due_report_schedules()
        assert sent == ["soc-lead@example.com"]
        n = _last_report_notification()
        assert n and "email ok" in n["title"] and n["severity"] == "info"
    finally:
        _cleanup(sid)


def test_scheduled_run_reports_failure_honestly(monkeypatch):
    """A failed webhook delivery must not be announced as a success."""
    monkeypatch.setattr(platform, "_deliver_report", lambda url, report: False)
    sid = _mk_schedule(webhook="https://example.invalid/hook")
    try:
        platform.run_due_report_schedules()
        n = _last_report_notification()
        assert n and "webhook FAILED" in n["title"] and n["severity"] == "warning"
    finally:
        _cleanup(sid)


def test_one_broken_schedule_cannot_starve_the_rest(monkeypatch):
    """Per-schedule isolation: an exception in one schedule's build must not
    abort the loop before later schedules run."""
    calls = []

    def fake_email(email, report):
        calls.append(email)
        return {"sent": True}

    import dashboard_api.reports as reports
    real_build = reports.build_report

    def exploding_build(kind, period):
        if kind == "threat-landscape":
            raise RuntimeError("boom")
        return real_build(kind, period)

    monkeypatch.setattr("dashboard_api.reports.build_report", exploding_build)
    monkeypatch.setattr(platform, "_email_report", fake_email)
    bad = _mk_schedule(kind="threat-landscape", email="a@example.com")
    good = _mk_schedule(kind="executive", email="b@example.com")
    try:
        platform.run_due_report_schedules()
        assert "b@example.com" in calls, "later schedule was starved by the broken one"
    finally:
        _cleanup(bad, good)
