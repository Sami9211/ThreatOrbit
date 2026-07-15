"""SOAR metrics honesty fences.

`casesClosedWeek` is shown in the UI as "Cases Closed (week)". The cases query
has no time filter, so it used to report `len(closed)` - the *all-time* closed
count - which on a long-running deployment reads as hundreds where the real
weekly figure is a dozen. It now windows on the `updated` close-time proxy.
"""
import uuid
from datetime import datetime, timedelta, timezone

from dashboard_api.db import get_conn


def _insert_closed_case(conn, updated_iso: str) -> None:
    conn.execute(
        "INSERT INTO cases (id,title,type,severity,status,owner,playbook,sla_hours,"
        "created,updated,alert_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), "regression", "incident", "low", "closed", None, None,
         24, updated_iso, updated_iso, 0),
    )


def test_cases_closed_week_windows_to_seven_days(client, auth):
    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=10)).replace(microsecond=0).isoformat()      # outside the week
    recent = (now - timedelta(hours=2)).replace(microsecond=0).isoformat()   # inside the week

    base = client.get("/soar/metrics", headers=auth).json()["casesClosedWeek"]
    with get_conn() as conn:
        for _ in range(3):
            _insert_closed_case(conn, old)
        for _ in range(2):
            _insert_closed_case(conn, recent)
        conn.commit()

    after = client.get("/soar/metrics", headers=auth).json()["casesClosedWeek"]
    # Only the 2 recent closures count toward "this week" - the 3 old ones don't,
    # even though all 5 are closed. (Pre-fix this asserted +5.)
    assert after == base + 2


def _insert_run(conn, ts_iso: str) -> None:
    conn.execute(
        "INSERT INTO playbook_runs (id,playbook_id,playbook_name,ts,status,trigger) "
        "VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), "pb-x", "Test PB", ts_iso, "success", "auto"),
    )


def test_runs_month_windows_to_thirty_days(client, auth):
    """`timeSavedMonth` is derived from `runsMonth`, which must count only the
    trailing 30 days of playbook runs - not the all-time cumulative counter that
    used to feed the 'this month' tile."""
    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=40)).replace(microsecond=0).isoformat()      # outside the month
    recent = (now - timedelta(days=5)).replace(microsecond=0).isoformat()    # inside the month

    base = client.get("/soar/metrics", headers=auth).json()["runsMonth"]
    with get_conn() as conn:
        for _ in range(4):
            _insert_run(conn, old)
        for _ in range(3):
            _insert_run(conn, recent)
        conn.commit()

    after = client.get("/soar/metrics", headers=auth).json()["runsMonth"]
    assert after == base + 3  # only the 3 runs inside the 30-day window count


def test_playbooks_today_counts_only_todays_runs(client, auth):
    """`playbooksToday` must count runs since midnight UTC, not every playbook
    that has ever run (the old `p["last_run"] is not null` count)."""
    now = datetime.now(timezone.utc)
    old = (now - timedelta(hours=30)).replace(microsecond=0).isoformat()  # before midnight
    recent = now.replace(microsecond=0).isoformat()                       # today

    base = client.get("/soar/metrics", headers=auth).json()["playbooksToday"]
    with get_conn() as conn:
        for _ in range(3):
            _insert_run(conn, old)
        for _ in range(2):
            _insert_run(conn, recent)
        conn.commit()

    after = client.get("/soar/metrics", headers=auth).json()["playbooksToday"]
    assert after == base + 2  # only today's runs count
