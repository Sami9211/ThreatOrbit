"""SOAR metrics honesty fences.

`casesClosedWeek` is shown in the UI as "Cases Closed (week)". The cases query
has no time filter, so it used to report `len(closed)` — the *all-time* closed
count — which on a long-running deployment reads as hundreds where the real
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
    # Only the 2 recent closures count toward "this week" — the 3 old ones don't,
    # even though all 5 are closed. (Pre-fix this asserted +5.)
    assert after == base + 2
