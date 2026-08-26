"""The notification bell is a digest, not a mirror of the alert queue.

The bell holds thirty rows. Before this, every critical alert wrote one of them,
so a single detection pass over a busy batch - or one connector import, which
may raise up to _MAX_INTEL_ALERTS_PER_RUN alerts and does it again every cycle -
took the whole page. A full-suite run measured it exactly: thirty rows, all of
type `alert`, and the playbook that had just completed was nowhere on the page.
A bell that only ever shows one kind of thing is not a full bell, it is an empty
one.

Two changes hold that line, and these tests hold both:

  * a feed LISTING something bad is inventory, not an event - it never rings;
    a value SEEN on this deployment's own traffic always does (`observed`);
  * detection alerts share a bucket per severity, so a burst reads as one row
    saying how many.
"""
import uuid

import pytest

from dashboard_api.db import get_conn
from dashboard_api.detections import _insert_alert, _worth_interrupting, alert_from_intel
from dashboard_api.routers.platform import notify


@pytest.fixture(autouse=True)
def _no_residue():
    """Undo every alert and notification these tests raise.

    The suite shares one database for the whole session, so a test that leaves
    rows behind is a test that can fail a different file. This one did: the
    feed-listing test raises an alert on a random 198.51.100.x address, and one
    run in a couple of hundred picks the exact address
    `test_scan_context_surfaces_real_relations` asserts it can see exactly one
    alert for. Cleaning up by name would not have caught that - it is the row
    existing at all that does the damage - so this snapshots the ids and removes
    whatever is new.
    """
    with get_conn() as conn:
        alerts = {r["id"] for r in conn.execute("SELECT id FROM alerts").fetchall()}
        notes = {r["id"] for r in conn.execute("SELECT id FROM notifications").fetchall()}
    yield
    with get_conn() as conn:
        for table, before in (("alerts", alerts), ("notifications", notes)):
            rows = conn.execute(f"SELECT id FROM {table}").fetchall()
            for r in rows:
                if r["id"] not in before:
                    conn.execute(f"DELETE FROM {table} WHERE id=?", (r["id"],))
        conn.commit()


def _bell(client, auth, limit=30):
    return client.get(f"/notifications?limit={limit}", headers=auth).json()["items"]


def _rows(conn, group_key):
    return conn.execute(
        "SELECT * FROM notifications WHERE group_key=? ORDER BY ts DESC", (group_key,)
    ).fetchall()


# -- the policy itself ------------------------------------------------------------

@pytest.mark.parametrize("severity,ti_value,observed,expected", [
    # Seen on our own traffic: always, whatever the severity. One per value ever.
    ("low", "203.0.113.7", True, True),
    ("critical", "203.0.113.7", True, True),
    # A feed merely listed it. Nothing happened here; the queue is the right
    # place for it, not an interruption.
    ("critical", "203.0.113.7", False, False),
    ("high", "203.0.113.7", False, False),
    # Ordinary detection: critical interrupts, nothing below it does.
    ("critical", None, False, True),
    ("high", None, False, False),
    ("medium", None, False, False),
])
def test_interrupt_policy(severity, ti_value, observed, expected):
    assert _worth_interrupting(severity, ti_value, observed) is expected


# -- grouping ---------------------------------------------------------------------

def test_alert_burst_folds_into_one_row():
    """Twelve critical alerts leave one bell row that says twelve."""
    key = f"alert:critical"
    with get_conn() as conn:
        before = len(_rows(conn, key))
        for i in range(12):
            _insert_alert(conn, title=f"Burst alert {i}", severity="critical", risk=90,
                          rule_name="PyTest · burst")
        conn.commit()
        rows = _rows(conn, key)
    # One bucket for the whole burst (there may be an older, expired bucket from
    # another test; the newest is the one this burst wrote).
    assert len(rows) <= before + 1
    top = rows[0]
    assert top["rollup_count"] >= 12
    # It says how many, and it points at the queue - no single alert id stands
    # for twelve of them.
    assert top["title"] == f"{top['rollup_count']} critical alerts"
    assert top["link"] == "/dashboard/siem?severity=critical"
    assert top["read"] == 0, "a bucket that grew must go unread again"


def test_first_of_a_burst_reads_as_itself():
    """A lone critical is not a bucket: it keeps its own title and record link."""
    marker = uuid.uuid4().hex[:8]
    with get_conn() as conn:
        conn.execute("DELETE FROM notifications WHERE group_key=?", ("alert:high",))
        aid = _insert_alert(conn, title=f"Solo {marker}", severity="high", risk=70,
                            rule_name="PyTest · solo")
        # `high` does not interrupt, so force the grouped path directly to check
        # the shape of a bucket of one.
        nid = notify(conn, type="alert", severity="high", title=f"Solo {marker}",
                     detail=aid, link=f"/dashboard/siem?alert={aid}",
                     group_key="alert:high", rollup_title="{n} high alerts",
                     rollup_link="/dashboard/siem?severity=high")
        conn.commit()
        row = conn.execute("SELECT * FROM notifications WHERE id=?", (nid,)).fetchone()
    assert row["rollup_count"] == 1
    assert row["title"] == f"Solo {marker}"
    assert row["link"] == f"/dashboard/siem?alert={aid}"


def test_expired_window_starts_a_new_bucket():
    """A bucket is a burst, not a forever-bin: past the window, a new row opens."""
    from datetime import datetime, timedelta, timezone
    key = f"pytest:window:{uuid.uuid4().hex[:8]}"
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    with get_conn() as conn:
        nid = notify(conn, type="system", title="first", group_key=key,
                     rollup_title="{n} things")
        # Age the bucket past the default window rather than shrinking the
        # window: a zero-second window is still "this second", and this second
        # is exactly when the row was written.
        conn.execute("UPDATE notifications SET ts=? WHERE id=?", (stale, nid))
        notify(conn, type="system", title="second", group_key=key,
               rollup_title="{n} things")
        conn.commit()
        rows = _rows(conn, key)
    assert len(rows) == 2
    assert all(r["rollup_count"] == 1 for r in rows)


def test_buckets_do_not_cross_orgs():
    """Two tenants sharing a bucket would let one workspace's burst swallow the
    other's notification."""
    key = f"pytest:org:{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        notify(conn, type="system", title="tenant a", group_key=key, org_id="org-a")
        notify(conn, type="system", title="tenant b", group_key=key, org_id="org-b")
        conn.commit()
        rows = _rows(conn, key)
    assert len(rows) == 2
    assert {r["org_id"] for r in rows} == {"org-a", "org-b"}


def test_rollup_title_tolerates_braces_in_an_alert_title():
    """Alert titles are arbitrary text; a JSON fragment in one must not blow up
    the roll-up (which is why it substitutes rather than .format()s)."""
    key = f"pytest:braces:{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        notify(conn, type="alert", title='beacon to {"c2": true}', group_key=key)
        nid = notify(conn, type="alert", title='beacon to {"c2": true}', group_key=key)
        conn.commit()
        row = conn.execute("SELECT * FROM notifications WHERE id=?", (nid,)).fetchone()
    assert row["title"] == '2 × beacon to {"c2": true}'


# -- the two threat-intel meanings -------------------------------------------------

def test_feed_listing_never_rings_the_bell():
    """connectors._import raises these in bulk. They are inventory."""
    value = f"198.51.100.{uuid.uuid4().int % 200 + 20}"
    with get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) AS n FROM notifications").fetchone()["n"]
        aid = alert_from_intel(conn, value=value, ioc_type="ip", severity="critical",
                               confidence=95, threat_type="c2", actor_name="",
                               source="PyTest feed")
        conn.commit()
        after = conn.execute("SELECT COUNT(*) AS n FROM notifications").fetchone()["n"]
        alert = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    assert alert is not None, "it still belongs in the alert queue"
    assert after == before, "a feed listing an indicator is not an interruption"


def test_a_value_seen_here_always_rings():
    """ingest.match_threat_intel's path: our own traffic touched it."""
    value = f"198.51.100.{uuid.uuid4().int % 200 + 20}"
    with get_conn() as conn:
        aid = alert_from_intel(conn, value=value, ioc_type="domain", severity="low",
                               confidence=60, threat_type="phishing", actor_name="",
                               source="PyTest feed", observed=True)
        conn.commit()
        note = conn.execute(
            "SELECT * FROM notifications WHERE detail=?", (aid,)).fetchone()
    assert note is not None, "a match on our own telemetry is the whole point"
    # Never rolled up: the value is the message.
    assert note["group_key"] is None and note["rollup_count"] == 1


# -- what the operator actually sees ----------------------------------------------

def test_a_burst_leaves_room_for_everything_else(client, auth):
    """The regression this whole change exists for: a detection burst must not
    push a playbook completing, a case opening, or a connector failing off the
    page."""
    marker = uuid.uuid4().hex[:8]
    with get_conn() as conn:
        conn.execute("DELETE FROM notifications")
        for i in range(60):
            _insert_alert(conn, title=f"Storm {i}", severity="critical", risk=93,
                          rule_name="PyTest · storm")
        notify(conn, type="playbook", title=f"Containment finished {marker}",
               severity="info", link="/dashboard/soar")
        conn.commit()
    items = _bell(client, auth)
    assert any(n["type"] == "playbook" for n in items), \
        f"bell shows only {sorted({n['type'] for n in items})}"
    alerts = [n for n in items if n["type"] == "alert"]
    assert len(alerts) == 1, f"60 alerts should read as one row, got {len(alerts)}"
    assert alerts[0]["rollup_count"] == 60


def test_bell_order_is_deterministic(client, auth):
    """Same request, same order. Timestamps used to truncate to the second, so a
    burst came back in whatever order the index walked and paging could repeat or
    skip rows."""
    with get_conn() as conn:
        for i in range(8):
            notify(conn, type="system", title=f"tick {i}", severity="info")
        conn.commit()
    first = [n["id"] for n in _bell(client, auth)]
    second = [n["id"] for n in _bell(client, auth)]
    assert first == second
    # And a smaller page is a true prefix of the larger one.
    assert [n["id"] for n in _bell(client, auth, limit=4)] == first[:4]


def test_severity_deep_link_target_exists():
    """The roll-up sends people to /dashboard/siem?severity=<sev>. If the page
    ignores the param the row is a dead end that silently shows everything."""
    import pathlib
    page = pathlib.Path("frontend/app/dashboard/siem/page.tsx").read_text()
    assert "get('severity')" in page, \
        "the SIEM page must honour ?severity= or the roll-up link goes nowhere useful"


# -- the unread badge --------------------------------------------------------------

def test_unread_badge_counts_events_not_rows(client, auth):
    """"1" over a row reading "40 critical alerts" is a badge contradicting the
    list underneath it. The badge answers "how many notifications are waiting",
    and a bucket of forty is forty."""
    with get_conn() as conn:
        conn.execute("DELETE FROM notifications")
        for i in range(40):
            _insert_alert(conn, title=f"Badge storm {i}", severity="critical", risk=91,
                          rule_name="PyTest · badge")
        conn.commit()
    body = client.get("/notifications", headers=auth).json()
    assert len(body["items"]) == 1
    assert body["unread"] == 40


def test_unread_badge_is_scoped_to_the_workspace(client, auth, monkeypatch):
    """It was not scoped at all: a workspace whose own bell was empty still saw
    another workspace's count on the badge."""
    from dashboard_api import tenancy
    with get_conn() as conn:
        conn.execute("DELETE FROM notifications")
        notify(conn, type="system", title="someone else's workspace",
               org_id="org-somebody-else")
        conn.commit()
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    try:
        body = client.get("/notifications", headers=auth).json()
    finally:
        monkeypatch.setattr(tenancy, "MULTI_TENANT", False)
    assert body["items"] == []
    assert body["unread"] == 0, "another tenant's notification was counted here"
