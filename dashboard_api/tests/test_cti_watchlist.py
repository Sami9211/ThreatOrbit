"""A saved CTI hunt on a schedule is a watchlist over the indicator store.

Scheduling only ever worked for SIEM hunts. A CTI hunt - the kind that asks
"has any new Cobalt Strike infrastructure landed?" - could be saved and run by
hand and nothing more, so the one question a threat researcher wants re-asked
every week was the one thing that could not be.

The hard part is what "new" means. `iocs.first_seen` is the SOURCE's claim about
the wider world and is routinely backdated by years: a feed publishing a 2019
address today would never register as new to a watchlist that trusted it. So
indicators now carry `imported_at` - when the value entered THIS store, on our
own clock - and that is what the watchlist compares against.

A match raises a NOTIFICATION, not a SIEM alert. A SIEM alert says something
happened on this network; a new indicator matching a standing hypothesis says
the world changed. Filing the second as the first puts intel into the queue an
analyst triages as detections.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from dashboard_api.db import get_conn
from dashboard_api.hunting import run_due_scheduled_hunts, run_ioc_hunt
from dashboard_api.ioc_store import insert_ioc

NOW = datetime.now(timezone.utc).replace(microsecond=0)
BACKDATED = "2019-01-01T00:00:00+00:00"


@pytest.fixture()
def watchlist():
    """A scheduled CTI hunt over a term nothing else in the suite uses."""
    tag = f"watch{uuid.uuid4().hex[:8]}"
    hid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO saved_hunts (id,domain,name,description,query,technique,"
            "last_run,hit_count,author,status,progress,created,schedule_minutes,"
            "auto_alert,org_id) VALUES (?,'cti',?,NULL,?,NULL,NULL,0,'a@b.test',"
            "'idle',0,?,60,1,'org-default')",
            (hid, f"watch {tag}", tag, NOW.isoformat()))
        conn.commit()
    yield hid, tag
    with get_conn() as conn:
        conn.execute("DELETE FROM saved_hunts WHERE id=?", (hid,))
        conn.execute("DELETE FROM iocs WHERE value LIKE ?", (f"{tag}%",))
        conn.execute("DELETE FROM notifications WHERE group_key=?", (f"watchlist:{hid}",))
        conn.commit()


def _add(tag, name, imported):
    """An indicator whose source backdates `first_seen` - the normal case."""
    value = f"{tag}-{name}.example.test"
    with get_conn() as conn:
        insert_ioc(conn, type="domain", value=value, threat_type=f"{tag}-activity",
                   confidence=70, source="feed", first_seen=BACKDATED)
        conn.execute("UPDATE iocs SET imported_at=? WHERE value=?",
                     (imported.isoformat(), value))
        conn.commit()
    return value


def _run(now):
    with get_conn() as conn:
        r = run_due_scheduled_hunts(conn, now=now)
        conn.commit()
    return r


def _notes(hid) -> int:
    with get_conn() as conn:
        return conn.execute(
            "SELECT COALESCE(SUM(rollup_count),0) AS n FROM notifications "
            "WHERE group_key=?", (f"watchlist:{hid}",)).fetchone()["n"]


# -- new means new to US --------------------------------------------------------

def test_new_is_measured_on_our_clock_not_the_sources(watchlist):
    """The case that decides whether this feature works at all. Three
    indicators arrive today, every one of them carrying a 2019 `first_seen`
    because that is what the feed published. They are new to this store."""
    hid, tag = watchlist
    for i in range(2):
        _add(tag, f"old-{i}", NOW - timedelta(days=5))
    _run(NOW)
    for i in range(3):
        _add(tag, f"new-{i}", NOW + timedelta(hours=3))
    _run(NOW + timedelta(hours=4))
    # ONE notification saying three, not three notifications: the count in the
    # title is the indicators, `rollup_count` is how many times this bucket has
    # been added to.
    with get_conn() as conn:
        rows = conn.execute("SELECT title FROM notifications WHERE group_key=?",
                            (f"watchlist:{hid}",)).fetchall()
    assert len(rows) == 1, "expected one bucket"
    assert "3 new" in rows[0]["title"], \
        f"backdated arrivals were not recognised as new: {rows[0]['title']}"


def test_imported_at_is_set_independently_of_first_seen(watchlist):
    """The column the above rests on. `first_seen` is what the source claimed;
    `imported_at` is when we took delivery."""
    hid, tag = watchlist
    value = _add(tag, "one", NOW)
    with get_conn() as conn:
        row = conn.execute("SELECT first_seen, imported_at FROM iocs WHERE value=?",
                           (value,)).fetchone()
    assert row["first_seen"] == BACKDATED
    assert row["imported_at"] and row["imported_at"] != BACKDATED


def test_a_fresh_insert_stamps_imported_at_without_being_asked():
    """It is derived at the one canonical insert point, so no caller can forget
    it - the failure mode that column list exists to prevent."""
    value = f"stamp-{uuid.uuid4().hex[:8]}.example.test"
    try:
        with get_conn() as conn:
            insert_ioc(conn, type="domain", value=value, source="test")
            conn.commit()
            assert conn.execute("SELECT imported_at FROM iocs WHERE value=?",
                                (value,)).fetchone()["imported_at"]
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM iocs WHERE value=?", (value,))
            conn.commit()


# -- quiet unless something changed ---------------------------------------------

def test_the_first_run_does_not_announce_the_backlog(watchlist):
    """Unlike the SIEM path, a watchlist has no first-run alert. The indicator
    store is half a million rows deep: "everything matching, ever" is a backlog,
    not news."""
    hid, tag = watchlist
    for i in range(4):
        _add(tag, f"old-{i}", NOW - timedelta(days=5))
    r = _run(NOW)
    assert r["ran"] >= 1
    assert _notes(hid) == 0


def test_a_run_where_nothing_arrived_is_silent(watchlist):
    hid, tag = watchlist
    _add(tag, "old", NOW - timedelta(days=5))
    _run(NOW)
    _run(NOW + timedelta(hours=2))
    assert _notes(hid) == 0


def test_auto_alert_off_still_refreshes_the_count_but_stays_quiet(watchlist):
    hid, tag = watchlist
    with get_conn() as conn:
        conn.execute("UPDATE saved_hunts SET auto_alert=0 WHERE id=?", (hid,))
        conn.commit()
    _add(tag, "old", NOW - timedelta(days=5))
    _run(NOW)
    _add(tag, "new", NOW + timedelta(hours=3))
    _run(NOW + timedelta(hours=4))
    with get_conn() as conn:
        assert conn.execute("SELECT hit_count FROM saved_hunts WHERE id=?",
                            (hid,)).fetchone()["hit_count"] == 2
    assert _notes(hid) == 0


# -- it is intel, not a detection ----------------------------------------------

def test_a_watchlist_match_is_a_notification_not_a_siem_alert(watchlist):
    """A SIEM alert says something happened on this network. A new indicator
    matching a hypothesis says the world changed. Filing the second as the first
    puts intel into the queue an analyst triages as detections."""
    hid, tag = watchlist
    _add(tag, "old", NOW - timedelta(days=5))
    _run(NOW)
    _add(tag, "new", NOW + timedelta(hours=3))
    _run(NOW + timedelta(hours=4))
    with get_conn() as conn:
        n = conn.execute(
            "SELECT type, title, detail FROM notifications WHERE group_key=?",
            (f"watchlist:{hid}",)).fetchone()
        alerts = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE title LIKE ?",
            (f"%{tag}%",)).fetchone()["n"]
    assert n is not None and n["type"] == "cti.watchlist"
    assert "1 new" in n["title"]
    assert alerts == 0, "a watchlist match raised a SIEM alert"


def test_a_burst_of_matches_is_one_growing_line(watchlist):
    """Grouped per hunt, like every other burst in this platform: a feed sync
    landing many matching indicators is one line that says how many."""
    hid, tag = watchlist
    _add(tag, "old", NOW - timedelta(days=5))
    _run(NOW)
    _add(tag, "a", NOW + timedelta(hours=3))
    _run(NOW + timedelta(hours=4))
    _add(tag, "b", NOW + timedelta(hours=5))
    _run(NOW + timedelta(hours=6))
    with get_conn() as conn:
        rows = conn.execute("SELECT rollup_count FROM notifications WHERE group_key=?",
                            (f"watchlist:{hid}",)).fetchall()
    assert len(rows) == 1, f"{len(rows)} separate rows instead of one bucket"
    assert rows[0]["rollup_count"] == 2


# -- the cadence ----------------------------------------------------------------

def test_a_watchlist_that_is_not_due_does_not_run(watchlist):
    hid, tag = watchlist
    _run(NOW)
    with get_conn() as conn:
        before = conn.execute("SELECT last_scheduled FROM saved_hunts WHERE id=?",
                              (hid,)).fetchone()["last_scheduled"]
    _run(NOW + timedelta(minutes=5))
    with get_conn() as conn:
        after = conn.execute("SELECT last_scheduled FROM saved_hunts WHERE id=?",
                             (hid,)).fetchone()["last_scheduled"]
    assert before == after


def test_the_since_filter_is_a_real_count_not_a_page(watchlist):
    """`newHits` is counted over all matches, not the returned page."""
    hid, tag = watchlist
    for i in range(6):
        _add(tag, f"n-{i}", NOW + timedelta(hours=1))
    r = run_ioc_hunt(tag, limit=2, since_iso=NOW.isoformat())
    assert r["newHits"] == 6, r["newHits"]
    assert len(r["newResults"]) == 2
