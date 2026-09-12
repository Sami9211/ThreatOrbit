"""A saved hunt is a standing hypothesis. The news is what is NEW.

Two defects made scheduled hunts a control that lies.

**They alerted on every run that had hits.** A hunt matching the same twelve
events raised an identical alert every fifteen minutes, forever. That is the
same failure as a feed that reports a poll as an event, or a bell that shows
thirty rows of one alert storm - and this platform has spent a lot of effort
not doing that everywhere else.

**They only ran inside the synthetic telemetry loop.** `run_due_scheduled_hunts`
was a step in `process_tick`, which `main` calls only when SYNTHETIC_ALLOWED. On
a real deployment - the one with real logs and real hunts in it - the schedule
was accepted by the API, shown in the UI, and honoured by nothing at all.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from dashboard_api.db import get_conn
from dashboard_api.hunting import run_due_scheduled_hunts

# Relative to the real clock, deliberately. `event_search` scopes to the last 24
# hours using the wall clock, so a literal date puts every fixture event outside
# the window and the hunt matches nothing - and a literal date is a time bomb
# besides. Everything below is offset from this.
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _event(ts, src, tag):
    """Insert AND COMMIT. `event_search` opens its own connection, so an
    uncommitted event is invisible to the hunt - which silently turned the
    "nothing changed" tests green for the wrong reason the first time."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (id,ts,category,event_type,severity_hint,src_ip,dest_ip,"
            "username,hostname,action,raw,source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), ts.isoformat(), "auth", tag, "medium", src, "10.0.0.1",
             "svc-backup", "web01", "deny", f"{tag} from {src}", "collector"))
        conn.commit()


def _run(now):
    with get_conn() as conn:
        r = run_due_scheduled_hunts(conn, now=now)
        conn.commit()
    return r


@pytest.fixture()
def hunt():
    """A scheduled hunt over an event type nothing else in the suite uses."""
    tag = f"hunttest_{uuid.uuid4().hex[:8]}"
    hid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO saved_hunts (id,domain,name,description,query,technique,"
            "last_run,hit_count,author,status,progress,created,schedule_minutes,auto_alert) "
            "VALUES (?,'siem',?,NULL,?,NULL,NULL,0,'a@b.test','idle',0,?,15,1)",
            (hid, f"hunt {tag}", f"event_type={tag}", NOW.isoformat()))
        conn.commit()
    yield hid, tag
    with get_conn() as conn:
        conn.execute("DELETE FROM saved_hunts WHERE id=?", (hid,))
        conn.execute("DELETE FROM events WHERE event_type=?", (tag,))
        conn.execute("DELETE FROM alerts WHERE rule_name LIKE ?", (f"%{tag}%",))
        conn.commit()


def _alerts(tag) -> int:
    with get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE rule_name LIKE ?",
            (f"%{tag}%",)).fetchone()["n"]


# -- only what is new is news ---------------------------------------------------

def test_the_first_scheduled_run_reports_what_is_already_there(hunt):
    """An analyst who has just scheduled a hunt should be told if it matches
    something NOW, rather than waiting a whole cadence to find out. That costs
    exactly one alert, ever - the repetition this module fixes comes from every
    run AFTER the first."""
    hid, tag = hunt
    for i in range(3):
        _event(NOW - timedelta(hours=2, minutes=i), f"203.0.113.{i}", tag)
    r = _run(NOW)
    assert r["ran"] >= 1, "the hunt was due and did not run"
    assert _alerts(tag) == 1, "the first run said nothing about a live match"


def test_a_run_where_nothing_changed_does_not_alert(hunt):
    """The defect. The same three events still match; that is not news, and
    saying so every fifteen minutes is how an alert channel gets muted."""
    hid, tag = hunt
    for i in range(3):
        _event(NOW - timedelta(hours=2, minutes=i), f"203.0.113.{i}", tag)
    _run(NOW)
    # Prove the hunt really does match them, or this test passes for free.
    with get_conn() as conn:
        assert conn.execute("SELECT hit_count FROM saved_hunts WHERE id=?",
                            (hid,)).fetchone()["hit_count"] == 3
    after_first = _alerts(tag)
    _run(NOW + timedelta(minutes=20))
    assert _alerts(tag) == after_first, "an unchanged result raised another alert"


def test_a_genuinely_new_match_does_alert(hunt):
    """...and the guard must not have turned the feature off."""
    hid, tag = hunt
    _event(NOW - timedelta(hours=2), "203.0.113.1", tag)
    _run(NOW)
    after_first = _alerts(tag)
    _event(NOW + timedelta(minutes=25), "198.51.100.7", tag)
    _run(NOW + timedelta(minutes=40))
    assert _alerts(tag) == after_first + 1, "a new match did not raise an alert"


def test_the_alert_says_how_many_are_new_not_just_how_many_match(hunt):
    """"12 hits" is true every run. "1 that was not there last time" is the
    thing the analyst is being interrupted for."""
    hid, tag = hunt
    for i in range(4):
        _event(NOW - timedelta(hours=2, minutes=i), f"203.0.113.{i}", tag)
    _run(NOW)
    _event(NOW + timedelta(minutes=25), "198.51.100.7", tag)
    _run(NOW + timedelta(minutes=40))
    # Both alerts land in the same second, so ask for the one this test is
    # about rather than trusting the ordering of a tie. The pattern goes in as a
    # PARAMETER: psycopg reads a literal `%` in query text as a placeholder
    # marker, so an inline '%newly matched%' fails on Postgres and passes on
    # SQLite - which is exactly how it got committed the first time.
    with get_conn() as conn:
        a = conn.execute(
            "SELECT title, description FROM alerts WHERE rule_name LIKE ? "
            "AND title LIKE ? ORDER BY ts DESC LIMIT 1",
            (f"%{tag}%", "%newly matched%")).fetchone()
    assert a is not None, "no new-match alert was raised"
    assert "1 new" in a["title"], a["title"]
    assert "not there at the last check" in a["description"]
    assert "5" in a["description"], "the total in the window should be stated too"


# -- the cadence is honoured ----------------------------------------------------

def test_a_hunt_that_is_not_due_does_not_run(hunt):
    hid, tag = hunt
    _run(NOW)
    with get_conn() as conn:
        before = conn.execute("SELECT last_scheduled FROM saved_hunts WHERE id=?",
                              (hid,)).fetchone()["last_scheduled"]
    _run(NOW + timedelta(minutes=5))
    with get_conn() as conn:
        after = conn.execute("SELECT last_scheduled FROM saved_hunts WHERE id=?",
                             (hid,)).fetchone()["last_scheduled"]
    assert before == after, "a 15-minute hunt ran again after 5 minutes"


def test_an_unscheduled_hunt_is_never_run(hunt):
    """schedule_minutes = 0 means "only when I press the button"."""
    hid, tag = hunt
    with get_conn() as conn:
        conn.execute("UPDATE saved_hunts SET schedule_minutes=0 WHERE id=?", (hid,))
        conn.commit()
    _run(NOW)
    with get_conn() as conn:
        assert conn.execute("SELECT last_scheduled FROM saved_hunts WHERE id=?",
                            (hid,)).fetchone()["last_scheduled"] is None


def test_auto_alert_off_still_runs_but_stays_quiet(hunt):
    """Some hunts are worth re-running to keep the count fresh without
    interrupting anybody."""
    hid, tag = hunt
    with get_conn() as conn:
        conn.execute("UPDATE saved_hunts SET auto_alert=0 WHERE id=?", (hid,))
        conn.commit()
    _event(NOW - timedelta(hours=2), "203.0.113.1", tag)
    _run(NOW)
    _event(NOW + timedelta(minutes=25), "198.51.100.7", tag)
    _run(NOW + timedelta(minutes=40))
    with get_conn() as conn:
        assert conn.execute("SELECT hit_count FROM saved_hunts WHERE id=?",
                            (hid,)).fetchone()["hit_count"] == 2, "it should still run"
    assert _alerts(tag) == 0, "auto_alert was off and it alerted anyway"


def test_a_scheduled_hunt_that_matches_nothing_is_silent(hunt):
    """No hits, no alert, on the first run or any other."""
    hid, tag = hunt
    assert _run(NOW)["ran"] >= 1
    assert _alerts(tag) == 0


# -- it runs at all, in the mode that matters -----------------------------------

def test_scheduled_hunts_do_not_ride_the_synthetic_telemetry_loop():
    """The hole that made the whole feature inert on a real deployment.

    `process_tick` only runs when synthetic generation is enabled, so a hunt
    scheduled in real-data mode was never executed by anything. It has its own
    loop now, started unconditionally alongside the other periodic jobs.
    """
    import inspect

    import dashboard_api.engine as engine_mod
    import dashboard_api.main as main_mod
    assert "run_due_scheduled_hunts" not in inspect.getsource(engine_mod.process_tick), \
        "scheduled hunts are back inside the synthetic-only tick"
    assert hasattr(main_mod, "_hunt_loop"), "no scheduled-hunt loop"
    assert "target=_hunt_loop" in inspect.getsource(main_mod), \
        "the hunt loop is never started"
    assert "leader.is_leader()" in inspect.getsource(main_mod._hunt_loop), \
        "every replica would run every hunt"
