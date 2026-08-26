"""The live stream, end to end: what the server pushes and what a browser hears.

Two halves, and the second is the one that keeps finding things.

  * The imports screen is driven by the import, not by a timer. `start_work`,
    `update_work` and `finish_work` each push the work's current state, in the
    same shape (and the same camelCase) the REST listing returns after the
    client camelises it - a console that merges a pushed work into its table
    must not have to compute percent and rate differently from the server.

  * EventSource only delivers a NAMED event to a listener registered for that
    exact name: `onmessage` never sees one. So every event name the server
    publishes has to appear in useLiveStream's NAMED list, or it is invisible to
    every page in the product while looking perfectly healthy on the wire. Two
    were - `playbook.failed` and `darkweb.takedown` were dispatched, delivered
    to webhook subscribers, and dropped by every browser.
"""
import pathlib
import re

import pytest

import dashboard_api.events_stream as es
from dashboard_api.connectors import finish_work, start_work, update_work, work_view

ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _no_residue():
    """Remove the work rows these tests open.

    One shared database for the whole session means residue from one file can
    fail another - a lesson this suite has already learned the expensive way.
    """
    from dashboard_api.db import get_conn
    with get_conn() as conn:
        before = {r["id"] for r in conn.execute("SELECT id FROM connector_works").fetchall()}
    yield
    with get_conn() as conn:
        for r in conn.execute("SELECT id FROM connector_works").fetchall():
            if r["id"] not in before:
                conn.execute("DELETE FROM connector_works WHERE id=?", (r["id"],))
        conn.commit()


@pytest.fixture()
def pushed(monkeypatch):
    """Capture everything published while the test runs."""
    seen = []
    real = es.publish
    monkeypatch.setattr(es, "publish",
                        lambda t, d=None, org=None: (seen.append((t, d or {})), real(t, d, org))[1])
    return seen


def _works(pushed):
    return [d for t, d in pushed if t == "connector.work"]


# -- the imports screen is pushed, not polled --------------------------------------

def test_a_run_announces_itself_the_moment_it_opens(pushed):
    wid = start_work("PyTest feed", None, 500)
    try:
        opened = _works(pushed)
        assert opened, "a sync that started told nobody"
        w = opened[-1]
        assert w["id"] == wid and w["status"] == "running"
        assert w["expected"] == 500 and w["processed"] == 0
        assert w["percent"] == 0
        # Nothing has been processed, so there is no rate to report. `null` is
        # honest where an invented number is not.
        assert w["ratePerSec"] is None
    finally:
        finish_work(wid, "completed", processed=500)


def test_progress_is_pushed_for_every_sub_batch(pushed):
    wid = start_work("PyTest feed", None, 400)
    try:
        update_work(wid, processed=100, imported=90, duplicates=10, skipped=0)
        update_work(wid, processed=400, imported=350, duplicates=50, skipped=0)
        seen = _works(pushed)
        assert [w["processed"] for w in seen] == [0, 100, 400], seen
        assert seen[-1]["percent"] == 100
        assert seen[-1]["imported"] == 350 and seen[-1]["duplicates"] == 50
    finally:
        finish_work(wid, "completed", processed=400)


def test_the_close_is_pushed_too(pushed):
    wid = start_work("PyTest feed", None, 10)
    finish_work(wid, "failed", "feed unreachable", processed=0)
    w = _works(pushed)[-1]
    assert w["status"] == "failed" and w["message"] == "feed unreachable"
    # A failed sync that fetched nothing is 0%, not 100%. Reported as 100 it drew
    # a FULL bar in red, reading as "finished" for a run that did nothing at all.
    assert w["percent"] == 0


def test_the_pushed_shape_is_the_shape_the_client_already_knows(pushed, client, auth):
    """SSE data reaches the browser as raw JSON - only api() responses pass
    through toCamel() - so a pushed work and a fetched one have to arrive
    already agreeing on their field names."""
    wid = start_work("PyTest shape check", None, 3)
    finish_work(wid, "completed", processed=3, imported=3)
    w = _works(pushed)[-1]

    listed = client.get("/connectors/works?limit=50", headers=auth).json()
    row = next((r for r in listed if r["id"] == wid), None)
    assert row is not None, "the work the stream announced is not in the listing"

    def camel(k):
        head, *rest = k.split("_")
        return head + "".join(p.title() for p in rest)

    fetched = {camel(k): v for k, v in row.items()}
    for key, value in w.items():
        assert key in fetched, f"the stream sends {key}, the listing has no such field"
        assert fetched[key] == value, f"{key}: pushed {value!r}, listing {fetched[key]!r}"


def test_percent_and_rate_come_from_one_place():
    """Both readers derive through work_view, so the progress bar cannot jump
    when a pushed row replaces a fetched one."""
    w = work_view({"status": "running", "expected": 200, "processed": 50,
                   "imported": 50, "started_at": "2026-01-01T00:00:00+00:00",
                   "updated_at": "2026-01-01T00:00:10+00:00"})
    assert w["percent"] == 25
    assert w["ratePerSec"] == 5.0
    assert w["noop"] is False


def test_publishing_can_never_fail_an_import(monkeypatch):
    """Telling somebody about an import must not be able to break one."""
    def boom(*a, **k):
        raise RuntimeError("the stream is down")
    monkeypatch.setattr(es, "publish", boom)
    wid = start_work("PyTest feed", None, 5)
    update_work(wid, processed=5, imported=5)
    finish_work(wid, "completed", processed=5, imported=5)
    monkeypatch.undo()
    from dashboard_api.db import get_conn
    with get_conn() as conn:
        row = conn.execute(
            "SELECT status, processed FROM connector_works WHERE id=?", (wid,)).fetchone()
    assert row["status"] == "completed" and row["processed"] == 5


# -- every event the server sends has to be one the browser listens for ------------

def _published_names() -> set[str]:
    """Literal event names this codebase publishes or dispatches (tests aside)."""
    names: set[str] = set()
    pattern = re.compile(r'\b(?:publish|dispatch)\(\s*"([a-z][a-z._]*)"')
    for path in (ROOT / "dashboard_api").rglob("*.py"):
        if "tests" in path.parts:
            continue
        names |= set(pattern.findall(path.read_text()))
    # The webhook catalogue the API validates subscriptions against is the
    # authoritative list of what this platform emits, so include names that are
    # only ever dispatched through a variable.
    cfg = (ROOT / "dashboard_api" / "routers" / "config.py").read_text()
    block = re.search(r"_WEBHOOK_EVENTS\s*=\s*\{(.*?)\}", cfg, re.S)
    if block:
        names |= set(re.findall(r'"([a-z][a-z._]*)"', block.group(1)))
    return names


def _named_in_client() -> set[str]:
    src = (ROOT / "frontend" / "lib" / "useLiveStream.ts").read_text()
    block = re.search(r"const NAMED = \[(.*?)\]", src, re.S)
    assert block, "useLiveStream no longer declares a NAMED list"
    return set(re.findall(r"'([^']+)'", block.group(1)))


def test_every_published_event_has_a_client_listener():
    published, named = _published_names(), _named_in_client()
    missing = sorted(published - named)
    assert not missing, (
        "the server pushes these and no page can hear them - EventSource only "
        f"delivers a named event to a listener for that exact name: {missing}")


def test_the_listener_list_has_no_ghosts():
    """A name nobody sends is a listener that will never fire, and reads as
    coverage the product does not have."""
    published, named = _published_names(), _named_in_client()
    ghosts = sorted(named - published)
    assert not ghosts, f"useLiveStream listens for events nothing emits: {ghosts}"
