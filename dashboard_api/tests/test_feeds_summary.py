"""Feeds summary honesty fence.

The feeds/sources "IOCs Today" tile used to sum each feed's nominal daily rate
(and, once live, each feed's *cumulative* indicator total) - never an actual
count of indicators seen today. `newToday` is now a real count of IOCs first
seen since midnight UTC.
"""
import pytest
import uuid
from datetime import datetime, timedelta, timezone

from dashboard_api.db import get_conn


def _insert_ioc(conn, first_seen_iso: str) -> None:
    conn.execute(
        "INSERT INTO iocs (id,type,value,first_seen) VALUES (?,?,?,?)",
        (str(uuid.uuid4()), "ip", f"203.0.113.{uuid.uuid4().int % 254}", first_seen_iso),
    )


def test_new_today_counts_only_iocs_first_seen_today(client, auth):
    now = datetime.now(timezone.utc)
    old = (now - timedelta(hours=30)).replace(microsecond=0).isoformat()  # before midnight UTC
    today = now.replace(microsecond=0).isoformat()

    base = client.get("/feeds/summary", headers=auth).json()["newToday"]
    with get_conn() as conn:
        for _ in range(3):
            _insert_ioc(conn, old)
        for _ in range(2):
            _insert_ioc(conn, today)
        conn.commit()

    after = client.get("/feeds/summary", headers=auth).json()["newToday"]
    assert after == base + 2  # only the 2 seen today count, not the 3 from 30h ago


def test_sources_are_reported_from_connectors(client, auth):
    """There is one place a source lives, and it is `connectors`.

    A `feeds` table used to hold the same idea beside it and was the loser of
    the two: a row in it never imported anything. Live mode seeded none, so the
    Threat Feeds page said "from 0 sources - No sources configured yet" and
    "Total IOCs 0" while two connectors were importing 315,185 indicators - a
    headline number contradicting the panel directly below it. The table is
    gone; these routes are a view.
    """
    import uuid
    from dashboard_api.db import get_conn

    tag = uuid.uuid4().hex[:8]
    cid = f"fs-{tag}"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,"
            "interval_seconds,field_map,status,builtin,created_at,indicator_count) "
            "VALUES (?,?,?,?,1,5,300,'{}','ok',0,?,?)",
            (cid, f"Feed Src {tag}", "json", "https://example.test/f",
             "2026-07-30T00:00:00+00:00", 1234))
        conn.commit()
    try:
        listed = client.get("/feeds", headers=auth).json()
        assert listed, "no sources reported despite a configured connector"
        mine = next((f for f in listed if f["id"] == cid), None)
        assert mine is not None, [f.get("name") for f in listed]
        assert mine["indicators"] == 1234
        assert mine["status"] == "active"

        s = client.get("/feeds/summary", headers=auth).json()
        assert s["totalFeeds"] == len(listed)
        with get_conn() as conn:
            real = conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
        assert s["totalIndicators"] == real, (
            f"summary says {s['totalIndicators']} indicators, store holds {real}")
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM connectors WHERE id=?", (cid,))
            conn.commit()


def test_toggling_a_listed_source_actually_toggles_it(client, auth):
    """The list returns CONNECTOR ids, and the toggle used to update the `feeds`
    table - so every switch on the Sources page 404'd and flicked back with no
    error. Reproduced against a live deployment before the fix: GET /feeds
    returned connector b687688b..., PATCH /feeds/b687688b... returned 404."""
    import uuid
    from dashboard_api.db import get_conn

    tag = uuid.uuid4().hex[:8]
    cid = f"tg-{tag}"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO connectors (id,name,kind,url,enabled,interval_minutes,"
            "interval_seconds,field_map,status,builtin,created_at,indicator_count) "
            "VALUES (?,?,?,?,1,5,300,'{}','ok',0,?,0)",
            (cid, f"Toggle Src {tag}", "json", "https://example.test/t",
             "2026-07-30T00:00:00+00:00"))
        conn.commit()
    try:
        off = client.patch(f"/feeds/{cid}", json={"enabled": False}, headers=auth)
        assert off.status_code == 200, off.text
        assert off.json()["enabled"] == 0 and off.json()["status"] == "paused"
        with get_conn() as conn:
            assert conn.execute("SELECT enabled FROM connectors WHERE id=?",
                                (cid,)).fetchone()["enabled"] == 0

        on = client.patch(f"/feeds/{cid}", json={"enabled": True}, headers=auth)
        assert on.status_code == 200 and on.json()["enabled"] == 1
        assert client.patch("/feeds/not-a-real-id", json={"enabled": True},
                            headers=auth).status_code == 404
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM connectors WHERE id=?", (cid,))
            conn.commit()


def test_adding_a_source_creates_something_that_actually_fetches(client, auth):
    """A `feeds` row reported a reliability grade and a sync interval and
    imported nothing, for ever, because no fetcher ever read that table. Adding
    a source now creates a connector - the thing the scheduler runs."""
    from dashboard_api.db import get_conn

    r = client.post("/feeds", headers=auth, json={
        "name": "PyTest CSV source", "type": "opensource",
        "url": "https://example.test/indicators.csv", "format": "CSV"})
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    try:
        with get_conn() as conn:
            row = conn.execute("SELECT kind, url, enabled FROM connectors WHERE id=?",
                               (cid,)).fetchone()
        assert row is not None, "the source was not created as a connector"
        assert row["kind"] == "csv", "the declared format must pick the reader"
        assert row["enabled"] == 1
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM connectors WHERE id=?", (cid,))
            conn.commit()

    # A source with nowhere to fetch from is exactly what the old table allowed.
    assert client.post("/feeds", headers=auth,
                       json={"name": "No URL"}).status_code == 400
    # And a format no reader can parse is refused rather than stored.
    assert client.post("/feeds", headers=auth, json={
        "name": "Mystery", "url": "https://example.test/x",
        "format": "carrier pigeon"}).status_code == 400


def test_total_indicators_is_the_stores_count_not_a_sum_of_feed_tallies(client, auth):
    """Per-source tallies double-count every value two feeds both list, which
    after the corroboration work is a large and growing share of the store."""
    from dashboard_api.db import get_conn
    s = client.get("/feeds/summary", headers=auth).json()
    with get_conn() as conn:
        real = conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
    assert s["totalIndicators"] == real
