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


def test_sources_are_reported_from_connectors_when_the_feeds_table_is_empty(client, auth):
    """The `feeds` table is a vestigial duplicate of `connectors` and is empty by
    design in live mode. Reading it made the Threat Feeds page say "from 0
    sources - No sources configured yet" and "Total IOCs 0" while two connectors
    were actively importing 315,185 indicators - a headline number contradicting
    the panel directly below it.

    The suite SEEDS the feeds table, so this empties it for the duration and puts
    it back. A version of this test that skipped when feeds was populated never
    ran at all, which is worse than not having it.
    """
    import uuid
    from dashboard_api.db import get_conn, rows_to_dicts

    tag = uuid.uuid4().hex[:8]
    cid = f"fs-{tag}"
    with get_conn() as conn:
        saved = rows_to_dicts(conn.execute("SELECT * FROM feeds").fetchall())
        cols = list(saved[0].keys()) if saved else []
        conn.execute("DELETE FROM feeds")
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
        assert mine["derived_from"] == "connector"

        s = client.get("/feeds/summary", headers=auth).json()
        assert s["totalFeeds"] >= 1, "summary still reports zero sources"
        with get_conn() as conn:
            real = conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
        assert s["totalIndicators"] == real, (
            f"summary says {s['totalIndicators']} indicators, store holds {real}")
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM connectors WHERE id=?", (cid,))
            if saved:
                ph = ",".join("?" * len(cols))
                conn.executemany(
                    f"INSERT INTO feeds ({','.join(cols)}) VALUES ({ph})",
                    [tuple(r[c] if not isinstance(r[c], (dict, list))
                           else __import__("json").dumps(r[c]) for c in cols)
                     for r in saved])
            conn.commit()


def test_total_indicators_is_the_stores_count_not_a_sum_of_feed_tallies(client, auth):
    """Per-source tallies double-count every value two feeds both list, which
    after the corroboration work is a large and growing share of the store."""
    from dashboard_api.db import get_conn
    s = client.get("/feeds/summary", headers=auth).json()
    with get_conn() as conn:
        real = conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
    assert s["totalIndicators"] == real
