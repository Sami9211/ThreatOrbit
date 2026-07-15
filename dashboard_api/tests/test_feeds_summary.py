"""Feeds summary honesty fence.

The feeds/sources "IOCs Today" tile used to sum each feed's nominal daily rate
(and, once live, each feed's *cumulative* indicator total) - never an actual
count of indicators seen today. `newToday` is now a real count of IOCs first
seen since midnight UTC.
"""
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
