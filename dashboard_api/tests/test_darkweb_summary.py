"""Dark-web summary honesty fence.

`last24h` used to alias `total` — every finding ever recorded — despite the
name. It now windows on `ts >= now-24h`.
"""
import uuid
from datetime import datetime, timedelta, timezone

from dashboard_api.db import get_conn


def _insert_finding(conn, ts_iso: str) -> None:
    conn.execute(
        "INSERT INTO dark_web_findings (id,ts,category,severity,title,status) "
        "VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), ts_iso, "credential-leak", "high", "regression", "new"),
    )


def test_last24h_windows_to_twenty_four_hours(client, auth):
    now = datetime.now(timezone.utc)
    old = (now - timedelta(hours=30)).replace(microsecond=0).isoformat()   # outside 24h
    recent = (now - timedelta(hours=1)).replace(microsecond=0).isoformat() # inside 24h

    base = client.get("/darkweb/summary", headers=auth).json()["last24h"]
    with get_conn() as conn:
        for _ in range(3):
            _insert_finding(conn, old)
        for _ in range(2):
            _insert_finding(conn, recent)
        conn.commit()

    after = client.get("/darkweb/summary", headers=auth).json()["last24h"]
    assert after == base + 2  # only the 2 findings inside the 24h window count
