"""SIEM rule hit-counter honesty fence.

`detection_rules.hits_24h` and `fired_last_7d` are set once at seed/import time
and never updated as the engine fires, so the rules list used to show frozen
numbers. They're now computed live from the alerts each rule produced (matched
on `rule_name`; engine alerts carry a constant `rule_id='R-ENGINE'`).
"""
import uuid
from datetime import datetime, timedelta, timezone

from dashboard_api.db import get_conn


def _insert_alert(conn, rule_name: str, ts_iso: str) -> None:
    conn.execute(
        "INSERT INTO alerts (id,ts,title,severity,status,rule_name) VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), ts_iso, "regression", "high", "new", rule_name),
    )


def test_rule_hit_counters_are_live_windowed(client, auth):
    rules = client.get("/siem/rules", headers=auth).json()
    assert rules
    name = rules[0]["name"]
    base = next(r for r in rules if r["name"] == name)
    base24, base7d = base["hits_24h"], base["fired_last_7d"]

    now = datetime.now(timezone.utc)
    within24 = now.replace(microsecond=0).isoformat()                       # in 24h + 7d
    within7d = (now - timedelta(days=3)).replace(microsecond=0).isoformat() # in 7d only
    old = (now - timedelta(days=10)).replace(microsecond=0).isoformat()     # outside both

    with get_conn() as conn:
        for ts, n in ((within24, 2), (within7d, 3), (old, 4)):
            for _ in range(n):
                _insert_alert(conn, name, ts)
        conn.commit()

    updated = next(r for r in client.get("/siem/rules", headers=auth).json()
                   if r["name"] == name)
    assert updated["hits_24h"] == base24 + 2            # only the 2 within 24h
    assert updated["fired_last_7d"] == base7d + 2 + 3   # 24h + 7d, not the 10-day-old ones
