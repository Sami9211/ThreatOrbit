"""Multi-worker detection pool: a concurrency-safe drain over the event queue.

The decisive invariant is that a multi-worker drain yields the SAME alerts as a
single-worker drain of identical input - i.e. no event is claimed (and so
alerted on) twice, and none is missed - regardless of how the work is sharded.
"""
import uuid

from dashboard_api.db import get_conn
from dashboard_api.detection_pool import run_pool


def _seed_egress(marker: str, k: int):
    """k unprocessed events that each trip the 'Large Outbound Data Transfer'
    pack rule (bytes_out > 50MB), with distinct entities so each yields one alert."""
    with get_conn() as conn:
        for i in range(k):
            conn.execute(
                "INSERT INTO events (id,ts,category,event_type,src_ip,bytes_out,raw,processed) "
                "VALUES (?,?,?,?,?,?,?,0)",
                (f"ev-{marker}-{i}", "2026-06-01T00:00:00+00:00", "network", "large_egress",
                 f"10.66.{i // 256}.{i % 256}", 60_000_000, marker))
        conn.commit()


def _alerts_with(marker: str) -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) c FROM alerts WHERE description LIKE ?",
                            (f"%{marker}%",)).fetchone()["c"]


def test_pool_drain_matches_single_worker(client, auth):
    client.post("/siem/rules/load-pack", headers=auth)        # ensure the egress rule exists

    m1 = "POOL1" + uuid.uuid4().hex[:6]
    _seed_egress(m1, 20)
    run_pool(workers=1, batch=4)
    a1 = _alerts_with(m1)

    m6 = "POOL6" + uuid.uuid4().hex[:6]
    _seed_egress(m6, 20)
    r6 = run_pool(workers=6, batch=4)                          # real contention: 5 batches / 6 workers
    a6 = _alerts_with(m6)

    assert a1 > 0, "baseline produced no alerts - rule not matching"
    assert a6 == a1, f"multi-worker drift: 1-worker={a1}, 6-worker={a6} (double-processing?)"
    assert r6["workers"] == 6

    # both batches fully drained - nothing left pending
    with get_conn() as conn:
        pending = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE raw IN (?,?) AND processed=0", (m1, m6)).fetchone()["c"]
    assert pending == 0


def test_drain_endpoint(client, auth):
    marker = "DRAIN" + uuid.uuid4().hex[:6]
    _seed_egress(marker, 8)
    r = client.post("/siem/detection/drain?workers=4", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["workers"] == 4 and body["events"] >= 8
    with get_conn() as conn:
        pending = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE raw=? AND processed=0", (marker,)).fetchone()["c"]
    assert pending == 0
