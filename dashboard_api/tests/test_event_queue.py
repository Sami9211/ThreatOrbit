"""Durable event-queue (ingest/detection seam) tests.

Proves the lease semantics that let detection become a worker pool without
double-processing - claim is exclusive within the lease, complete clears it,
stale leases re-queue - plus the backpressure signals (depth / lag) and that the
engine's detection path now flows through the queue.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from dashboard_api import event_queue
from dashboard_api.db import get_conn


@pytest.fixture()
def clean_queue():
    """Start each test from an empty queue (benign: marks existing events done)."""
    with get_conn() as conn:
        conn.execute("UPDATE events SET processed=1, claimed_by=NULL, claimed_at=NULL")
        conn.commit()
    yield


def _insert(conn, n, *, ts=None, event_type="failed_login", action="auth_fail"):
    base = (ts or datetime.now(timezone.utc)).isoformat()
    ids = []
    for _ in range(n):
        eid = f"qtest-{uuid.uuid4()}"
        conn.execute(
            "INSERT INTO events (id,ts,category,event_type,action,severity_hint,processed) "
            "VALUES (?,?,?,?,?,?,0)", (eid, base, "test", event_type, action, "high"))
        ids.append(eid)
    return ids


def test_depth_lag_and_stats(clean_queue):
    with get_conn() as conn:
        _insert(conn, 3, ts=datetime.now(timezone.utc) - timedelta(seconds=30))
        conn.commit()
        s = event_queue.stats(conn)
    assert s["depth"] == 3
    assert s["lagSeconds"] >= 25  # ~30s old
    assert s["inFlight"] == 0


def test_claim_is_exclusive_within_lease(clean_queue):
    with get_conn() as conn:
        _insert(conn, 5)
        conn.commit()
        first = event_queue.claim(conn, "worker-1", 3)
        assert len(first) == 3
        first_ids = {r["id"] for r in first}
        # A second worker claiming must not re-grab the leased rows.
        second = event_queue.claim(conn, "worker-2", 10)
        second_ids = {r["id"] for r in second}
        assert first_ids.isdisjoint(second_ids)
        assert len(second_ids) == 2  # the remaining unclaimed events
        assert event_queue.in_flight(conn) == 5


def test_complete_marks_processed_and_clears_lease(clean_queue):
    with get_conn() as conn:
        ids = _insert(conn, 3)
        conn.commit()
        event_queue.claim(conn, "w", 10)
        event_queue.complete(conn, ids)
        conn.commit()
        assert event_queue.depth(conn) == 0
        rows = conn.execute(
            "SELECT processed, claimed_by FROM events WHERE id=?", (ids[0],)).fetchone()
    assert rows["processed"] == 1 and rows["claimed_by"] is None


def test_requeue_stale_releases_dead_worker_leases(clean_queue):
    with get_conn() as conn:
        ids = _insert(conn, 2)
        conn.commit()
        event_queue.claim(conn, "dead-worker", 10)
        # Backdate the lease to simulate a worker that died mid-batch.
        old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        conn.execute("UPDATE events SET claimed_at=? WHERE id IN (?,?)", (old, *ids))
        conn.commit()
        released = event_queue.requeue_stale(conn)
        conn.commit()
        assert released == 2
        # Now re-claimable by a fresh worker.
        again = event_queue.claim(conn, "worker-2", 10)
    assert {r["id"] for r in again} == set(ids)


def test_detection_flows_through_the_queue(clean_queue):
    from dashboard_api.engine import run_detection, seed_builtin_rules
    with get_conn() as conn:
        seed_builtin_rules()
        ids = _insert(conn, 2, event_type="failed_login")  # matches R-BRUTEFORCE
        conn.commit()
        res = run_detection(conn)
        conn.commit()
        assert res["events"] >= 2
        # the leased batch is completed (no longer pending)
        assert event_queue.depth(conn) == 0
        processed = conn.execute(
            "SELECT processed FROM events WHERE id=?", (ids[0],)).fetchone()["processed"]
    assert processed == 1


def test_engine_status_exposes_backpressure(client, auth):
    body = client.get("/config/engine", headers=auth).json()
    assert "queue" in body
    assert set(body["queue"]) >= {"depth", "lagSeconds", "inFlight", "maxBacklog", "shedding"}


# ── bounded ingest queue (429 backpressure) ──────────────────────────────────

def test_ingest_sheds_load_with_429(clean_queue, client, auth, monkeypatch):
    monkeypatch.setattr("dashboard_api.config.INGEST_MAX_BACKLOG", 3)
    with get_conn() as conn:
        _insert(conn, 5)  # backlog 5 ≥ cap 3 → ingest must shed
        conn.commit()
    r = client.post("/siem/ingest", headers=auth, json={
        "lines": ['{"event_type":"failed_login","src_ip":"8.8.8.8"}'],
        "format": "json", "source": "test"})
    assert r.status_code == 429
    assert r.headers.get("Retry-After") == "5"


def test_ingest_accepts_under_backlog(clean_queue, client, auth, monkeypatch):
    monkeypatch.setattr("dashboard_api.config.INGEST_MAX_BACKLOG", 100000)
    r = client.post("/siem/ingest", headers=auth, json={
        "lines": ['{"event_type":"failed_login","src_ip":"8.8.8.8","message":"failed login"}'],
        "format": "json", "source": "test"})
    assert r.status_code == 200, r.text
    assert "ingested" in r.json()
