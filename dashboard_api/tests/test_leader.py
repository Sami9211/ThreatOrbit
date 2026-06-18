"""Leader election for singleton background work (HA).

Pins the lease semantics that keep two app replicas from double-running the
engine tick and scheduler: exactly one holder at a time, renew-in-place,
takeover only after expiry, and graceful release. The contention test simulates
two replicas (distinct holder ids) racing the same lease.
"""
import time

from dashboard_api import leader
from dashboard_api.db import get_conn


def _reset(name):
    with get_conn() as conn:
        conn.execute("DELETE FROM leader_lease WHERE name=?", (name,))
        conn.commit()


def test_single_holder_under_contention():
    name = "test-elect"
    _reset(name)
    a, b = "replica-A:1", "replica-B:2"
    got_a = leader.acquire(name, ttl=60, holder=a)
    got_b = leader.acquire(name, ttl=60, holder=b)
    assert got_a is True and got_b is False        # A wins, B is a follower
    assert leader.is_leader(name, holder=a) is True
    assert leader.is_leader(name, holder=b) is False
    _reset(name)


def test_renew_in_place_keeps_leadership():
    name = "test-renew"
    _reset(name)
    a = "replica-A:1"
    assert leader.acquire(name, ttl=60, holder=a) is True
    # renewing extends our own lease and never hands it off
    assert leader.acquire(name, ttl=60, holder=a) is True
    assert leader.is_leader(name, holder=a) is True
    _reset(name)


def test_takeover_after_expiry():
    name = "test-expire"
    _reset(name)
    a, b = "replica-A:1", "replica-B:2"
    # A holds a lease that already expired (ttl=0 → expires_at = now)
    assert leader.acquire(name, ttl=0, holder=a) is True
    time.sleep(1.1)                                 # let it lapse
    assert leader.is_leader(name, holder=a) is False
    assert leader.acquire(name, ttl=60, holder=b) is True   # B takes over
    assert leader.is_leader(name, holder=b) is True
    assert leader.acquire(name, ttl=60, holder=a) is False  # A is now the follower
    _reset(name)


def test_release_allows_immediate_takeover():
    name = "test-release"
    _reset(name)
    a, b = "replica-A:1", "replica-B:2"
    assert leader.acquire(name, ttl=60, holder=a) is True
    assert leader.acquire(name, ttl=60, holder=b) is False
    leader.release(name, holder=a)                  # graceful shutdown
    assert leader.acquire(name, ttl=60, holder=b) is True   # no need to wait out TTL
    _reset(name)


def test_status_endpoint(client, auth):
    out = client.get("/config/leader", headers=auth)
    assert out.status_code == 200, out.text
    body = out.json()
    assert body["name"] == "background"
    assert "held" in body and "self" in body and "ttlSeconds" in body
