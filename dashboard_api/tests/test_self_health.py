"""Platform self-health surface + the /ready readiness contract.

Two things under test:

  * ``/ready`` must return HTTP **503** (not a 200 body saying ``ready:false``)
    when the DB is unreachable — otherwise a k8s httpGet readiness probe reads
    the 200 as READY and keeps routing traffic to a broken pod.
  * ``self_health.collect`` derives an honest overall verdict from real
    subsystem signals, degrading only on the gating checks.
"""
from unittest.mock import patch

from dashboard_api import self_health as sh


# ── /ready readiness contract ────────────────────────────────────────────────────

def test_ready_healthy_is_200(client):
    r = client.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] is True
    assert "schema" in body


def test_ready_db_down_is_503(client):
    """The regression fence: DB unreachable ⇒ 503, so the orchestrator pulls
    the pod out of rotation instead of trusting a 200 with ready:false."""
    def boom(*a, **k):
        raise RuntimeError("database is unreachable")

    with patch("dashboard_api.main.get_conn", side_effect=boom):
        r = client.get("/ready")
    assert r.status_code == 503
    assert r.json()["ready"] is False


def test_health_liveness_stays_static(client):
    """Liveness stays a cheap always-200 (don't kill+restart a pod for a DB
    outage a restart can't fix — that's readiness's job)."""
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── verdict logic ─────────────────────────────────────────────────────────────────

def test_worst_ranks_down_over_degraded_over_ok():
    assert sh._worst(["ok", "degraded", "down"]) == "down"
    assert sh._worst(["ok", "degraded"]) == "degraded"
    assert sh._worst(["ok", "ok"]) == "ok"
    # unknown never gates — the real signal lives in the failing check
    assert sh._worst(["ok", "unknown"]) == "ok"
    # nothing measurable succeeded → down
    assert sh._worst(["unknown"]) == "down"


def test_collect_healthy_is_ok(client):
    h = sh.collect()
    assert h["status"] == "ok"
    assert set(h["checks"]) == {"database", "schema", "queue", "leader", "process"}
    assert h["checks"]["database"]["status"] == "ok"
    assert "latencyMs" in h["checks"]["database"]
    assert "generatedAt" in h


def test_collect_db_down_is_down(client):
    def boom(*a, **k):
        raise RuntimeError("no route to host")

    with patch("dashboard_api.self_health.get_conn", side_effect=boom):
        h = sh.collect()
    assert h["status"] == "down"
    assert h["checks"]["database"]["status"] == "down"
    # DB-dependent checks are marked unknown, never fabricated
    assert h["checks"]["schema"]["status"] == "unknown"
    assert h["checks"]["queue"]["status"] == "unknown"


def test_collect_queue_lag_is_degraded(client):
    """A backlog past the lag threshold degrades the verdict without the DB
    being down — the EPS-ceiling signal."""
    over = sh._LAG_WARN + 60
    with patch("dashboard_api.event_queue.stats",
               return_value={"depth": 3, "inFlight": 0, "lagSeconds": over}):
        h = sh.collect()
    assert h["status"] == "degraded"
    assert h["checks"]["queue"]["status"] == "degraded"
    assert "detail" in h["checks"]["queue"]


def test_collect_schema_drift_is_degraded(client):
    with patch("dashboard_api.db.schema_versions", return_value={"code": 4, "db": 3}):
        h = sh.collect()
    assert h["status"] == "degraded"
    assert h["checks"]["schema"]["status"] == "degraded"


# ── /platform/self-health endpoint ────────────────────────────────────────────────

def test_self_health_endpoint_requires_auth(client):
    r = client.get("/self-health")
    assert r.status_code == 401


def test_self_health_endpoint_returns_verdict(client, auth):
    r = client.get("/self-health", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in {"ok", "degraded", "down"}
    assert body["checks"]["database"]["status"] == "ok"
    assert "uptimeSeconds" in body["checks"]["process"]
