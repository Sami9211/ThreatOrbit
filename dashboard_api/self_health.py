"""Platform self-health — the SOC watching its own vitals.

Aggregates real, cheap subsystem signals into one verdict so operators (and the
UI) can answer "is the platform itself healthy right now?" — the piece plan.md
called out as missing (alerting on the platform's *own* health).

Every number here is measured, never assumed:

  * **database** — a real ``SELECT 1`` with its round-trip latency
  * **schema**   — code vs. on-disk migration version (drift ⇒ degraded)
  * **queue**    — detection backlog depth + lag of the oldest pending event
  * **leader**   — background-work lease snapshot (informational)
  * **process**  — uptime + cumulative error/engine counters (informational)

The overall verdict is the worst *gating* check: database down ⇒ ``down``;
schema drift or a queue past its thresholds ⇒ ``degraded``; otherwise ``ok``.
Informational checks (leader, process) never gate — a follower that holds no
lease is perfectly healthy, and cumulative counters are context, not a verdict.
Thresholds are env-tunable so a high-throughput deployment can widen them.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from dashboard_api import observability
from dashboard_api.db import get_conn

OK, DEGRADED, DOWN, UNKNOWN = "ok", "degraded", "down", "unknown"
_RANK = {OK: 0, DEGRADED: 1, DOWN: 2}

# Backpressure thresholds (env-tunable). Defaults are generous: a healthy live
# pipeline drains within seconds, so 300s of lag or a 10k backlog means the
# detection loop is falling behind — worth flagging degraded, not down.
_LAG_WARN = float(os.environ.get("DASHBOARD_HEALTH_LAG_SECONDS", "300"))
_DEPTH_WARN = int(os.environ.get("DASHBOARD_HEALTH_QUEUE_DEPTH", "10000"))


def _worst(statuses) -> str:
    """Worst status among the gating checks (down > degraded > ok). Statuses
    outside the rank table (e.g. ``unknown``) don't gate — the check that
    caused them, such as ``database=down``, already carries the real signal."""
    ranked = [s for s in statuses if s in _RANK]
    if not ranked:
        return DOWN  # nothing measurable succeeded → treat as down
    return max(ranked, key=lambda s: _RANK[s])


def _schema_check() -> dict:
    """Code schema version vs. the version stored in the DB. They match at
    runtime on a healthy install (init migrates up / refuses to start on a
    newer DB); reporting it anyway catches a hand-migrated or half-upgraded
    node before it corrupts data."""
    from dashboard_api.db import schema_versions
    v = schema_versions()
    code, db = v.get("code"), v.get("db")
    if db is None:
        return {"status": DOWN, "code": code, "db": db, "detail": "schema uninitialised"}
    if db != code:
        return {"status": DEGRADED, "code": code, "db": db, "detail": "migration drift"}
    return {"status": OK, "code": code, "db": db}


def _queue_check(conn) -> dict:
    """Detection backpressure: backlog depth + age of the oldest pending event.
    Both are 0 on an idle/demo instance; sustained lag or a deep backlog is the
    EPS-ceiling signal an operator needs to see."""
    from dashboard_api import event_queue
    s = event_queue.stats(conn)
    reasons = []
    status = OK
    if s["lagSeconds"] > _LAG_WARN:
        status = DEGRADED
        reasons.append(f"lag {s['lagSeconds']}s > {_LAG_WARN:.0f}s")
    if s["depth"] > _DEPTH_WARN:
        status = DEGRADED
        reasons.append(f"backlog {s['depth']} > {_DEPTH_WARN}")
    out = {"status": status, **s,
           "thresholds": {"lagSeconds": _LAG_WARN, "depth": _DEPTH_WARN}}
    if reasons:
        out["detail"] = "; ".join(reasons)
    return out


def _leader_check() -> dict:
    """Background-work lease snapshot (informational). A single-replica install
    is always its own leader; a follower simply holds no lease — neither is a
    fault, so this never gates the verdict."""
    try:
        from dashboard_api import leader
        st = leader.status()
        return {"status": OK, "isLeader": st["isSelf"], "holder": st["holder"],
                "electionEnabled": st["electionEnabled"],
                "expiresInSeconds": st["expiresInSeconds"]}
    except Exception as e:  # pragma: no cover - leader table missing pre-init
        return {"status": UNKNOWN, "error": str(e)[:200]}


def _process_check() -> dict:
    """Uptime + cumulative domain counters (informational). Counters are
    monotonic totals since process start, not a rate — context for the verdict,
    never the verdict itself."""
    snap = observability.counters_snapshot()
    return {
        "status": OK,
        "uptimeSeconds": int(observability.uptime_seconds()),
        "errors": snap.get("errors", 0),
        "engineTicks": snap.get("engine_ticks", 0),
        "engineTickFailures": snap.get("engine_tick_failures", 0),
        "ingestedEvents": snap.get("ingested_events", 0),
    }


def collect() -> dict:
    """Snapshot every subsystem and derive the overall verdict.

    Opens one connection and reuses it for the DB-dependent checks. If the DB
    is unreachable the database check reports ``down`` and the checks that need
    it are marked ``unknown`` rather than fabricated — the caller still gets a
    truthful ``down`` verdict."""
    checks: dict[str, dict] = {}
    t0 = time.perf_counter()
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1").fetchone()
            latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            checks["database"] = {"status": OK, "latencyMs": latency_ms}
            checks["schema"] = _schema_check()
            checks["queue"] = _queue_check(conn)
    except Exception as e:
        checks["database"] = {"status": DOWN, "error": str(e)[:200]}
        checks.setdefault("schema", {"status": UNKNOWN})
        checks.setdefault("queue", {"status": UNKNOWN})

    checks["leader"] = _leader_check()
    checks["process"] = _process_check()

    overall = _worst(checks[k]["status"] for k in ("database", "schema", "queue"))
    return {
        "status": overall,
        "checks": checks,
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
