"""Durable event queue over the `events` table - the ingest/detection seam.

Detection currently runs inline in the engine tick (one worker). To lift the
single-table EPS ceiling, detection needs to become a POOL of workers that each
CLAIM a batch, process it, and COMPLETE it - without two workers ever grabbing
the same event. This module is that seam:

  * `claim`    - mark a batch of pending events as owned by a worker (a lease);
  * `complete` - mark a processed batch done and drop the lease;
  * `requeue_stale` - release leases from workers that died mid-batch;
  * `depth` / `oldest_pending_seconds` - backpressure signals (backlog + lag).

Backed by the WAL-SQLite `events` table today (claimed_by / claimed_at columns);
the claim/complete contract is the interface a Redis/Kafka backend would
implement later. The engine routes its single inline worker ("engine-0") through
here, so behaviour is unchanged while the seam + backpressure metrics exist.

NOTE (next increment): a multi-worker pool needs each claim to run in its own
write-locked transaction (BEGIN IMMEDIATE / isolation_level=None) so concurrent
claims can't overlap; the engine connection uses SQLite's default auto-txn, fine
for the single inline worker here.
"""
from datetime import datetime, timedelta, timezone

DEFAULT_LEASE = 300  # seconds a claim is held before it's considered abandoned


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def claim(conn, worker_id: str, batch: int, lease_seconds: int = DEFAULT_LEASE) -> list:
    """Claim up to `batch` pending events for `worker_id` and return the rows.

    Picks events that are unprocessed and either unclaimed or whose lease has
    expired (so a crashed worker's events re-flow). Newest-first, matching the
    engine's existing order.
    """
    cutoff = _iso(_now() - timedelta(seconds=lease_seconds))
    rows = conn.execute(
        "SELECT * FROM events WHERE processed=0 AND (claimed_by IS NULL OR claimed_at < ?) "
        "ORDER BY ts DESC LIMIT ?", (cutoff, batch)).fetchall()
    ids = [r["id"] for r in rows]
    if ids:
        ph = ",".join("?" * len(ids))
        conn.execute(f"UPDATE events SET claimed_by=?, claimed_at=? WHERE id IN ({ph})",
                     (worker_id, _iso(_now()), *ids))
    return rows


def complete(conn, ids) -> None:
    """Mark a processed batch done and release its lease."""
    ids = list(ids)
    if ids:
        conn.executemany("UPDATE events SET processed=1, claimed_by=NULL WHERE id=?",
                         [(i,) for i in ids])


def requeue_stale(conn, lease_seconds: int = DEFAULT_LEASE) -> int:
    """Release leases held longer than the lease window (dead workers). Returns
    the number of events put back on the queue."""
    cutoff = _iso(_now() - timedelta(seconds=lease_seconds))
    cur = conn.execute(
        "UPDATE events SET claimed_by=NULL WHERE processed=0 AND claimed_by IS NOT NULL "
        "AND claimed_at < ?", (cutoff,))
    return cur.rowcount or 0


def depth(conn) -> int:
    """Pending (unprocessed) events - the detection backlog."""
    return conn.execute("SELECT COUNT(*) c FROM events WHERE processed=0").fetchone()["c"]


def in_flight(conn) -> int:
    """Currently-claimed-but-not-done events (work in progress across workers)."""
    return conn.execute(
        "SELECT COUNT(*) c FROM events WHERE processed=0 AND claimed_by IS NOT NULL"
    ).fetchone()["c"]


def oldest_pending_seconds(conn, now: datetime | None = None) -> float:
    """Age of the oldest unprocessed event - the detection lag. 0 when empty."""
    row = conn.execute("SELECT MIN(ts) m FROM events WHERE processed=0").fetchone()
    if not row or not row["m"]:
        return 0.0
    try:
        t = datetime.fromisoformat(str(row["m"]))
    except ValueError:
        return 0.0
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - t).total_seconds())


def stats(conn) -> dict:
    """Backpressure snapshot for the API + metrics."""
    return {"depth": depth(conn), "inFlight": in_flight(conn),
            "lagSeconds": round(oldest_pending_seconds(conn), 1)}
