"""Multi-worker detection pool — the concurrency-safe drain over the event queue.

The engine's inline tick processes detection with a single worker (engine-0).
To catch up on a large backlog, this runs a POOL of workers that each atomically
CLAIM a batch and process it, with no two workers ever grabbing the same event.

The claim is the only concurrency-critical step. It runs under a write-locked
transaction (SQLite `BEGIN IMMEDIATE` acquires the write lock *before* the
SELECT), so a concurrent claim blocks until the first commits and then sees the
already-claimed rows excluded. Processing reuses the normal detection path
(`run_detection(..., claimed=batch)` on a standard connection), so alert creation
behaves exactly as the inline worker.

At-least-once: if a worker dies after claiming but before completing, the lease
expires and `requeue_stale` re-flows the batch (a re-run may re-alert — the same
durable-queue trade-off the inline lease already documents).
"""
import logging
import threading

from dashboard_api import event_queue
from dashboard_api.config import DETECTION_WORKERS

logger = logging.getLogger("dashboard_api.detection_pool")


def _claim_conn():
    """A dedicated connection in autocommit mode so we can drive BEGIN IMMEDIATE
    explicitly for an atomic claim (SQLite)."""
    from dashboard_api.db import _connect
    conn = _connect()
    try:
        conn.isolation_level = None     # we control BEGIN/COMMIT ourselves
    except Exception:
        pass
    return conn


def claim_locked(conn, worker_id: str, batch: int,
                 lease: int = event_queue.DEFAULT_LEASE) -> list:
    """Atomically claim up to `batch` pending events under a write lock, so two
    workers never claim the same event. Returns the claimed rows (maybe empty)."""
    from dashboard_api.db_backend import is_postgres
    if is_postgres():  # pragma: no cover - the adapter manages its own transaction
        rows = event_queue.claim(conn, worker_id, batch, lease)
        try:
            conn.commit()
        except Exception:
            pass
        return rows
    conn.execute("BEGIN IMMEDIATE")     # write lock acquired here, before the SELECT
    try:
        rows = event_queue.claim(conn, worker_id, batch, lease)
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    return rows


def run_pool(workers: int | None = None, batch: int = 100,
             lease: int = event_queue.DEFAULT_LEASE) -> dict:
    """Drain the pending detection backlog with `workers` concurrent workers.
    Returns aggregate stats `{alerts, events, batches, workers}`. A single worker
    is equivalent to the inline path; the result is identical regardless of the
    worker count (the claim guarantees no overlap)."""
    n = max(1, workers or DETECTION_WORKERS)
    from dashboard_api.db import get_conn
    from dashboard_api.engine import run_detection
    # Recover any leases abandoned by dead workers before draining.
    with get_conn() as conn:
        event_queue.requeue_stale(conn, lease)
        conn.commit()

    totals = {"alerts": 0, "events": 0, "batches": 0}
    lock = threading.Lock()

    def worker(idx: int):
        wid = f"pool-{idx}"
        cconn = _claim_conn()
        local = {"alerts": 0, "events": 0, "batches": 0}
        try:
            while True:
                rows = claim_locked(cconn, wid, batch, lease)
                if not rows:
                    break
                events = [dict(r) for r in rows]
                with get_conn() as pconn:                     # process exactly like the inline path
                    res = run_detection(pconn, claimed=events)
                    pconn.commit()
                local["alerts"] += res.get("alerts", 0)
                local["events"] += res.get("events", 0)
                local["batches"] += 1
        except Exception:
            logger.exception("detection pool worker %s failed", wid)
        finally:
            cconn.close()
            with lock:
                for k in totals:
                    totals[k] += local[k]

    threads = [threading.Thread(target=worker, args=(i,), name=f"detpool-{i}", daemon=True)
               for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    totals["workers"] = n
    return totals
