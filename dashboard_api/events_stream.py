"""In-process pub/sub broker for Server-Sent Events (real-time push).

The live engine runs on a background thread and produces alerts, cases,
notifications and dark-web findings; webhooks/notify() fire on request
threads. Rather than have the UI poll, those producers `publish()` a small
event here, and each connected SSE client holds a thread-safe queue it drains.

Deliberately simple and dependency-free: a set of bounded `queue.Queue`s under
a lock. A slow/dead client's queue fills and is dropped silently (its
connection's heartbeat loop will clean it up), so a stalled browser can never
back-pressure the engine.
"""
import queue
import threading
from datetime import datetime, timezone

# queue -> the subscriber's org (None = untagged). A dict so publish can deliver
# tenant events only to matching subscribers when isolation is enforced.
_subscribers: dict[queue.Queue, str | None] = {}
_lock = threading.Lock()
_MAX_QUEUED = 200


def subscribe(org: str | None = None) -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=_MAX_QUEUED)
    with _lock:
        _subscribers[q] = org
    return q


def unsubscribe(q: queue.Queue) -> None:
    with _lock:
        _subscribers.pop(q, None)


def subscriber_count() -> int:
    with _lock:
        return len(_subscribers)


def publish(event_type: str, data: dict | None = None, org: str | None = None) -> int:
    """Fan a `{type, data, ts}` message out to subscribers. Never raises; returns
    how many it reached. Safe to call from any thread.

    Tenant isolation: when it's enforced, an event with an org (passed explicitly
    or carried as `data['org_id']`) is delivered only to subscribers in that org;
    an event with no org (system-wide, e.g. engine ticks) still reaches everyone.
    When isolation is off, every subscriber receives every event (unchanged)."""
    msg = {"type": event_type, "data": data or {},
           "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat()}
    from dashboard_api import tenancy
    scoped = tenancy.enforced()
    event_org = org if org is not None else (data or {}).get("org_id") if scoped else None
    with _lock:
        subs = list(_subscribers.items())
    delivered = 0
    for q, sub_org in subs:
        # Deliver unless isolation is on AND this is a tenant event for another org.
        if scoped and event_org is not None and sub_org != event_org:
            continue
        try:
            q.put_nowait(msg)
            delivered += 1
        except queue.Full:
            # Drop for a backed-up client; its heartbeat loop will recycle it.
            pass
    return delivered
