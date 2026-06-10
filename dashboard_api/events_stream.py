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

_subscribers: set[queue.Queue] = set()
_lock = threading.Lock()
_MAX_QUEUED = 200


def subscribe() -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=_MAX_QUEUED)
    with _lock:
        _subscribers.add(q)
    return q


def unsubscribe(q: queue.Queue) -> None:
    with _lock:
        _subscribers.discard(q)


def subscriber_count() -> int:
    with _lock:
        return len(_subscribers)


def publish(event_type: str, data: dict | None = None) -> int:
    """Fan a `{type, data, ts}` message out to every subscriber. Never raises;
    returns how many subscribers it reached. Safe to call from any thread."""
    msg = {"type": event_type, "data": data or {},
           "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat()}
    with _lock:
        subs = list(_subscribers)
    delivered = 0
    for q in subs:
        try:
            q.put_nowait(msg)
            delivered += 1
        except queue.Full:
            # Drop for a backed-up client; its heartbeat loop will recycle it.
            pass
    return delivered
