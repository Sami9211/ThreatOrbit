"""Observability baseline (Tier-1 production hardening) - stdlib only.

Three pieces:

  * **Prometheus metrics** - an ASGI middleware counts every request and its
    latency by (method, route-template, status); the engine/ingest loops feed
    domain counters; `/metrics` renders the standard text exposition format
    plus on-scrape gauges (uptime, core-table row counts). No client library
    needed - the format is plain text. Scraping is open by default (private
    networks); set `DASHBOARD_METRICS_TOKEN` to require
    `Authorization: Bearer <token>`.

  * **Structured logs** - `DASHBOARD_LOG_FORMAT=json` switches the root
    handler to one-line JSON records (ts, level, logger, message, exc), ready
    for Loki/CloudWatch/Datadog pipelines. Default stays human-readable.

  * **Error tracking** - `SENTRY_DSN` initialises sentry-sdk when the package
    is installed; if it isn't, we say so once instead of pretending.
    Unhandled exceptions are counted in `threatorbit_errors_total` either way.
"""
import json
import logging
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

logger = logging.getLogger("dashboard_api.observability")

_START = time.time()
_LOCK = threading.Lock()

# (method, path_template, status) → count / latency-sum
_REQUESTS: dict[tuple[str, str, str], int] = defaultdict(int)
_LATENCY_SUM: dict[tuple[str, str, str], float] = defaultdict(float)
_COUNTERS: dict[str, int] = defaultdict(int)  # domain counters (engine/ingest/errors)

# Core tables surfaced as row-count gauges on scrape (cheap COUNT(*)s).
_GAUGE_TABLES = ("alerts", "events", "cases", "iocs", "assets", "users")


def inc(counter: str, by: int = 1) -> None:
    """Bump a domain counter (engine ticks, ingested events, errors, …)."""
    with _LOCK:
        _COUNTERS[counter] += by


def record_request(method: str, path: str, status: int, seconds: float) -> None:
    key = (method, path, str(status))
    with _LOCK:
        _REQUESTS[key] += 1
        _LATENCY_SUM[key] += seconds


def counters_snapshot() -> dict[str, int]:
    """Point-in-time copy of the domain counters (engine/ingest/errors). Used
    by the self-health surface — reads under the same lock the writers use."""
    with _LOCK:
        return dict(_COUNTERS)


def uptime_seconds() -> float:
    """Seconds since the API process started (same clock as /metrics)."""
    return time.time() - _START


class BodySizeLimitMiddleware:
    """Pure-ASGI ingress body cap (DoS guard). Rejects an over-large request
    body with 413 BEFORE the app buffers it into memory — the line-count check
    inside /siem/ingest runs only after the whole body is read/parsed, so
    without this a multi-GB POST (or one enormous line) exhausts memory first.

    Two layers: a fast reject on a declared `content-length`, plus a streaming
    byte counter that trips even when the length is absent or understated
    (chunked / lying clients). GET-like requests carry no body and pass through.
    """

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send):
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body",
                    "body": b'{"error":"Request body too large"}'})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.max_bytes <= 0:
            return await self.app(scope, receive, send)
        # Fast path: a declared content-length over the cap is rejected outright.
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        return await self._reject(send)
                except ValueError:
                    pass
                break

        counted = 0
        too_big = False

        async def receive_capped():
            # Bounds memory even when content-length is absent/understated
            # (chunked or lying clients): once the cap trips we stop handing bytes
            # to the app and signal end-of-body, so it can buffer at most
            # ~max_bytes + one chunk rather than the whole payload.
            nonlocal counted, too_big
            if too_big:
                return {"type": "http.request", "body": b"", "more_body": False}
            message = await receive()
            if message["type"] == "http.request":
                counted += len(message.get("body", b""))
                if counted > self.max_bytes:
                    too_big = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        # Prefer a clean 413 when the app hasn't already responded (the
        # content-length fast path covers well-behaved clients cleanly).
        started = {"v": False}

        async def send_guard(message):
            if message["type"] == "http.response.start":
                started["v"] = True
            await send(message)

        await self.app(scope, receive_capped, send_guard)
        if too_big and not started["v"]:
            await self._reject(send)


class MetricsMiddleware:
    """Pure-ASGI middleware (no BaseHTTPMiddleware buffering): times every
    request and records it under the resolved route template, so
    /siem/alerts/{alert_id} aggregates as one series, not one per id."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = time.perf_counter()
        status_holder = {"status": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            path = getattr(route, "path", None) or scope.get("path", "?")
            record_request(scope.get("method", "?"), path, status_holder["status"],
                           time.perf_counter() - started)


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"')


def render_metrics() -> str:
    """The Prometheus text exposition document."""
    lines = [
        "# HELP threatorbit_uptime_seconds Seconds since the API process started",
        "# TYPE threatorbit_uptime_seconds gauge",
        f"threatorbit_uptime_seconds {time.time() - _START:.0f}",
        "# HELP threatorbit_requests_total HTTP requests by method/route/status",
        "# TYPE threatorbit_requests_total counter",
    ]
    with _LOCK:
        req = dict(_REQUESTS)
        lat = dict(_LATENCY_SUM)
        counters = dict(_COUNTERS)
    for (m, p, s), n in sorted(req.items()):
        lines.append(f'threatorbit_requests_total{{method="{_esc(m)}",path="{_esc(p)}",status="{s}"}} {n}')
    lines += ["# HELP threatorbit_request_seconds_sum Cumulative request latency",
              "# TYPE threatorbit_request_seconds_sum counter"]
    for (m, p, s), v in sorted(lat.items()):
        lines.append(f'threatorbit_request_seconds_sum{{method="{_esc(m)}",path="{_esc(p)}",status="{s}"}} {v:.4f}')
    lines += ["# HELP threatorbit_domain_total Domain event counters",
              "# TYPE threatorbit_domain_total counter"]
    for name, n in sorted(counters.items()):
        lines.append(f'threatorbit_domain_total{{counter="{_esc(name)}"}} {n}')
    # Row-count gauges sampled at scrape time - storage growth at a glance.
    lines += ["# HELP threatorbit_table_rows Current row count of core tables",
              "# TYPE threatorbit_table_rows gauge"]
    try:
        from dashboard_api.db import get_conn
        with get_conn() as conn:
            for t in _GAUGE_TABLES:
                try:
                    n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    lines.append(f'threatorbit_table_rows{{table="{t}"}} {n}')
                except Exception:
                    continue
            # Event-queue backpressure: detection backlog + lag - the EPS-ceiling
            # signal, so an operator can SEE the pipeline falling behind.
            try:
                from dashboard_api import event_queue
                s = event_queue.stats(conn)
                lines += [
                    "# HELP threatorbit_event_queue_depth Pending (unprocessed) events",
                    "# TYPE threatorbit_event_queue_depth gauge",
                    f"threatorbit_event_queue_depth {s['depth']}",
                    "# HELP threatorbit_event_queue_lag_seconds Age of the oldest pending event",
                    "# TYPE threatorbit_event_queue_lag_seconds gauge",
                    f"threatorbit_event_queue_lag_seconds {s['lagSeconds']}",
                ]
            except Exception:
                pass
    except Exception:  # storage briefly unavailable - scrape still succeeds
        pass
    return "\n".join(lines) + "\n"


class SecurityHeadersMiddleware:
    """Baseline security headers on every API response (Tier-1 hardening).

    The API serves JSON to authenticated clients, so the conservative set is
    safe everywhere: no MIME sniffing, no framing, no referrer leakage, and
    no intermediary caching of (often sensitive) responses. The static
    frontend's CSP/HSTS belong to whatever serves it - see docs/DEPLOYMENT.md
    for the reverse-proxy reference configs."""

    _HEADERS = [
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"cache-control", b"no-store"),
    ]

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                headers += [(k, v) for k, v in self._HEADERS if k not in present]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ── Structured logging ──────────────────────────────────────────────────────────

class JsonFormatter(logging.Formatter):
    """One JSON object per line - machine-shippable log records."""

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
                  .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False)


def configure_logging() -> None:
    """Apply DASHBOARD_LOG_FORMAT=json to the root handlers (idempotent)."""
    if os.environ.get("DASHBOARD_LOG_FORMAT", "").lower() != "json":
        return
    formatter = JsonFormatter()
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)
    logger.info("Structured JSON logging enabled")


# ── Error tracking ──────────────────────────────────────────────────────────────

def init_error_tracking() -> bool:
    """Initialise Sentry when SENTRY_DSN is set AND sentry-sdk is installed.
    Honest about absence: logs why it is off instead of silently no-opping."""
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk  # optional dependency - deliberately not pinned
    except ImportError:
        logger.warning("SENTRY_DSN is set but sentry-sdk is not installed "
                       "(pip install sentry-sdk) - error tracking disabled")
        return False
    sentry_sdk.init(dsn=dsn, traces_sample_rate=0.0)
    logger.info("Sentry error tracking enabled")
    return True
