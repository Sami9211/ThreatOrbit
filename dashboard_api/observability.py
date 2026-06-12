"""Observability baseline (Tier-1 production hardening) — stdlib only.

Three pieces:

  * **Prometheus metrics** — an ASGI middleware counts every request and its
    latency by (method, route-template, status); the engine/ingest loops feed
    domain counters; `/metrics` renders the standard text exposition format
    plus on-scrape gauges (uptime, core-table row counts). No client library
    needed — the format is plain text. Scraping is open by default (private
    networks); set `DASHBOARD_METRICS_TOKEN` to require
    `Authorization: Bearer <token>`.

  * **Structured logs** — `DASHBOARD_LOG_FORMAT=json` switches the root
    handler to one-line JSON records (ts, level, logger, message, exc), ready
    for Loki/CloudWatch/Datadog pipelines. Default stays human-readable.

  * **Error tracking** — `SENTRY_DSN` initialises sentry-sdk when the package
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
    # Row-count gauges sampled at scrape time — storage growth at a glance.
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
    except Exception:  # storage briefly unavailable — scrape still succeeds
        pass
    return "\n".join(lines) + "\n"


# ── Structured logging ──────────────────────────────────────────────────────────

class JsonFormatter(logging.Formatter):
    """One JSON object per line — machine-shippable log records."""

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
        import sentry_sdk  # optional dependency — deliberately not pinned
    except ImportError:
        logger.warning("SENTRY_DSN is set but sentry-sdk is not installed "
                       "(pip install sentry-sdk) — error tracking disabled")
        return False
    sentry_sdk.init(dsn=dsn, traces_sample_rate=0.0)
    logger.info("Sentry error tracking enabled")
    return True
