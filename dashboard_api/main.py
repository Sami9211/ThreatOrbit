"""ThreatOrbit Dashboard API (FastAPI, :8002).

Unified backend powering the operator dashboard: auth + users, SIEM alerts,
SOAR cases/playbooks/integrations, CTI actors/IOCs, asset surface, threat feeds,
and configuration. Backed by WAL-mode SQLite, seeded with realistic demo data
on first run.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from dashboard_api.config import AUTO_SEED, CONNECTOR_TICK_SECONDS, CORS_ALLOWED, CORS_ORIGIN_REGEX, DATA_MODE
from dashboard_api.db import get_conn, init_db
from dashboard_api.routers import (
    assets, assistant as assistant_router, auth, billing as billing_router,
    compliance as compliance_router, connectors as connectors_router, cti,
    config as config_router, darkweb, feeds, overview, platform as platform_router,
    privacy as privacy_router, reports as reports_router, orgs, saml as saml_router,
    scim as scim_router, services, siem, soar, sso as sso_router, stream, taxii,
    roles as roles_router, users,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("dashboard_api")

from dashboard_api import observability  # noqa: E402 (needs logging configured first)

observability.configure_logging()
observability.init_error_tracking()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup work lives in _startup() below (defined later so it can reach the
    # engine/connector helpers); the name resolves at call time. Migrated off the
    # deprecated @app.on_event("startup") hook. Background workers are daemon
    # threads that exit with the process, so there's no shutdown teardown.
    _startup()
    yield


app = FastAPI(title="ThreatOrbit Dashboard API", version="1.0.0", lifespan=lifespan)

app.add_middleware(observability.MetricsMiddleware)
app.add_middleware(observability.SecurityHeadersMiddleware)
# Ingress body cap (DoS): reject an over-large body with 413 before the app
# buffers it. Added after the two above so it wraps them (runs earlier on ingress).
from dashboard_api.config import MAX_BODY_BYTES  # noqa: E402
app.add_middleware(observability.BodySizeLimitMiddleware, max_bytes=MAX_BODY_BYTES)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED,
    # Evaluation posture also accepts private-network origins (LAN IP /
    # intranet hostname) so a non-localhost origin doesn't break every call;
    # production keeps the explicit allowlist. See config.CORS_ORIGIN_REGEX.
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Added last → outermost: rewrite the stable `/v1` alias to the canonical path
# before routing/metrics see it. See dashboard_api/api_versioning.py.
from dashboard_api.api_versioning import ApiVersionMiddleware  # noqa: E402
app.add_middleware(ApiVersionMiddleware)


@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    # Propagate any headers the raiser set (e.g. Retry-After on 429 backpressure,
    # WWW-Authenticate on 401) so clients can honour them.
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail},
                        headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_exc(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"error": "Validation error", "detail": exc.errors()})


@app.exception_handler(Exception)
async def global_exc(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    observability.inc("errors")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


@app.get("/metrics", include_in_schema=False)
def metrics(request: Request):
    """Prometheus text exposition. Open by default (scrapers live on private
    networks); set DASHBOARD_METRICS_TOKEN to require a bearer token."""
    import os
    from fastapi.responses import PlainTextResponse
    token = os.environ.get("DASHBOARD_METRICS_TOKEN", "")
    if token:
        supplied = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
        if supplied != token:
            return JSONResponse(status_code=401, content={"error": "metrics token required"})
    return PlainTextResponse(observability.render_metrics(),
                             media_type="text/plain; version=0.0.4")


def _connector_scheduler():
    """Background loop (live mode): run due connectors so real threat intel
    keeps flowing in without anyone pressing a button."""
    import time
    from dashboard_api.connectors import run_due_connectors
    from dashboard_api import leader
    # Small initial delay so the companion services have time to come up.
    time.sleep(8)
    while True:
        # HA: only the leader replica runs scheduled work, or two nodes would
        # double-import connectors and double-deliver reports. (is_leader, not
        # acquire - the engine loop renews the shared lease.)
        if not leader.is_leader():
            time.sleep(CONNECTOR_TICK_SECONDS)
            continue
        try:
            from dashboard_api.routers.platform import run_due_report_schedules
            run_due_report_schedules()
        except Exception:
            logger.exception("Report schedule tick failed")
        try:
            ran = run_due_connectors()
            for r in ran:
                if "error" in r:
                    logger.warning("Connector %s failed: %s", r.get("connector"), r["error"])
                elif r.get("imported"):
                    logger.info("Connector %s imported %d indicators", r.get("connector"), r["imported"])
        except Exception:  # never let the scheduler thread die
            logger.exception("Connector scheduler tick failed")
        try:  # agentless S3 log pull (no-op unless configured; honours its own interval)
            from dashboard_api.s3_pull import poll_if_configured
            poll_if_configured()
        except Exception:
            logger.exception("S3 pull tick failed")
        time.sleep(CONNECTOR_TICK_SECONDS)


def _engine_loop():
    """Background loop (live mode): the live processing engine. Generates
    environment telemetry and runs it through detect → correlate → escalate,
    so SIEM/SOAR/CTI/Dark-Web fill with live data continuously. Honours the
    engine_enabled setting so it can be paused from the UI."""
    import time
    from dashboard_api.engine import process_tick
    from dashboard_api.config import ENGINE_TICK_SECONDS, ENGINE_EVENTS_PER_TICK
    from dashboard_api import leader
    time.sleep(5)
    while True:
        try:
            # HA: the engine loop also drives leader election - acquire/renew the
            # shared lease each tick. A follower (someone else holds a live lease)
            # idles, so exactly one replica generates telemetry.
            if not leader.acquire():
                time.sleep(ENGINE_TICK_SECONDS)
                continue
            with get_conn() as conn:
                row = conn.execute("SELECT value FROM settings WHERE key='engine_enabled'").fetchone()
            enabled = (row is None) or (row["value"] != "false")
            if enabled:
                s = process_tick(max_events=ENGINE_EVENTS_PER_TICK)
                logger.info("Engine tick: %d events → %d alerts, %d IOCs, %d dark-web, %d cases",
                            s["events"], s["alerts"], s["iocs"], s["darkWeb"], s["casesEscalated"])
                observability.inc("engine_ticks")
                observability.inc("engine_events", s["events"])
                observability.inc("engine_alerts", s["alerts"])
        except Exception:
            logger.exception("Engine tick failed")
            observability.inc("engine_tick_failures")
        time.sleep(ENGINE_TICK_SECONDS)


def _health_monitor():
    """Background loop (live mode): watch the platform's *own* health and alert
    the notification centre on a verdict transition (ok→degraded→down and
    recovery). Leadership is checked read-only (`is_leader`, not `acquire`) so it
    never fights the engine loop's lease - exactly one replica alerts. Disabled
    when DASHBOARD_HEALTH_MONITOR_SECONDS<=0."""
    import time
    from dashboard_api import leader, self_health
    if self_health.MONITOR_SECONDS <= 0:
        logger.info("Self-health monitor disabled (DASHBOARD_HEALTH_MONITOR_SECONDS<=0)")
        return
    time.sleep(10)  # let the first engine tick claim leadership before we sample
    while True:
        try:
            if leader.is_leader():
                self_health.monitor_once()
        except Exception:
            logger.exception("Self-health monitor tick failed")
        time.sleep(self_health.MONITOR_SECONDS)


def _apply_engine_mode() -> bool:
    """Boot-time application of DASHBOARD_ENGINE. In real-data mode ("off") the
    engine is paused on EVERY start - the operator's env wins at boot, while the
    UI toggle can still resume it deliberately until the next restart. Returns
    True when synthetic telemetry is disabled."""
    from dashboard_api.config import ENGINE_MODE
    if ENGINE_MODE != "off":
        return False
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) "
                     "VALUES ('engine_enabled','false')")
        conn.commit()
    logger.info("Real-data mode (DASHBOARD_ENGINE=off): synthetic engine disabled; "
                "only ingested/connector data will appear")
    return True


def _startup():
    import threading
    # JWT_SECRET is now always a strong value: an explicit env var, or a
    # per-install random secret generated and persisted by config.py (never the
    # old shared default). DASHBOARD_REQUIRE_SECRETS makes an explicit value
    # mandatory in production.
    init_db()
    # Guardrail: a multi-worker detection pool has NO throughput benefit on
    # SQLite (single writer) and measurably regresses it under lock contention -
    # it only helps on Postgres (docs/LOAD_LIMITS.md). Warn an operator who set
    # workers > 1 on the default SQLite backend so they don't silently footgun.
    try:
        from dashboard_api.config import DETECTION_WORKERS
        from dashboard_api import db_backend
        if DETECTION_WORKERS > 1 and not db_backend.is_postgres():
            logger.warning(
                "DASHBOARD_DETECTION_WORKERS=%d on SQLite has no benefit and is "
                "slightly slower (single writer). Use 1 worker on SQLite, or the "
                "Postgres backend to scale detection. See docs/LOAD_LIMITS.md.",
                DETECTION_WORKERS)
    except Exception:
        pass
    # Secrets-at-rest migration: encrypt any legacy plaintext credentials.
    try:
        from dashboard_api.db import get_conn
        from dashboard_api.secretstore import encrypt_existing
        with get_conn() as conn:
            encrypt_existing(conn)
            conn.commit()
    except Exception:
        logger.exception("Secret encryption migration failed")
    if DATA_MODE == "live":
        from dashboard_api.seed import bootstrap_live
        from dashboard_api.connectors import seed_builtin_connectors
        first_boot = bootstrap_live()
        # Built-in content first (idempotent), so the engine's detection rules
        # and the SOAR automation playbooks exist before any tick runs.
        seed_builtin_connectors()
        from dashboard_api.engine import seed_builtin_rules
        seed_builtin_rules()
        from dashboard_api.playbook_engine import seed_builtin_playbooks
        seed_builtin_playbooks()
        engine_off = _apply_engine_mode()
        if first_boot:
            logger.info("Live mode: bootstrapped admin + settings (no demo data)")
        if first_boot and not engine_off:
            # Prime the stores so the first login isn't an empty screen - these
            # are live engine ticks (real pipeline), not static seed data.
            try:
                from dashboard_api.engine import process_tick
                from dashboard_api.scoring import recompute_asset_risk
                for _ in range(25):
                    process_tick()
                with get_conn() as conn:
                    recompute_asset_risk(conn)
                    conn.commit()
                logger.info("Live mode: primed initial telemetry via the engine")
            except Exception:
                logger.exception("Initial engine prime failed")
        threading.Thread(target=_connector_scheduler, daemon=True).start()
        threading.Thread(target=_engine_loop, daemon=True).start()
        threading.Thread(target=_health_monitor, daemon=True).start()
        # Long-running log collectors (syslog UDP + file/dir watcher), if configured.
        try:
            from dashboard_api.log_listeners import start_listeners
            started = start_listeners()
            if started["syslog"] or started["fileWatch"]:
                logger.info("Live mode: log collectors started %s", started)
        except Exception:
            logger.exception("Log collectors failed to start")
        logger.info("Live mode: connector scheduler + live engine started")
    elif AUTO_SEED:
        from dashboard_api.seed import seed
        if seed():
            logger.info("Database seeded with demo data")


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "dashboard_api"}


@app.get("/ready", tags=["meta"])
def ready(response: Response):
    """Readiness probe (k8s/LB). Returns HTTP 503 - not 200 - when the DB is
    unreachable, so an orchestrator pulls the pod out of rotation instead of
    routing traffic to an instance that can't serve it. A 200 body with
    ``ready:false`` looks READY to an httpGet probe; that was the bug."""
    try:
        from dashboard_api.db import schema_versions
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"ready": True, "schema": schema_versions()}
    except Exception as e:
        response.status_code = 503
        return {"ready": False, "error": str(e)}


for r in (auth.router, users.router, overview.router, siem.router, soar.router,
          cti.router, assets.router, feeds.router, config_router.router, services.router,
          connectors_router.router, darkweb.router, reports_router.router,
          platform_router.router, taxii.router, stream.router, orgs.router,
          assistant_router.router, billing_router.router, sso_router.router,
          scim_router.router, saml_router.router, compliance_router.router,
          privacy_router.router, roles_router.router):
    app.include_router(r)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard_api.main:app", host="127.0.0.1", port=8002, reload=False)
