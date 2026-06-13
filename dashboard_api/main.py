"""ThreatOrbit Dashboard API (FastAPI, :8002).

Unified backend powering the operator dashboard: auth + users, SIEM alerts,
SOAR cases/playbooks/integrations, CTI actors/IOCs, asset surface, threat feeds,
and configuration. Backed by WAL-mode SQLite, seeded with realistic demo data
on first run.
"""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from dashboard_api.config import AUTO_SEED, CONNECTOR_TICK_SECONDS, CORS_ORIGINS, DATA_MODE
from dashboard_api.db import get_conn, init_db
from dashboard_api.routers import (
    assets, assistant as assistant_router, auth, connectors as connectors_router, cti,
    config as config_router, darkweb, feeds, overview, platform as platform_router,
    reports as reports_router, orgs, services, siem, soar, stream, taxii, users,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("dashboard_api")

from dashboard_api import observability  # noqa: E402 (needs logging configured first)

observability.configure_logging()
observability.init_error_tracking()

app = FastAPI(title="ThreatOrbit Dashboard API", version="1.0.0")

app.add_middleware(observability.MetricsMiddleware)
app.add_middleware(observability.SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in CORS_ORIGINS.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


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
    # Small initial delay so the companion services have time to come up.
    time.sleep(8)
    while True:
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
        time.sleep(CONNECTOR_TICK_SECONDS)


def _engine_loop():
    """Background loop (live mode): the live processing engine. Generates
    environment telemetry and runs it through detect → correlate → escalate,
    so SIEM/SOAR/CTI/Dark-Web fill with live data continuously. Honours the
    engine_enabled setting so it can be paused from the UI."""
    import time
    from dashboard_api.engine import process_tick
    from dashboard_api.config import ENGINE_TICK_SECONDS, ENGINE_EVENTS_PER_TICK
    time.sleep(5)
    while True:
        try:
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


@app.on_event("startup")
def startup():
    import threading
    from dashboard_api.config import JWT_SECRET
    if JWT_SECRET == "dev-insecure-secret-change-me":
        logger.warning(
            "DASHBOARD_JWT_SECRET is the development default - set a long random "
            "value before exposing this service (e.g. `openssl rand -hex 32`)."
        )
    init_db()
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
        if first_boot:
            logger.info("Live mode: bootstrapped admin + settings (no demo data)")
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
def ready():
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"ready": True}
    except Exception as e:  # pragma: no cover
        return {"ready": False, "error": str(e)}


for r in (auth.router, users.router, overview.router, siem.router, soar.router,
          cti.router, assets.router, feeds.router, config_router.router, services.router,
          connectors_router.router, darkweb.router, reports_router.router,
          platform_router.router, taxii.router, stream.router, orgs.router,
          assistant_router.router):
    app.include_router(r)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard_api.main:app", host="127.0.0.1", port=8002, reload=False)
