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
    assets, auth, connectors as connectors_router, cti, config as config_router,
    feeds, overview, services, siem, soar, users,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("dashboard_api")

app = FastAPI(title="ThreatOrbit Dashboard API", version="1.0.0")

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
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


def _connector_scheduler():
    """Background loop (live mode): run due connectors so real threat intel
    keeps flowing in without anyone pressing a button."""
    import time
    from dashboard_api.connectors import run_due_connectors
    # Small initial delay so the companion services have time to come up.
    time.sleep(8)
    while True:
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


@app.on_event("startup")
def startup():
    import threading
    from dashboard_api.config import JWT_SECRET
    if JWT_SECRET == "dev-insecure-secret-change-me":
        logger.warning(
            "DASHBOARD_JWT_SECRET is the development default — set a long random "
            "value before exposing this service (e.g. `openssl rand -hex 32`)."
        )
    init_db()
    if DATA_MODE == "live":
        from dashboard_api.seed import bootstrap_live
        from dashboard_api.connectors import seed_builtin_connectors
        if bootstrap_live():
            logger.info("Live mode: bootstrapped admin + settings (no demo data)")
        seed_builtin_connectors()
        threading.Thread(target=_connector_scheduler, daemon=True).start()
        logger.info("Live mode: connector scheduler started (tick=%ss)", CONNECTOR_TICK_SECONDS)
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
          connectors_router.router):
    app.include_router(r)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard_api.main:app", host="127.0.0.1", port=8002, reload=False)
