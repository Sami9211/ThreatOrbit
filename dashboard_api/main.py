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

from dashboard_api.config import AUTO_SEED, CORS_ORIGINS
from dashboard_api.db import get_conn, init_db
from dashboard_api.routers import (
    assets, auth, cti, config as config_router, feeds, overview, services, siem, soar, users,
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


@app.on_event("startup")
def startup():
    from dashboard_api.config import JWT_SECRET
    if JWT_SECRET == "dev-insecure-secret-change-me":
        logger.warning(
            "DASHBOARD_JWT_SECRET is the development default — set a long random "
            "value before exposing this service (e.g. `openssl rand -hex 32`)."
        )
    init_db()
    if AUTO_SEED:
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
          cti.router, assets.router, feeds.router, config_router.router, services.router):
    app.include_router(r)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard_api.main:app", host="127.0.0.1", port=8002, reload=False)
