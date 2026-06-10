"""Environment-driven configuration for the ThreatOrbit dashboard API.

All secrets and tunables come from environment variables with sensible
development defaults so the service runs out-of-the-box for local testing.
"""
import os

# --- Database ---------------------------------------------------------------
DB_PATH = os.environ.get("DASHBOARD_DB_PATH", os.path.join(os.path.dirname(__file__), "dashboard.db"))

# --- Auth / JWT -------------------------------------------------------------
# In production set DASHBOARD_JWT_SECRET to a long random value.
JWT_SECRET = os.environ.get("DASHBOARD_JWT_SECRET", "dev-insecure-secret-change-me")
JWT_ALG = "HS256"
JWT_TTL_MINUTES = int(os.environ.get("DASHBOARD_JWT_TTL_MINUTES", "720"))  # 12h

# Default admin bootstrapped on first run if the users table is empty.
SEED_ADMIN_EMAIL = os.environ.get("DASHBOARD_ADMIN_EMAIL", "admin@threatorbit.space")
SEED_ADMIN_PASSWORD = os.environ.get("DASHBOARD_ADMIN_PASSWORD", "ChangeMe123!")

# --- CORS -------------------------------------------------------------------
CORS_ORIGINS = os.environ.get(
    "DASHBOARD_CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3111",
)

# --- Auth throttling ----------------------------------------------------------
# Failed login/register attempts allowed per client+identity inside the window
# before the API answers 429. Successful auth clears the counter.
AUTH_MAX_FAILURES = int(os.environ.get("DASHBOARD_AUTH_MAX_FAILURES", "10"))
AUTH_FAILURE_WINDOW_SEC = int(os.environ.get("DASHBOARD_AUTH_FAILURE_WINDOW_SEC", "300"))

# --- Registration --------------------------------------------------------------
# Public self-service signup can be disabled for closed deployments.
ALLOW_REGISTRATION = os.environ.get("DASHBOARD_ALLOW_REGISTRATION", "true").lower() != "false"

# --- Companion services ---------------------------------------------------------
# The Threat API (ingestion engine) and Log API (anomaly analysis) are proxied
# server-side so the browser never needs their X-API-Key credentials.
THREAT_API_URL = os.environ.get("THREAT_API_URL", "http://127.0.0.1:8000").rstrip("/")
LOG_API_URL = os.environ.get("LOG_API_URL", "http://127.0.0.1:8001").rstrip("/")
SERVICES_API_KEY = os.environ.get("SERVICES_API_KEY", os.environ.get("APP_API_KEY", ""))
SERVICES_ADMIN_KEY = os.environ.get("SERVICES_ADMIN_KEY",
                                    os.environ.get("ADMIN_API_KEY", SERVICES_API_KEY))

# --- Seed -------------------------------------------------------------------
# Deterministic seed so generated demo data is stable across restarts.
SEED_RANDOM = int(os.environ.get("DASHBOARD_SEED", "1337"))
AUTO_SEED = os.environ.get("DASHBOARD_AUTO_SEED", "true").lower() != "false"
