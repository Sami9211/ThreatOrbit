"""Environment-driven configuration for the ThreatOrbit dashboard API.

All secrets and tunables come from environment variables with sensible
development defaults so the service runs out-of-the-box for local testing.
"""
import logging
import os
import secrets
import sys

_log = logging.getLogger("dashboard_api.config")

# --- Database ---------------------------------------------------------------
DB_PATH = os.environ.get("DASHBOARD_DB_PATH", os.path.join(os.path.dirname(__file__), "dashboard.db"))
_DATA_DIR = os.path.dirname(os.path.abspath(DB_PATH))

# Production hardening gate. When on, the service refuses to start with any
# insecure default secret (fail-fast). Off by default so local/demo just works.
REQUIRE_SECRETS = (
    os.environ.get("DASHBOARD_REQUIRE_SECRETS", "false").lower() == "true"
    or os.environ.get("DASHBOARD_ENV", "").lower() in ("prod", "production")
)


def _persisted_secret(env_name: str, filename: str) -> str:
    """A strong secret for `env_name`: the env value if set, otherwise a
    per-install random value persisted under the data dir (created once, 0600).

    This removes the shared 'dev-insecure' default - an attacker can't forge
    tokens with a known key - without forcing every local run to set an env var.
    Tokens still survive restarts because the generated secret is persisted.
    In production (DASHBOARD_REQUIRE_SECRETS) an explicit env value is mandatory.
    """
    env = os.environ.get(env_name, "").strip()
    if env:
        return env
    if REQUIRE_SECRETS:
        _log.error("FATAL: %s must be set to a strong random value in production.", env_name)
        sys.exit(1)
    path = os.path.join(_DATA_DIR, filename)
    try:
        if os.path.exists(path):
            existing = open(path, encoding="utf-8").read().strip()
            if existing:
                return existing
        value = secrets.token_hex(32)
        os.makedirs(_DATA_DIR, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(value)
        _log.warning("Generated a persistent secret for %s at %s (set %s to override).",
                     env_name, path, env_name)
        return value
    except OSError:
        # Last resort: ephemeral random - never the known default. Tokens won't
        # survive a restart, but that only forces a re-login.
        _log.warning("Could not persist %s; using an ephemeral random secret.", env_name)
        return secrets.token_hex(32)


# --- Auth / JWT -------------------------------------------------------------
# In production set DASHBOARD_JWT_SECRET to a long random value; otherwise a
# per-install random secret is generated and persisted (never the old default).
JWT_SECRET = _persisted_secret("DASHBOARD_JWT_SECRET", ".jwt_secret")
JWT_ALG = "HS256"
JWT_TTL_MINUTES = int(os.environ.get("DASHBOARD_JWT_TTL_MINUTES", "720"))  # 12h

# Default admin bootstrapped on first run if the users table is empty. The
# bootstrap password must be changed on first login (enforced in routers/auth).
SEED_ADMIN_EMAIL = os.environ.get("DASHBOARD_ADMIN_EMAIL", "admin@threatorbit.space")
SEED_ADMIN_PASSWORD = os.environ.get("DASHBOARD_ADMIN_PASSWORD", "ChangeMe123!")
if REQUIRE_SECRETS and SEED_ADMIN_PASSWORD == "ChangeMe123!":
    _log.error("FATAL: DASHBOARD_ADMIN_PASSWORD must be set (not the default) in production.")
    sys.exit(1)

# --- CORS -------------------------------------------------------------------
CORS_ORIGINS = os.environ.get(
    "DASHBOARD_CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3111",
)
# Parsed allowlist. Credentials are enabled on the API, so a wildcard origin is
# both invalid per the CORS spec and unsafe - refuse it explicitly rather than
# silently shipping an insecure config.
CORS_ALLOWED = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
if "*" in CORS_ALLOWED:
    _log.error("FATAL: DASHBOARD_CORS_ORIGINS must list explicit origins, not '*' "
               "(credentials are enabled). Set the exact dashboard origin(s).")
    sys.exit(1)

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

# --- Billing (Stripe self-serve, optional) ----------------------------------
# Entirely opt-in: with no STRIPE_SECRET_KEY the billing endpoints degrade
# honestly to "not configured" and licence keys remain the only path. When set,
# a completed Checkout mints the plan's signed licence key (so the existing
# limit enforcement is unchanged). Map the paid tiers to Stripe Price IDs.
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()
# Where Stripe sends the customer back to (the dashboard origin).
BILLING_RETURN_URL = os.environ.get("DASHBOARD_BILLING_RETURN_URL",
                                    "http://localhost:3000/dashboard/config").rstrip("/")
# backend plan id -> Stripe Price ID (only the self-serve paid tiers).
STRIPE_PRICES = {
    plan: os.environ[env].strip()
    for plan, env in (("starter", "STRIPE_PRICE_STARTER"), ("pro", "STRIPE_PRICE_PRO"))
    if os.environ.get(env, "").strip()
}

# --- SSO (OIDC, optional) ---------------------------------------------------
# Opt-in single sign-on via any OpenID Connect provider (Entra ID, Okta, Google
# Workspace, Auth0, Keycloak…). With no OIDC_ISSUER the SSO endpoints degrade to
# "not configured" and email+password remains the only path. The redirect URI
# is the backend callback you register with the IdP; users are JIT-provisioned
# on first login and their role is mapped from an IdP groups claim.
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").strip().rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI",
                                   "http://localhost:8002/auth/sso/callback").strip()
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid email profile").strip()
OIDC_GROUPS_CLAIM = os.environ.get("OIDC_GROUPS_CLAIM", "groups").strip()
# JSON map of IdP group -> role (admin|manager|analyst|viewer). First match wins.
import json as _json  # noqa: E402
try:
    OIDC_ROLE_MAP = _json.loads(os.environ.get("OIDC_ROLE_MAP", "{}"))
except ValueError:
    OIDC_ROLE_MAP = {}
OIDC_DEFAULT_ROLE = os.environ.get("OIDC_DEFAULT_ROLE", "viewer").strip()
# Optional comma-separated allowlist of email domains (e.g. "acme.com").
OIDC_ALLOWED_DOMAINS = [d.strip().lower() for d in
                        os.environ.get("OIDC_ALLOWED_DOMAINS", "").split(",") if d.strip()]
# Frontend page to land on after callback (receives the session token in the
# URL fragment so it never hits a server log).
OIDC_POST_LOGIN_URL = os.environ.get("OIDC_POST_LOGIN_URL", "http://localhost:3000/login").rstrip("/")

# --- SCIM 2.0 provisioning (optional) ---------------------------------------
# Lets an IdP (Okta, Entra ID / Azure AD, OneLogin…) push user lifecycle -
# create / update / deactivate - to the dashboard over SCIM 2.0. The IdP
# authenticates with a long bearer token (SCIM_TOKEN); with no token set the
# /scim/v2 endpoints degrade to "not configured" (404). Provisioned users sign
# in through the existing OIDC SSO (or a set password). Role defaults to
# SCIM_DEFAULT_ROLE and can be mapped from a SCIM role/group via SCIM_ROLE_MAP.
SCIM_TOKEN = os.environ.get("SCIM_TOKEN", "").strip()
SCIM_DEFAULT_ROLE = os.environ.get("SCIM_DEFAULT_ROLE", "viewer").strip()
# JSON map of SCIM role/group value -> dashboard role (admin|manager|analyst|viewer).
try:
    SCIM_ROLE_MAP = _json.loads(os.environ.get("SCIM_ROLE_MAP", "{}"))
except ValueError:
    SCIM_ROLE_MAP = {}

# --- Data mode --------------------------------------------------------------
# "demo" → seed realistic demo data on first boot (great for evaluation/sales).
# "live" → start empty, bootstrap the admin + built-in connectors, and ingest
#          REAL threat intelligence from the OSINT engine on a schedule.
DATA_MODE = os.environ.get("DASHBOARD_DATA_MODE", "demo").lower()

# How often the connector scheduler wakes to run due connectors (live mode).
CONNECTOR_TICK_SECONDS = int(os.environ.get("DASHBOARD_CONNECTOR_TICK_SECONDS", "60"))

# Live processing engine (live mode): how often it generates a telemetry batch
# and how many events per batch. Lower the interval for a more active demo.
ENGINE_TICK_SECONDS = int(os.environ.get("DASHBOARD_ENGINE_TICK_SECONDS", "20"))
ENGINE_EVENTS_PER_TICK = int(os.environ.get("DASHBOARD_ENGINE_EVENTS_PER_TICK", "6"))

# --- Seed -------------------------------------------------------------------
# Deterministic seed so generated demo data is stable across restarts.
SEED_RANDOM = int(os.environ.get("DASHBOARD_SEED", "1337"))
# In demo mode seed on first boot; live mode never seeds demo data.
AUTO_SEED = (os.environ.get("DASHBOARD_AUTO_SEED", "true").lower() != "false"
             and DATA_MODE != "live")
