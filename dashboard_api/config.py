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

# Evaluation installs get reached from origins the fixed allowlist can't
# anticipate - a LAN IP (http://192.168.1.20:3000), the machine's hostname
# (http://desk-01:3000), a nonstandard port. Every API call then fails CORS,
# and the loudest symptom is UI actions "erroring" (the mode toggle POSTs
# /config/mode on every click). In evaluation posture we therefore also accept
# loopback/private-range IPs and single-label intranet hostnames on any port
# (single-label = no dot, unreachable from the public internet). Production
# (DASHBOARD_REQUIRE_SECRETS=true) keeps the explicit allowlist only, unless
# the operator sets DASHBOARD_CORS_ORIGIN_REGEX deliberately.
_PRIVATE_ORIGIN_REGEX = (
    r"^https?://("
    r"localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|[A-Za-z0-9-]+"
    r")(:\d+)?$"
)
CORS_ORIGIN_REGEX = os.environ.get(
    "DASHBOARD_CORS_ORIGIN_REGEX",
    "" if REQUIRE_SECRETS else _PRIVATE_ORIGIN_REGEX,
) or None

# --- Auth throttling ----------------------------------------------------------
# Failed login/register attempts allowed per client+identity inside the window
# before the API answers 429. Successful auth clears the counter.
AUTH_MAX_FAILURES = int(os.environ.get("DASHBOARD_AUTH_MAX_FAILURES", "10"))
AUTH_FAILURE_WINDOW_SEC = int(os.environ.get("DASHBOARD_AUTH_FAILURE_WINDOW_SEC", "300"))

# --- Registration --------------------------------------------------------------
# Public self-service signup can be disabled for closed deployments.
ALLOW_REGISTRATION = os.environ.get("DASHBOARD_ALLOW_REGISTRATION", "true").lower() != "false"
# When enabled (and SMTP is configured), a new self-service signup is created in
# 'pending' status and cannot sign in until it confirms ownership of its email
# via a link. Off by default so existing deployments (and tests) are unchanged;
# the very first account (the bootstrap admin) is always active regardless.
REQUIRE_EMAIL_VERIFICATION = (
    os.environ.get("DASHBOARD_REQUIRE_EMAIL_VERIFICATION", "false").lower() == "true"
)
# Public base URL of the dashboard, used to build links in outbound email
# (e.g. the email-verification link). Falls back to a relative path.
APP_BASE_URL = os.environ.get("DASHBOARD_APP_BASE_URL", "").rstrip("/")

# --- Detection pipeline ---------------------------------------------------------
# Worker count for a pooled backlog drain (detection_pool). The engine's inline
# tick still uses a single worker; >1 lets an operator drain a large backlog with
# a concurrency-safe pool (each claim is write-locked so workers never overlap).
DETECTION_WORKERS = max(1, int(os.environ.get("DASHBOARD_DETECTION_WORKERS", "1")))

# --- Data lifecycle -------------------------------------------------------------
# Opt-in PII/secret redaction of raw log text at the ingest seam, BEFORE
# persistence. Comma-separated categories: email, secret, cc, ssn (see
# dashboard_api/redaction.py + docs/PII_HANDLING.md). Empty = store verbatim.
# Redaction is lossy and irreversible; structured pivot fields (src_ip,
# username, hostname) are always retained for detection.
LOG_REDACT = [c.strip().lower() for c in
              os.environ.get("DASHBOARD_LOG_REDACT", "").split(",") if c.strip()]

# When set to a writable directory, retention enforcement archives each batch of
# purged rows to compressed NDJSON there BEFORE deleting them, so compliance can
# keep raw logs cheaply. Unset = purge-only (unless an object store is set below).
ARCHIVE_DIR = os.environ.get("DASHBOARD_ARCHIVE_DIR", "").strip()
# Direct object-storage archival (S3 / S3-compatible): set a bucket to write each
# purged batch as an immutable gzip object via a SigV4-signed PUT. Credentials
# come from the standard AWS environment. _ENDPOINT enables path-style for
# MinIO/R2/B2; leave unset for AWS. Independent of (and combinable with) the dir.
ARCHIVE_S3_BUCKET = os.environ.get("DASHBOARD_ARCHIVE_S3_BUCKET", "").strip()
ARCHIVE_S3_PREFIX = os.environ.get("DASHBOARD_ARCHIVE_S3_PREFIX", "").strip()
ARCHIVE_S3_REGION = os.environ.get("DASHBOARD_ARCHIVE_S3_REGION", "").strip()
ARCHIVE_S3_ENDPOINT = os.environ.get("DASHBOARD_ARCHIVE_S3_ENDPOINT", "").strip()
# Agentless log pull: tail an S3 (or S3-compatible) bucket prefix on an interval,
# fetching new objects and feeding their lines through the ingest pipeline. Off
# unless a bucket is set; credentials come from the standard AWS environment.
S3_PULL_BUCKET = os.environ.get("DASHBOARD_S3_PULL_BUCKET", "").strip()
S3_PULL_PREFIX = os.environ.get("DASHBOARD_S3_PULL_PREFIX", "").strip()
S3_PULL_REGION = os.environ.get("DASHBOARD_S3_PULL_REGION", "").strip()
S3_PULL_ENDPOINT = os.environ.get("DASHBOARD_S3_PULL_ENDPOINT", "").strip()
S3_PULL_ORG = os.environ.get("DASHBOARD_S3_PULL_ORG", "").strip()
S3_PULL_INTERVAL = int(os.environ.get("DASHBOARD_S3_PULL_SECONDS", "60") or "60")

# --- Audit trail external sink (tamper-evidence) --------------------------------
# When set, every audit event is also shipped (fire-and-forget) to this HTTP
# endpoint - the customer's SIEM or an append-only/object-lock store - so the
# trail survives even if the local DB is tampered with. Optionally HMAC-signed
# with AUDIT_SINK_SECRET (same scheme as outbound webhooks). Unset = in-DB only.
AUDIT_SINK_URL = os.environ.get("DASHBOARD_AUDIT_SINK_URL", "").strip()
AUDIT_SINK_SECRET = os.environ.get("DASHBOARD_AUDIT_SINK_SECRET", "").strip()

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

# --- SAML 2.0 SP (optional) -------------------------------------------------
# SP-initiated SSO for IdPs that speak SAML rather than OIDC (ADFS, many
# enterprise Okta/Entra setups). With no SAML_IDP_* the endpoints degrade to
# "not configured". The assertion's XML signature is verified against the IdP's
# X.509 cert (signxml); audience, recipient, timestamps, issuer, InResponseTo
# and one-time-use are all enforced. Users are JIT-provisioned like OIDC.
SAML_IDP_ENTITY_ID = os.environ.get("SAML_IDP_ENTITY_ID", "").strip()
SAML_IDP_SSO_URL = os.environ.get("SAML_IDP_SSO_URL", "").strip()
SAML_IDP_CERT = os.environ.get("SAML_IDP_CERT", "").strip()          # PEM or bare base64 DER
SAML_SP_ENTITY_ID = os.environ.get("SAML_SP_ENTITY_ID", "threatorbit-dashboard").strip()
SAML_SP_ACS_URL = os.environ.get("SAML_SP_ACS_URL",
                                 "http://localhost:8002/auth/saml/acs").strip()
# Optional SP signing key (PEM, RSA or EC). When set, the SP signs its
# AuthnRequest per the HTTP-Redirect binding (detached SigAlg + Signature query
# parameters) for IdPs that require signed requests (WantAuthnRequestsSigned).
# Unset = requests are sent unsigned, exactly as before.
SAML_SP_PRIVATE_KEY = os.environ.get("SAML_SP_PRIVATE_KEY", "").strip()
# Attribute names carrying email / display name / groups (IdP-specific; sensible
# defaults below also try the SAML NameID and common friendly names).
SAML_EMAIL_ATTR = os.environ.get("SAML_EMAIL_ATTR", "").strip()
SAML_NAME_ATTR = os.environ.get("SAML_NAME_ATTR", "").strip()
SAML_GROUPS_ATTR = os.environ.get("SAML_GROUPS_ATTR", "groups").strip()
try:
    SAML_ROLE_MAP = _json.loads(os.environ.get("SAML_ROLE_MAP", "{}"))
except ValueError:
    SAML_ROLE_MAP = {}
SAML_DEFAULT_ROLE = os.environ.get("SAML_DEFAULT_ROLE", "viewer").strip()
SAML_ALLOWED_DOMAINS = [d.strip().lower() for d in
                        os.environ.get("SAML_ALLOWED_DOMAINS", "").split(",") if d.strip()]

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

# Synthetic-telemetry switch - THE knob for real-data deployments.
#   "on"  (default) → live mode generates representative environment telemetry
#                     continuously so the console is alive before any log
#                     forwarding exists (evaluation / demo liveliness).
#   "off"           → REAL DATA ONLY: no first-boot prime, and the engine
#                     boots paused on every start (the UI toggle can still
#                     resume it deliberately for a demo burst; the next boot
#                     re-pauses). Real ingestion - log uploads, the collector,
#                     syslog/file listeners, connectors, TAXII push - is
#                     unaffected. See docs/GOING_LIVE.md.
ENGINE_MODE = os.environ.get("DASHBOARD_ENGINE", "on").strip().lower()

# Ingest backpressure: the max detection backlog (pending events) before the
# /siem/ingest endpoint sheds load with HTTP 429 instead of growing the queue
# unboundedly. Generous by default so normal use never hits it; 0 disables the
# guard. This is the bounded-queue half of the event-pipeline backpressure work.
INGEST_MAX_BACKLOG = int(os.environ.get("DASHBOARD_INGEST_MAX_BACKLOG", "100000"))

# Max HTTP request body accepted, in bytes (DoS guard). Rejected with 413 at the
# ASGI edge BEFORE the app buffers it - the ingest line-count cap only applies
# after the whole body is read, so this bounds memory against a huge POST (or one
# enormous line). 25 MB comfortably fits a 5000-line log batch; 0 disables it.
MAX_BODY_BYTES = int(os.environ.get("DASHBOARD_MAX_BODY_BYTES", str(25 * 1024 * 1024)))

# --- Seed -------------------------------------------------------------------
# Deterministic seed so generated demo data is stable across restarts.
SEED_RANDOM = int(os.environ.get("DASHBOARD_SEED", "1337"))
# In demo mode seed on first boot; live mode never seeds demo data.
AUTO_SEED = (os.environ.get("DASHBOARD_AUTO_SEED", "true").lower() != "false"
             and DATA_MODE != "live")
