import os


def _get_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


# API auth
# APP_API_KEY:   standard user, read access to IOCs, jobs, OpenCTI read endpoints
# ADMIN_API_KEY: admin, everything above plus trigger fetch, export STIX, push to OpenCTI
#                 Falls back to APP_API_KEY when not set so single-key setups keep working.
APP_API_KEY = os.getenv("APP_API_KEY")
if not APP_API_KEY:
    raise ValueError(
        "APP_API_KEY environment variable is required but not set. "
        "Set it before starting the service: export APP_API_KEY=<your-secret-key>"
    )

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY") or APP_API_KEY

# Server
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
FLASK_DEBUG = _get_bool("FLASK_DEBUG", False)

# DB
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///threat_api.db")
DB_PATH = os.getenv("DB_PATH", "threat_api.db")

# External sources / enrichment
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_DAYS_BACK = int(os.getenv("OTX_DAYS_BACK", "14"))

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_RATE_LIMIT_SECONDS = int(os.getenv("VT_RATE_LIMIT_SECONDS", "15"))

ABUSECH_URLHAUS_URL = os.getenv("ABUSECH_URLHAUS_URL", "https://urlhaus-api.abuse.ch/v1/urls/recent/")
ABUSECH_MALWARE_URL = os.getenv("ABUSECH_MALWARE_URL", "https://mb-api.abuse.ch/api/v1/")
ABUSECH_FEODO_URL = os.getenv("ABUSECH_FEODO_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
# abuse.ch added an Auth-Key requirement to its query APIs in 2024. Get a free
# key at https://auth.abuse.ch/ and set ABUSECH_AUTH_KEY to enable URLHaus.
# The Feodo ipblocklist.json download below still works without a key.
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")

# STIX
STIX_IDENTITY_NAME = os.getenv("STIX_IDENTITY_NAME", "ThreatOrbit CTI Platform")
STIX_IDENTITY_CLASS = os.getenv("STIX_IDENTITY_CLASS", "organization")

# OpenCTI
OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080")
OPENCTI_API_KEY = os.getenv("OPENCTI_API_KEY", "")
OPENCTI_ENABLED = _get_bool("OPENCTI_ENABLED", False)

# Scheduler
ENABLE_SCHEDULER = _get_bool("ENABLE_SCHEDULER", True)
SCHEDULE_FETCH_CRON_MINUTES = int(os.getenv("SCHEDULE_FETCH_CRON_MINUTES", "60"))

# Rate limiting
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))

# Pipeline limits
PIPELINE_MAX_IOCS_PER_SOURCE = int(os.getenv("PIPELINE_MAX_IOCS_PER_SOURCE", "2000"))
PIPELINE_MAX_TOTAL_IOCS = int(os.getenv("PIPELINE_MAX_TOTAL_IOCS", "10000"))
PIPELINE_MAX_ENRICH = int(os.getenv("PIPELINE_MAX_ENRICH", "200"))

# Source toggles
ENABLE_OTX = _get_bool("ENABLE_OTX", True)
ENABLE_ABUSECH = _get_bool("ENABLE_ABUSECH", True)
ENABLE_RSS = _get_bool("ENABLE_RSS", True)
ENABLE_DARKWEB_OSINT = _get_bool("ENABLE_DARKWEB_OSINT", True)
ENABLE_SOCIAL_OSINT = _get_bool("ENABLE_SOCIAL_OSINT", True)

# CORS
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

# Files
BUNDLE_PATH = os.getenv("BUNDLE_PATH", "stix_bundle.json")
TRUST_CONFIG_PATH = os.getenv("TRUST_CONFIG_PATH", "source_trust_config.json")
