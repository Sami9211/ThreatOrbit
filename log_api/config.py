import os


def _get_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


# API auth — uses the same env vars as threat_api so a single .env covers both services.
# USER_API_KEY  — analysts: submit logs, view results, view reports
# ADMIN_API_KEY — admins: everything above (log_api has no write-only admin ops yet)
#                 Falls back to USER_API_KEY when not set.
USER_API_KEY = os.getenv("APP_API_KEY")
if not USER_API_KEY:
    raise ValueError(
        "APP_API_KEY environment variable is required but not set."
    )

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY") or USER_API_KEY

API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

ENABLE_PATTERN_DETECTOR = _get_bool("ENABLE_PATTERN_DETECTOR", True)
ENABLE_STATISTICAL_DETECTOR = _get_bool("ENABLE_STATISTICAL_DETECTOR", True)
ENABLE_ML_DETECTOR = _get_bool("ENABLE_ML_DETECTOR", True)
ENABLE_TEMPORAL_DETECTOR = _get_bool("ENABLE_TEMPORAL_DETECTOR", True)

ZSCORE_THRESHOLD = float(os.getenv("ZSCORE_THRESHOLD", "3.0"))
RATE_SPIKE_RPM_THRESHOLD = int(os.getenv("RATE_SPIKE_RPM_THRESHOLD", "120"))
ERROR_RATE_THRESHOLD_PCT = float(os.getenv("ERROR_RATE_THRESHOLD_PCT", "40.0"))

ML_CONTAMINATION = float(os.getenv("ML_CONTAMINATION", "0.05"))
ML_N_ESTIMATORS = int(os.getenv("ML_N_ESTIMATORS", "100"))

BUSINESS_HOURS_START = int(os.getenv("BUSINESS_HOURS_START", "7"))
BUSINESS_HOURS_END = int(os.getenv("BUSINESS_HOURS_END", "20"))

BURST_EVENT_COUNT = int(os.getenv("BURST_EVENT_COUNT", "20"))
BURST_WINDOW_SECONDS = int(os.getenv("BURST_WINDOW_SECONDS", "10"))

SEVERITY_CRITICAL_THRESHOLD = int(os.getenv("SEVERITY_CRITICAL_THRESHOLD", "80"))
SEVERITY_HIGH_THRESHOLD = int(os.getenv("SEVERITY_HIGH_THRESHOLD", "50"))
SEVERITY_MEDIUM_THRESHOLD = int(os.getenv("SEVERITY_MEDIUM_THRESHOLD", "25"))

REPORT_OUTPUT_PATH = os.getenv("REPORT_OUTPUT_PATH", "anomaly_report.html")
MAX_EVENTS_PER_ALERT_IN_REPORT = int(os.getenv("MAX_EVENTS_PER_ALERT_IN_REPORT", "5"))

SUPPORTED_FORMATS = ["syslog", "apache", "windows_event", "generic"]

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
