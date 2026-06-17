import os
import sys
import tempfile

# Ensure auth keys are set before importing the app.
os.environ.setdefault("APP_API_KEY", "test-user-key")
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")
# Isolate the DB to a throwaway file (db.py reads LOG_DB_PATH at import time).
os.environ.setdefault("LOG_DB_PATH",
                      tempfile.NamedTemporaryFile(suffix="-logapi-test.db", delete=False).name)

# Add repo root to path so `log_api` package is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Create the schema (the app's lifespan init doesn't run under a bare TestClient).
from log_api.db import init_db  # noqa: E402

init_db()
