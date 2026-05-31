import os
import sys

import os

# Ensure auth keys are set before importing the app
os.environ.setdefault("APP_API_KEY", "test-user-key")
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")

# Add repo root to path so `log_api` package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
