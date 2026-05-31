import os
import sys

# Ensure APP_API_KEY is set before importing the app
os.environ.setdefault("APP_API_KEY", "test-key-for-testing")

# Add repo root to path so `threat_api` package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
