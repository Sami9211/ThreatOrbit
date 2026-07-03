"""Lock-in guards for the real-data promise: a live-mode boot must seed NO demo
data, and DASHBOARD_ENGINE=off must produce nothing.

These run in a SUBPROCESS against a throwaway DB so they exercise a genuinely
fresh boot without touching the session's demo-seeded test database. They are
the regression fence around the whole "real feeds only" guarantee — if someone
later wires _seed_integrations (or any demo seeder) into bootstrap_live, or the
engine-off gate stops pausing, these fail.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Tables that a real deployment MUST start empty (no fabricated data).
_MUST_BE_EMPTY = ["alerts", "cases", "assets", "integrations", "iocs",
                  "detection_rules", "playbooks", "feeds", "saved_hunts",
                  "dark_web_findings", "events"]


def _run_boot(env_extra: dict) -> dict:
    """Boot the app's live bootstrap in a subprocess against a fresh DB and
    return per-table row counts + the engine_enabled setting."""
    db = Path(tempfile.mkdtemp()) / "live.db"
    script = f"""
import os, json
os.environ["DASHBOARD_DB_PATH"] = {str(db)!r}
os.environ["DASHBOARD_JWT_SECRET"] = "test-secret-live-honesty"
os.environ["DASHBOARD_DATA_MODE"] = "live"
from dashboard_api.db import init_db, get_conn
from dashboard_api.seed import bootstrap_live
init_db()
bootstrap_live()
# Apply the same engine-mode gate the app applies at startup.
import dashboard_api.main as m
engine_off = m._apply_engine_mode()
tables = {_MUST_BE_EMPTY + ["users", "threat_actors"]!r}
with get_conn() as conn:
    counts = {{t: conn.execute(f"SELECT COUNT(*) FROM {{t}}").fetchone()[0] for t in tables}}
    row = conn.execute("SELECT value FROM settings WHERE key='engine_enabled'").fetchone()
print(json.dumps({{"counts": counts, "engineOff": engine_off,
                   "engineEnabled": (row[0] if row else None)}}))
"""
    env = {**dict(__import__("os").environ), **env_extra}
    out = subprocess.run([sys.executable, "-c", script], capture_output=True,
                         text=True, env=env, cwd=str(Path(__file__).resolve().parents[2]))
    assert out.returncode == 0, f"boot failed:\n{out.stderr}"
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_live_boot_seeds_no_demo_data():
    """A fresh live boot: exactly one admin user, the real actor reference
    library present, and every operational store empty."""
    res = _run_boot({"DASHBOARD_ENGINE": "on"})
    c = res["counts"]
    assert c["users"] == 1, f"expected only the admin user, got {c['users']}"
    # The curated public actor library IS seeded (reference data, not activity).
    assert c["threat_actors"] > 0, "the real actor reference library should be seeded"
    for table in _MUST_BE_EMPTY:
        assert c[table] == 0, f"{table} must be empty on a live boot, got {c[table]}"


def test_engine_off_pauses_and_produces_nothing():
    """With DASHBOARD_ENGINE=off the engine is paused at boot and no synthetic
    telemetry is generated (all operational stores stay empty)."""
    res = _run_boot({"DASHBOARD_ENGINE": "off"})
    assert res["engineOff"] is True
    assert res["engineEnabled"] == "false", "engine must boot paused when off"
    for table in ("alerts", "iocs", "events", "cases", "dark_web_findings"):
        assert res["counts"][table] == 0, f"{table} should be empty with engine off"
