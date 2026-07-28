"""Lock-in guards for the real-data promise: a live-mode boot must seed NO demo
data, and DASHBOARD_ENGINE=off must produce nothing.

These run in a SUBPROCESS against a throwaway DB so they exercise a genuinely
fresh boot without touching the session's demo-seeded test database. They are
the regression fence around the whole "real feeds only" guarantee - if someone
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
    # Genuine isolation: this boots a THROWAWAY SQLite DB, so it must not inherit
    # a Postgres backend from the parent env (the CI Postgres job sets
    # DASHBOARD_DB_BACKEND/DATABASE_URL). Otherwise the subprocess ignores the
    # temp DB path and connects to the shared, already-populated Postgres, and the
    # "empty on a live boot" assertions see other tests' data. The live-boot
    # seeding under test is backend-agnostic, so exercising it on SQLite is valid.
    env["DASHBOARD_DB_BACKEND"] = "sqlite"
    env.pop("DATABASE_URL", None)
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


def test_live_mode_refuses_synthetic_generation(client, auth, monkeypatch):
    """In live mode the platform must be INCAPABLE of fabricating indicators - not
    merely "paused". A paused engine is one click away from inventing random IPs
    and hashes and placing them beside real intel, which is exactly what makes a
    live deployment untrustworthy. The API must refuse the burst outright."""
    import dashboard_api.config as cfg

    # Live posture: synthetic generation is forbidden (the endpoint reads this
    # flag at call time, so patching the module attribute exercises the real guard).
    monkeypatch.setattr(cfg, "SYNTHETIC_ALLOWED", False)

    st = client.get("/config/engine", headers=auth).json()
    assert st["syntheticAllowed"] is False
    assert st["running"] is False, "nothing synthetic may run in live mode"

    before = client.get("/cti/iocs", headers=auth).json()
    before_n = len(before.get("items", before))

    r = client.post("/config/engine", json={"generate": 3}, headers=auth)
    assert r.status_code == 409, f"live mode generated synthetic data (HTTP {r.status_code})"

    after = client.get("/cti/iocs", headers=auth).json()
    assert len(after.get("items", after)) == before_n, "indicators were fabricated"


def test_demo_mode_still_allows_synthetic_generation(client, auth, monkeypatch):
    """The demo/evaluation path must keep working - the guard is about LIVE mode,
    not about removing the feature."""
    import dashboard_api.config as cfg
    monkeypatch.setattr(cfg, "SYNTHETIC_ALLOWED", True)
    r = client.post("/config/engine", json={"generate": 1}, headers=auth)
    assert r.status_code == 200, r.text


def test_process_tick_itself_refuses_to_fabricate_in_live_mode(monkeypatch):
    """The refusal must live in the GENERATOR, not only at its call sites.

    The first-boot prime called process_tick() directly and so bypassed the
    caller-side SYNTHETIC_ALLOWED check, seeding 25 ticks of fabricated
    telemetry into a live deployment before anyone had logged in. Guarding the
    generator makes that class of bypass impossible for any future caller too.
    """
    import dashboard_api.config as cfg
    from dashboard_api.engine import process_tick
    from dashboard_api.db import get_conn

    monkeypatch.setattr(cfg, "SYNTHETIC_ALLOWED", False)
    tables = ("events", "alerts", "iocs", "dark_web_findings")
    with get_conn() as c:
        before = {t: c.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"] for t in tables}

    summary = process_tick(max_events=10)
    assert summary["events"] == 0 and summary["iocs"] == 0
    assert summary.get("refused") == "synthetic-disabled"

    with get_conn() as c:
        after = {t: c.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"] for t in tables}
    assert after == before, f"process_tick fabricated rows in live mode: {before} -> {after}"


def test_full_live_startup_primes_nothing_fabricated():
    """End-to-end fence on the real startup path.

    The other boot tests call bootstrap_live() directly, which is why the prime
    block's missing guard went unnoticed: the code that fabricated the data was
    never exercised. This runs the actual _startup() a deployment runs, with the
    engine ON, and requires every observation store to still be empty.

    Built-in detection rules and playbooks are deliberately NOT in scope here:
    _startup seeds them and should, they are shipped content (logic an analyst
    edits), not claims about what was observed on this network."""
    observed = ["alerts", "cases", "assets", "integrations", "iocs",
                "feeds", "saved_hunts", "dark_web_findings", "events"]
    db = Path(tempfile.mkdtemp()) / "startup.db"
    script = f"""
import os, json
os.environ["DASHBOARD_DB_PATH"] = {str(db)!r}
os.environ["DASHBOARD_JWT_SECRET"] = "test-secret-live-startup"
os.environ["DASHBOARD_DATA_MODE"] = "live"
os.environ["DASHBOARD_ENGINE"] = "on"
os.environ.pop("DASHBOARD_ALLOW_SYNTHETIC", None)
import dashboard_api.main as m
m._startup()
from dashboard_api.db import get_conn
tables = {observed!r}
with get_conn() as conn:
    counts = {{t: conn.execute(f"SELECT COUNT(*) FROM {{t}}").fetchone()[0] for t in tables}}
print(json.dumps(counts))
"""
    env = {**dict(__import__("os").environ)}
    env["DASHBOARD_DB_BACKEND"] = "sqlite"
    env.pop("DATABASE_URL", None)
    env.pop("DASHBOARD_ALLOW_SYNTHETIC", None)
    out = subprocess.run([sys.executable, "-c", script], capture_output=True,
                         text=True, env=env, cwd=str(Path(__file__).resolve().parents[2]),
                         timeout=180)
    assert out.returncode == 0, f"startup failed:\n{out.stderr}"
    counts = json.loads(out.stdout.strip().splitlines()[-1])
    for table in observed:
        assert counts[table] == 0, (
            f"{table} has {counts[table]} fabricated rows after a live startup - "
            "live mode must never prime the stores with simulated telemetry")


def test_upgrading_an_existing_database_backfills_url_hosts():
    """An operator upgrading a running deployment already has indicators in the
    store, imported before `iocs.host` existed. Without a backfill those rows
    keep working for exact lookups but silently stop being found by domain
    queries - the store gets quietly less accurate after an upgrade, which is
    worse than a slow lookup because nothing reports it.

    Runs in a subprocess against a throwaway DB, reconstructing the pre-upgrade
    shape (no host column, schema_version 9) and then booting the current code
    against it - the same path a restart after `git pull` takes."""
    db = Path(tempfile.mkdtemp()) / "upgrade.db"
    script = f"""
import json, os, sqlite3, uuid
os.environ["DASHBOARD_DB_PATH"] = {str(db)!r}
os.environ["DASHBOARD_JWT_SECRET"] = "test-secret-upgrade"
os.environ["DASHBOARD_DATA_MODE"] = "live"
from dashboard_api.db import init_db, get_conn
init_db()

# Rewind to the pre-upgrade shape: drop the column and the version marker, then
# write rows the way the older build did.
with get_conn() as c:
    c.execute("DROP INDEX IF EXISTS idx_iocs_host")
    c.execute("ALTER TABLE iocs DROP COLUMN host")
    c.execute("DELETE FROM iocs")
    for i in range(50):
        c.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,"
            "actor,first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,'[]')",
            (str(uuid.uuid4()), "url", f"https://legacy-{{i}}.example/path?a=1",
             "phishing", 80, "high", "pre-upgrade-feed", "",
             "2026-01-01T00:00:00", "2026-01-01T00:00:00"))
    c.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('schema_version','9')")
    c.commit()

init_db()                      # the upgrade: migration + backfill

with get_conn() as c:
    ver = c.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()["value"]
    total = c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    filled = c.execute("SELECT COUNT(*) FROM iocs WHERE host IS NOT NULL").fetchone()[0]
    one = c.execute("SELECT host FROM iocs WHERE value LIKE '%legacy-7.example%'").fetchone()
print(json.dumps({{"version": ver, "total": total, "filled": filled,
                   "host": one["host"] if one else None}}))
"""
    env = {**dict(__import__("os").environ)}
    env["DASHBOARD_DB_BACKEND"] = "sqlite"
    env.pop("DATABASE_URL", None)
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                         env=env, cwd=str(Path(__file__).resolve().parents[2]), timeout=180)
    assert out.returncode == 0, f"upgrade boot failed:\n{out.stderr}"
    res = json.loads(out.stdout.strip().splitlines()[-1])

    assert res["total"] == 50, f"the upgrade lost indicators: {res['total']} of 50 remain"
    assert res["filled"] == 50, (
        f"only {res['filled']} of 50 pre-upgrade URLs got a host - the rest became "
        "invisible to domain lookups")
    assert res["host"] == "legacy-7.example", f"host parsed wrong: {res['host']!r}"
    assert res["version"] == "10", f"schema version not bumped: {res['version']}"
