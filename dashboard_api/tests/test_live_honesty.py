"""Lock-in guards for the real-data promise: a live-mode boot must seed NO demo
data, and DASHBOARD_ENGINE=off must produce nothing.

These run in a SUBPROCESS against a throwaway DB so they exercise a genuinely
fresh boot without touching the session's demo-seeded test database. They are
the regression fence around the whole "real feeds only" guarantee - if someone
later wires _seed_integrations (or any demo seeder) into bootstrap_live, or the
engine-off gate stops pausing, these fail.
"""
import json
import re
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
    # Compare against the code's current version rather than a literal: pinning
    # "10" meant every later migration broke this test for the wrong reason.
    from dashboard_api.db import SCHEMA_VERSION
    assert int(res["version"]) == SCHEMA_VERSION, (
        f"schema version not bumped to {SCHEMA_VERSION}: {res['version']}")


def test_url_host_backfill_runs_on_the_configured_backend():
    """The backfill must work on the backend this run actually uses.

    test_upgrading_an_existing_database_backfills_url_hosts pins SQLite in its
    subprocess, so it proved nothing about Postgres - where the query
    `... LIKE '%://%'` raised "only '%s', '%b', '%t' are allowed as
    placeholders" on every boot and the backfill silently never ran. The caller
    logs and continues, so the only symptom was domain lookups quietly failing
    to find URLs imported before the column existed."""
    import uuid

    from dashboard_api.db import _backfill_ioc_hosts, get_conn, host_of

    value = f"https://backfill-{uuid.uuid4().hex[:8]}.example/p?q=1"
    with get_conn() as c:
        c.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,"
            "source,actor,first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,'[]')",
            (str(uuid.uuid4()), "url", value, "phishing", 80, "high",
             "backfill-test", "", "2026-01-01T00:00:00", "2026-01-01T00:00:00"))
        c.commit()
    try:
        with get_conn() as c:
            _backfill_ioc_hosts(c)          # must not raise on ANY backend
            c.commit()
            row = c.execute("SELECT host FROM iocs WHERE value=?", (value,)).fetchone()
        assert row["host"] == host_of(value, "url"), (
            "the backfill did not populate host - domain lookups will silently "
            "stop finding indicators imported before the column existed")
    finally:
        with get_conn() as c:
            c.execute("DELETE FROM iocs WHERE value=?", (value,))
            c.commit()


def test_existing_indicators_get_their_own_source_recorded():
    """Corroboration must not start blind on an existing store.

    Feeds use conditional GET, so an unchanged feed is never re-fetched and its
    indicators would never acquire an assertion row - on a stable store, that is
    effectively never. Every existing indicator IS the record of one source
    asserting one value; the backfill states that explicitly so the count starts
    from the truth instead of from zero.

    What it cannot do is recover corroboration that was already discarded: the
    old import kept one row per value with one `source`, so a second feed's
    agreement was dropped at write time and is simply gone. Only imports after
    the change carry the full picture."""
    import uuid

    from dashboard_api.db import _backfill_source_assertions, get_conn, host_of

    val = f"seeded-{uuid.uuid4().hex[:8]}.example"
    src = f"osint:Backfill Feed {uuid.uuid4().hex[:4]}"
    with get_conn() as c:
        c.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,"
            "actor,first_seen,last_seen,tags,host) VALUES (?,?,?,?,?,?,?,?,?,?,'[]',?)",
            (str(uuid.uuid4()), "domain", val, "phishing", 70, "high", src, "",
             "2026-01-01T00:00:00", "2026-01-02T00:00:00", host_of(val, "domain")))
        c.execute("DELETE FROM observable_sources WHERE value=?", (val,))
        c.commit()
    try:
        with get_conn() as c:
            assert _backfill_source_assertions(c) >= 1
            c.commit()
            rows = c.execute(
                "SELECT source_id, raw_label FROM observable_sources WHERE value=?",
                (val,)).fetchall()
        assert [r["source_id"] for r in rows] == [src]
        assert rows[0]["raw_label"] == "phishing", "the source's own label is kept"

        # Idempotent: a second boot must not duplicate or re-do the work.
        with get_conn() as c:
            again = _backfill_source_assertions(c)
            c.commit()
            n = c.execute("SELECT COUNT(*) AS n FROM observable_sources WHERE value=?",
                          (val,)).fetchone()["n"]
        assert n == 1, f"backfill duplicated assertions ({n} rows)"
        assert again == 0, "backfill re-processed rows it had already seeded"
    finally:
        with get_conn() as c:
            c.execute("DELETE FROM observable_sources WHERE value=?", (val,))
            c.execute("DELETE FROM iocs WHERE value=?", (val,))
            c.commit()


# ---------------------------------------------------------------------------
# The frontend half of the same promise.
#
# The backend guards above prove a live boot seeds nothing. They said nothing
# about the browser, and six live pages fell back to a hardcoded demo dataset
# when their first API call failed - rendered exactly like real records, with
# nothing on screen marking them as fiction. On a live deployment an expired
# token or a restarting backend produced a SIEM queue of fabricated critical
# alerts, a demo estate of healthy collectors, a rule list claiming detections
# that were not running, and a scanner verdict carrying invented judgements
# attributed by name to Google, Kaspersky and CrowdStrike about a value they
# were never asked about.
#
# These are text checks over the source rather than a rendering test, because
# what has to be guaranteed is a property of the CODE: the fabricated datasets
# must not exist to be rendered.
# ---------------------------------------------------------------------------
_FRONTEND = Path(__file__).resolve().parents[2] / "frontend"

# (file, identifier) pairs that were the actual fabrication vectors.
_BANNED = [
    ("app/dashboard/siem/page.tsx", "const ALERTS"),
    ("app/dashboard/siem/page.tsx", "const MITRE_DIST"),
    ("app/dashboard/siem/sources/page.tsx", "const SOURCES"),
    ("app/dashboard/siem/rules/page.tsx", "const RULES_DATA"),
    ("app/dashboard/siem/hunt/page.tsx", "const SAVED_HUNTS"),
    ("app/dashboard/siem/hunt/page.tsx", "const TIME_RANGE_EVENTS"),
    ("app/dashboard/cti/actors/page.tsx", "const ACTORS"),
    ("app/dashboard/scanner/page.tsx", "const DEMO_RESULTS"),
    ("app/dashboard/assets/page.tsx", "const SEED"),
    ("app/dashboard/assets/vulns/page.tsx", "const SEED"),
    ("app/dashboard/config/api/page.tsx", "const API_KEYS"),
    ("app/dashboard/config/api/page.tsx", "const WEBHOOKS"),
    ("app/dashboard/config/users/page.tsx", "const USERS"),
    ("app/dashboard/cti/page.tsx", "const ACTORS"),
    ("app/dashboard/cti/page.tsx", "const HUNTS"),
    ("app/dashboard/cti/hunt/page.tsx", "const HUNTS"),
    ("app/dashboard/soar/page.tsx", "const CASES"),
    ("app/dashboard/soar/page.tsx", "const PLAYBOOKS"),
    ("app/dashboard/soar/playbooks/page.tsx", "const PLAYBOOKS"),
    # The feeds page went furthest: on an API failure it showed seeded threats
    # AND ran a simulator that invented a new one every 8-14 seconds, animated
    # and pulsing, so an analyst watched fiction arrive live during an outage.
    ("app/dashboard/feeds/page.tsx", "const CONFIRMED_SEED"),
    ("app/dashboard/feeds/page.tsx", "const UNCONFIRMED_SEED"),
    ("app/dashboard/feeds/page.tsx", "const SOURCES_FALLBACK"),
    ("app/dashboard/feeds/page.tsx", "function makeLiveEntry"),
]


def test_no_live_page_carries_a_fabricated_dataset():
    """Each of these rendered invented security findings to a real analyst when
    an API call failed. Removing the fallback is not enough on its own - while
    the data is still in the bundle it is one conditional away from coming
    back, which is exactly how it got there."""
    if not _FRONTEND.is_dir():                       # backend-only checkout
        return
    offenders = []
    for rel, ident in _BANNED:
        p = _FRONTEND / rel
        # Whole identifier, anchored to the start of a line. A substring check
        # flags `SOURCES_ACTIVE`; dropping the anchor flags the INDENTED local
        # alias `const CASES = casesData`. Both are live code, and a guard that
        # cries wolf gets deleted, which would cost more than it saves. The
        # fabricated datasets were all module-level declarations.
        rx = re.compile(rf"^{re.escape(ident)}\b", re.MULTILINE)
        if p.is_file() and rx.search(p.read_text(encoding="utf-8")):
            offenders.append(f"{rel}: {ident}")
    assert not offenders, (
        "fabricated dataset(s) back in a live page - render an honest "
        "'could not load' state instead:\n  " + "\n  ".join(offenders))


def test_no_live_page_falls_back_to_demo_data_when_the_api_fails():
    """The pattern itself, not just today's instances. `catch(() => setX(SOME_
    CONSTANT))` is the shape that turns an outage into fiction, and it reads as
    defensive coding, which is why it kept being written."""
    if not _FRONTEND.is_dir():
        return
    # A catch handler assigning a SCREAMING_CASE constant - i.e. a module-level
    # literal rather than anything the API returned. Checked per line: a
    # single regex over the whole handler cannot be written reliably, because
    # `.catch(() => ...)` closes a paren before the interesting part and every
    # attempt to allow that swallows half the file. This does not catch a
    # multi-line catch block, which is why the explicit list above exists too -
    # between them they cover the shape and the known instances.
    setter = re.compile(r"set[A-Z]\w*\(\s*[A-Z][A-Z_0-9]{3,}\s*\)")
    offenders = []
    for p in sorted((_FRONTEND / "app").rglob("*.tsx")) + \
            sorted((_FRONTEND / "components").rglob("*.tsx")):
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if ".catch(" in line and setter.search(line):
                offenders.append(f"{p.relative_to(_FRONTEND)}:{n}: {line.strip()[:70]}")
    assert not offenders, (
        "an API failure must never be answered with compiled-in data:\n  "
        + "\n  ".join(offenders))
