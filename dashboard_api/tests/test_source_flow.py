"""Log-source flow attribution: live events/24h instead of a frozen snapshot.

`log_sources.total_events_24h` is written once at seed/registration and never
updated, so the sources page showed a frozen number. Events now carry the
ingest `source` name; a source whose name appears in the event flow gets a
live windowed count (and last-event), while never-wired sources (e.g. seeded
demo rows) keep their stored sample values.
"""
import uuid
from datetime import datetime, timedelta, timezone

from dashboard_api.db import get_conn


def _insert_event(conn, source: str, ts_iso: str) -> None:
    conn.execute(
        "INSERT INTO events (id,ts,category,source,processed) VALUES (?,?,?,?,1)",
        (str(uuid.uuid4()), ts_iso, "network", source),
    )


def _source_row(client, auth, name: str) -> dict:
    return next(s for s in client.get("/siem/sources", headers=auth).json()
                if s["name"] == name)


def test_wired_source_gets_live_24h_count_and_last_event(client, auth):
    name = f"pytest-src-{uuid.uuid4().hex[:8]}"
    r = client.post("/siem/sources", json={"name": name, "type": "Syslog"}, headers=auth)
    assert r.status_code == 201

    now = datetime.now(timezone.utc)
    old = (now - timedelta(hours=30)).replace(microsecond=0).isoformat()     # outside 24h
    recent = (now - timedelta(minutes=10)).replace(microsecond=0).isoformat()

    with get_conn() as conn:
        for _ in range(3):
            _insert_event(conn, name, old)
        for _ in range(2):
            _insert_event(conn, name, recent)
        conn.commit()

    row = _source_row(client, auth, name)
    assert row["total_events_24h"] == 2      # only the 2 within 24h; not 5, not frozen
    assert row["last_event"] == recent       # real newest event timestamp


def test_quiet_wired_source_shows_zero_not_stale(client, auth):
    """A source that HAS flowed events but none in the last 24h must show a
    truthful 0 - not fall back to a stale stored number."""
    name = f"pytest-quiet-{uuid.uuid4().hex[:8]}"
    assert client.post("/siem/sources", json={"name": name, "type": "Syslog"},
                       headers=auth).status_code == 201
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        _insert_event(conn, name, old)
        conn.commit()
    assert _source_row(client, auth, name)["total_events_24h"] == 0


def test_never_wired_source_keeps_stored_value(client, auth):
    """Seeded demo sources have no matching events - their stored sample values
    must pass through untouched (demo stays sample-data by contract)."""
    sources = client.get("/siem/sources", headers=auth).json()
    seeded = next((s for s in sources if s["name"] == "Palo Alto Firewall"), None)
    assert seeded is not None
    with get_conn() as conn:
        stored = conn.execute(
            "SELECT total_events_24h FROM log_sources WHERE name='Palo Alto Firewall'"
        ).fetchone()["total_events_24h"]
    assert seeded["total_events_24h"] == stored


def test_ingest_stamps_source_on_events(client, auth):
    """The ingest path records its source name on each stored event - the
    attribution everything above depends on."""
    src = f"pytest-ingest-{uuid.uuid4().hex[:8]}"
    r = client.post("/siem/ingest", headers=auth, json={
        "lines": ['{"event_type": "connection", "src_ip": "203.0.113.7"}'],
        "format": "json", "source": src,
    })
    assert r.status_code == 200
    assert r.json()["parsed"] == 1
    with get_conn() as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM events WHERE source=?", (src,)).fetchone()["n"]
    assert n == 1


def test_ingest_auto_registers_unknown_source(client, auth):
    """A collector ingesting under a name with no log_sources row must appear
    on SIEM → Sources automatically (zero-setup discovery), with the live
    Events(24h) count attached - and repeat ingests must not duplicate it."""
    src = f"pytest-auto-{uuid.uuid4().hex[:8]}"
    line = '{"event_type": "connection", "src_ip": "203.0.113.20"}'
    for _ in range(2):  # two batches: first registers, second must not duplicate
        r = client.post("/siem/ingest", headers=auth,
                        json={"lines": [line], "format": "json", "source": src})
        assert r.status_code == 200 and r.json()["parsed"] == 1

    rows = [s for s in client.get("/siem/sources", headers=auth).json()
            if s["name"] == src]
    assert len(rows) == 1                      # discovered exactly once
    assert rows[0]["total_events_24h"] == 2    # live count covers both batches
    assert "auto-discovered" in rows[0]["tags"]


def test_zz_init_db_upgrades_pre_source_schema(client):
    """Upgrade fence: a deployment whose events table predates the `source`
    column must boot cleanly across this change. The subtle failure mode is
    Postgres-specific: the schema pass hits `idx_events_source` before the
    migration has added the column, and the error both isn't a
    sqlite3.OperationalError (so the old tolerant path missed it) and aborts
    the transaction (so every later statement failed too). init_db must
    tolerate the bad index, add the column via migration, then create the
    index on the second pass. (zz-prefix: runs last - it drops/re-adds the
    column, nulling `source` on rows earlier tests created.)"""
    from dashboard_api.db import init_db
    with get_conn() as conn:
        conn.execute("DROP INDEX IF EXISTS idx_events_source")
        conn.execute("ALTER TABLE events DROP COLUMN source")
        conn.commit()

    init_db()  # must not raise

    with get_conn() as conn:
        conn.execute("SELECT source FROM events LIMIT 1")  # column restored
        _insert_event(conn, "post-upgrade", datetime.now(timezone.utc).isoformat())
        conn.commit()
        n = conn.execute("SELECT COUNT(*) AS n FROM events WHERE source='post-upgrade'").fetchone()["n"]
    assert n == 1
