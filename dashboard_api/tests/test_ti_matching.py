"""Threat-intel matching: whether the store can actually fire on local telemetry.

The store holds 208,845 domains, 68,457 IPs and 50,678 URLs. The matching pass
compared `src_ip` and `dest_ip` against indicators of severity critical or high -
so 5,466 values, 1.7% of the store, were reachable from a log line. Every domain
and every URL was structurally undetectable no matter how well corroborated,
because the event model had no field naming what the traffic was AIMED at:
`hostname` is the box that wrote the log.

These pin the three properties that fix follows from: the destination is
captured, every observable type is compared, and an event is examined once.
"""
import uuid

from dashboard_api.db import get_conn
from dashboard_api.ingest import ingest_lines, match_threat_intel, parse_line


def _ioc(conn, itype, value, *, severity="high", score=60):
    iid = f"ti-{uuid.uuid4().hex[:12]}"
    conn.execute(
        "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
        "first_seen,last_seen,tags,status,sightings,intel_score) "
        "VALUES (?,?,?,?,80,?,'test-feed','','2026-01-01T00:00:00+00:00',"
        "'2026-01-01T00:00:00+00:00','[]','active',1,?)",
        (iid, itype, value, "malware-c2", severity, score))
    return iid


def _sightings(conn, iid):
    return conn.execute("SELECT sightings FROM iocs WHERE id=?", (iid,)).fetchone()["sightings"]


def _cleanup(conn, iid, value):
    conn.execute("DELETE FROM ioc_sightings WHERE ioc_id=?", (iid,))
    conn.execute("DELETE FROM iocs WHERE id=?", (iid,))
    conn.execute("DELETE FROM alerts WHERE ti_value=?", (value,))
    conn.execute("DELETE FROM events WHERE dest_host=? OR url=? OR src_ip=?",
                 (value, value, value))


# -- the destination is captured at all ------------------------------------


def test_a_dns_query_names_its_destination_not_the_reporting_host():
    """Sysmon 22 is the best domain telemetry most estates have: it names the
    process that asked, on the endpoint that asked, before a connection exists.
    `Computer` is the endpoint; `QueryName` is what it looked up. Reading the
    second as the first is how a DNS log matches nothing."""
    ev = parse_line('{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":22,'
                    '"Computer":"WKS-014","QueryName":"c2.evil-example.test",'
                    '"Image":"C:\\\\Windows\\\\System32\\\\rundll32.exe"}', "json")
    assert ev["hostname"] == "WKS-014", "the reporting endpoint"
    assert ev["dest_host"] == "c2.evil-example.test", "what it tried to reach"


def test_fortigate_spells_the_visited_site_in_hostname_and_the_device_in_devname():
    """The opposite of the syslog convention, and FortiGate webfilter logs are
    the richest domain source most networks have. Its `url` is the path alone,
    so the two have to be recombined rather than stored as a bare slash."""
    ev = parse_line('date=2026-07-30 devname="FG100F" devid="FG100F0000" '
                    'type="utm" subtype="webfilter" srcip=10.1.1.5 '
                    'hostname="phish.evil-example.test" url="/login" action="blocked"', "kv")
    assert ev["dest_host"] == "phish.evil-example.test"
    assert ev["hostname"] == "FG100F", "devname is the appliance"
    assert ev["url"] == "http://phish.evil-example.test/login", (
        "a bare path matches nothing; the host is what makes it a URL")


def test_a_proxy_that_logs_only_a_url_still_yields_the_domain():
    """The store holds four times as many domains as URLs, so deriving the host
    is the difference between matching one exact URL and matching the domain
    every feed actually lists."""
    ev = parse_line('{"src_ip":"10.2.2.9","url":"https://bad.evil-example.test:8443/a/b?c=d"}',
                    "json")
    assert ev["url"] == "https://bad.evil-example.test:8443/a/b?c=d"
    assert ev["dest_host"] == "bad.evil-example.test", "port and path stripped"


def test_ecs_documents_normalise_their_destination_however_they_spell_it():
    """ECS spreads the same fact across four fields depending on the producer."""
    for doc, expected in [
        ('{"dns":{"question":{"name":"a.evil-example.test"}}}', "a.evil-example.test"),
        ('{"destination":{"domain":"b.evil-example.test"}}', "b.evil-example.test"),
        ('{"url":{"domain":"c.evil-example.test"}}', "c.evil-example.test"),
        ('{"tls":{"client":{"server_name":"d.evil-example.test"}}}', "d.evil-example.test"),
    ]:
        assert parse_line(doc, "json")["dest_host"] == expected, doc


def test_a_domain_mentioned_in_prose_is_not_a_destination():
    """A wrong destination is worse than a missing one: it silently matches the
    customer's own estate. Only a field the producer LABELLED as the destination
    may set this - never a word from the raw line that happened to have a dot."""
    ev = parse_line("Jan 10 11:00:00 fw01 user reported a phishing mail from "
                    "evil-example.test to the helpdesk", "auto")
    assert ev["dest_host"] is None
    assert ev["url"] is None


# -- every observable type is compared -------------------------------------


def test_a_domain_indicator_fires_on_a_dns_query(client, auth):
    """The headline gap. 208,845 domains in the store and no channel by which any
    of them could ever match a log line."""
    value = "c2.match-domain-test.invalid"
    with get_conn() as conn:
        iid = _ioc(conn, "domain", value, severity="high")
        conn.commit()
    try:
        out = ingest_lines([f'{{"src_ip":"10.9.9.9","query":"{value}"}}'], "json")
        assert out["tiMatches"] >= 1, "a malicious domain looked up here must alert"
        with get_conn() as conn:
            assert _sightings(conn, iid) == 2, "the lookup is a sighting"
            assert conn.execute(
                "SELECT 1 FROM alerts WHERE rule_id='R-TIMATCH' AND ti_value=?",
                (value,)).fetchone(), "the alert must record WHAT it matched"
    finally:
        with get_conn() as conn:
            _cleanup(conn, iid, value)
            conn.commit()


def test_a_url_indicator_fires_on_a_proxy_log(client, auth):
    value = "https://drop.match-url-test.invalid/payload.bin"
    with get_conn() as conn:
        iid = _ioc(conn, "url", value, severity="high")
        conn.commit()
    try:
        ingest_lines([f'{{"src_ip":"10.9.9.8","url":"{value}"}}'], "json")
        with get_conn() as conn:
            assert _sightings(conn, iid) == 2
    finally:
        with get_conn() as conn:
            _cleanup(conn, iid, value)
            conn.commit()


def test_a_match_is_always_a_sighting_but_only_some_matches_are_alerts(client, auth):
    """Matching and alerting are different decisions, and conflating them is what
    kept 98% of the store out of local detection. A Tor exit node or a scanning
    source in a firewall log is a fact about the internet, not an incident - but
    it is still evidence that this network touched it, and the score is entitled
    to know."""
    value = "noisy.match-medium-test.invalid"
    with get_conn() as conn:
        iid = _ioc(conn, "domain", value, severity="medium", score=30)
        conn.commit()
    try:
        out = ingest_lines([f'{{"src_ip":"10.9.9.7","query":"{value}"}}'], "json")
        with get_conn() as conn:
            assert _sightings(conn, iid) == 2, (
                "a medium-severity match is still evidence and must be recorded")
            assert not conn.execute(
                "SELECT 1 FROM alerts WHERE rule_id='R-TIMATCH' AND ti_value=?",
                (value,)).fetchone(), "scanning noise must not wake anyone"
        assert out["tiMatches"] == 0
    finally:
        with get_conn() as conn:
            _cleanup(conn, iid, value)
            conn.commit()


# -- an event is examined exactly once -------------------------------------


def test_an_event_is_counted_once_however_often_the_pass_runs(client, auth):
    """The pass keyed off `processed`, which the detection queue sets to 1 the
    moment detection completes - so every later ingest re-examined the same
    recent events and recorded a fresh sighting each time. Sightings feed the one
    score term that outranks any amount of third-party agreement, so the
    inflation went straight into the ranking."""
    value = "once.match-idempotent-test.invalid"
    with get_conn() as conn:
        iid = _ioc(conn, "domain", value)
        conn.commit()
    try:
        ingest_lines([f'{{"src_ip":"10.9.9.6","query":"{value}"}}'], "json")
        with get_conn() as conn:
            first = _sightings(conn, iid)
        for _ in range(3):
            with get_conn() as conn:
                assert match_threat_intel(conn) == 0
                conn.commit()
        with get_conn() as conn:
            assert _sightings(conn, iid) == first, (
                f"re-running the pass inflated sightings {first} -> "
                f"{_sightings(conn, iid)}")
    finally:
        with get_conn() as conn:
            _cleanup(conn, iid, value)
            conn.commit()


def test_a_backlog_larger_than_one_batch_is_drained_not_truncated(client, auth):
    """`ORDER BY ts DESC LIMIT 300` is a recency window, not a queue: on a burst
    the older events were never examined by anything, ever. A marker turns the
    same bound into a batch size that drains over consecutive passes."""
    value = "deep.match-backlog-test.invalid"
    with get_conn() as conn:
        iid = _ioc(conn, "domain", value)
        # One matching event, then a wall of newer non-matching ones. Under a
        # recency window the match is pushed out of view and silently lost.
        conn.execute(
            "INSERT INTO events (id,ts,category,event_type,dest_host,source,processed,ti_checked) "
            "VALUES (?,'2026-01-01T00:00:00+00:00','network','dns_query',?,'test',1,0)",
            (f"ev-{uuid.uuid4().hex[:12]}", value))
        conn.executemany(
            "INSERT INTO events (id,ts,category,event_type,dest_host,source,processed,ti_checked) "
            "VALUES (?,?,'network','dns_query',?,'test',1,0)",
            [(f"ev-{uuid.uuid4().hex[:12]}", f"2026-06-01T00:{i // 60:02d}:{i % 60:02d}+00:00",
              f"benign-{i}.match-backlog-test.invalid") for i in range(600)])
        conn.commit()
    try:
        drained = 0
        with get_conn() as conn:
            for _ in range(5):                      # 601 events, 500 per pass
                match_threat_intel(conn)
                conn.commit()
                drained = conn.execute(
                    "SELECT COUNT(*) AS n FROM events WHERE ti_checked=0").fetchone()["n"]
                if drained == 0:
                    break
            assert drained == 0, f"{drained} events never examined"
            assert _sightings(conn, iid) == 2, "the oldest event still had to be seen"
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM events WHERE dest_host LIKE ?",
                         ("%match-backlog-test.invalid",))
            _cleanup(conn, iid, value)
            conn.commit()


def test_upgrading_does_not_re_sight_the_whole_event_backlog():
    """A database upgraded into this change already has events, and they have all
    been through the matching pass - repeatedly. Letting the new marker sweep
    them would record a second sighting for observations already counted, so an
    upgrade would silently re-rank the store on the day it was applied."""
    import sqlite3

    from dashboard_api.db import _adopt_existing_events

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE events (id TEXT PRIMARY KEY, ti_checked INTEGER "
                 "NOT NULL DEFAULT 0)")
    conn.executemany("INSERT INTO events (id) VALUES (?)", [(f"e{i}",) for i in range(25)])
    assert _adopt_existing_events(conn) == 25
    assert conn.execute("SELECT COUNT(*) FROM events WHERE ti_checked=0").fetchone()[0] == 0, (
        "an upgraded backlog must not be re-examined")


def test_the_live_scheduler_drains_events_the_ingest_endpoint_never_saw():
    """`/siem/ingest` runs a pass over its own batch, but that is not the only
    way events arrive: the syslog/TLS listeners, the agentless S3 pull and the
    detection worker pool all write events no ingest call ever touches. Without a
    drain on the scheduler those sit at ti_checked=0 forever and the question
    "did anything here touch a known-bad value?" is simply never asked of them."""
    import inspect
    from dashboard_api import main

    src = inspect.getsource(main._connector_scheduler)
    assert "match_threat_intel" in src, (
        "TI matching must run on the live scheduler, not only on the ingest path")


def test_one_standing_alert_per_value_however_many_events_match(client, auth):
    """A beaconing host asks the same question every few seconds. A queue of
    identical alerts is how a real one gets missed."""
    value = "beacon.match-dedup-test.invalid"
    with get_conn() as conn:
        iid = _ioc(conn, "domain", value)
        conn.commit()
    try:
        for _ in range(3):
            ingest_lines([f'{{"src_ip":"10.9.9.5","query":"{value}"}}'], "json")
        with get_conn() as conn:
            n = conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE rule_id='R-TIMATCH' AND ti_value=?",
                (value,)).fetchone()["n"]
            assert n == 1, f"{n} alerts for one indicator"
            assert _sightings(conn, iid) == 4, (
                "every observation is still a sighting - only the ALERT is deduped")
    finally:
        with get_conn() as conn:
            _cleanup(conn, iid, value)
            conn.commit()
