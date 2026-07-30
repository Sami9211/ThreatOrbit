"""An indicator's history, assembled from the four tables that hold pieces of it.

"Score 74, active, three sources" answers what we think NOW and nothing about how
we got there: whether it was corroborated on arrival or a fortnight later, whether
this deployment has ever seen it, whether somebody already looked at it and called
it a false positive. All of that was recorded and none of it was ever assembled,
so every analyst who met the same indicator started from the same blank page.
"""
import uuid

from dashboard_api.db import audit, get_conn


def _seed(conn, value):
    iid = f"tl-{uuid.uuid4().hex[:12]}"
    conn.execute(
        "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
        "first_seen,last_seen,tags,status,sightings,intel_score) "
        "VALUES (?,'domain',?,'malware-c2',80,'high','feed-a','',"
        "'2026-01-01T00:00:00+00:00','2026-01-05T00:00:00+00:00','[]','active',1,60)",
        (iid, value))
    conn.executemany(
        "INSERT INTO observable_sources (value,source_id,first_seen,last_seen,raw_label,"
        "confidence) VALUES (?,?,?,?,?,80) ON CONFLICT(value,source_id) DO NOTHING",
        [(value, "feed-a", "2026-01-01T00:00:00+00:00", "2026-01-05T00:00:00+00:00", "c2"),
         (value, "feed-b", "2026-01-03T00:00:00+00:00", "2026-01-03T00:00:00+00:00", "")])
    conn.execute(
        "INSERT INTO ioc_sightings (id,ioc_id,ts,source,context) VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), iid, "2026-01-04T00:00:00+00:00", "siem:event",
         "event ev-1 matched"))
    audit(conn, "analyst@example.test", "ioc.known_good", iid, "whitelisted for pilot")
    return iid


def _clean(conn, iid, value):
    conn.execute("DELETE FROM ioc_sightings WHERE ioc_id=?", (iid,))
    conn.execute("DELETE FROM observable_sources WHERE value=?", (value,))
    conn.execute("DELETE FROM audit_log WHERE target=?", (iid,))
    conn.execute("DELETE FROM ioc_verdicts WHERE ioc_value=?", (value,))
    conn.execute("DELETE FROM iocs WHERE id=?", (iid,))


def test_the_timeline_merges_every_table_that_holds_part_of_the_story(client, auth):
    value = f"timeline-{uuid.uuid4().hex[:8]}.invalid"
    with get_conn() as conn:
        iid = _seed(conn, value)
        conn.commit()
    try:
        client.post(f"/cti/iocs/{iid}/verdict", headers=auth,
                    json={"verdict": "false-positive", "reason": "our own CDN"})
        body = client.get(f"/cti/iocs/{iid}/timeline", headers=auth).json()
        kinds = {e["kind"] for e in body["items"]}
        assert {"asserted", "sighting", "verdict", "action"} <= kinds, (
            f"the timeline is missing part of the story: {sorted(kinds)}")
        # Two sources asserted it, and one of them re-asserted later. Collapsing
        # those loses the only freshness evidence there is.
        assert sum(1 for e in body["items"] if e["kind"] == "asserted") == 2
        assert any(e["kind"] == "reasserted" for e in body["items"]), (
            "'still listed on 5 Jan' is a different claim from 'first listed on "
            "1 Jan' and must survive the merge")
    finally:
        with get_conn() as conn:
            _clean(conn, iid, value)
            conn.commit()


def test_the_timeline_is_ordered_newest_first_and_deterministically(client, auth):
    """Several of these tables carry only second precision, so without a
    secondary key a same-second group comes back in whatever order the backend
    felt like - and SQLite and Postgres do not feel the same way."""
    value = f"timeline-{uuid.uuid4().hex[:8]}.invalid"
    with get_conn() as conn:
        iid = _seed(conn, value)
        conn.commit()
    try:
        first = [(e["ts"], e["kind"]) for e in
                 client.get(f"/cti/iocs/{iid}/timeline", headers=auth).json()["items"]]
        again = [(e["ts"], e["kind"]) for e in
                 client.get(f"/cti/iocs/{iid}/timeline", headers=auth).json()["items"]]
        assert first == again, "two identical requests returned different orders"
        assert first == sorted(first, reverse=True), "newest must lead"
    finally:
        with get_conn() as conn:
            _clean(conn, iid, value)
            conn.commit()


def test_lifecycle_transitions_are_absent_rather_than_reconstructed(client, auth):
    """Expiry and reactivation are not recorded as events anywhere. Deriving them
    from timestamps would put an event on the timeline that nobody witnessed,
    which is worse than the gap - the gap is honest about what we know."""
    value = f"timeline-{uuid.uuid4().hex[:8]}.invalid"
    with get_conn() as conn:
        iid = _seed(conn, value)
        conn.execute("UPDATE iocs SET status='expired' WHERE id=?", (iid,))
        conn.commit()
    try:
        items = client.get(f"/cti/iocs/{iid}/timeline", headers=auth).json()["items"]
        assert not [e for e in items if e["kind"] in ("expired", "revoked", "reactivated")]
    finally:
        with get_conn() as conn:
            _clean(conn, iid, value)
            conn.commit()


def test_the_timeline_404s_across_tenants_like_every_other_id_addressed_read(client, auth):
    assert client.get("/cti/iocs/no-such-ioc/timeline", headers=auth).status_code == 404
