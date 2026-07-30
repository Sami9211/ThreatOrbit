"""Analyst conclusions feeding back into the intel store.

Until this existed, nothing an analyst concluded ever reached the store. An L1
could spend twenty minutes establishing that an indicator is a false positive in
this environment, write it in a case note, and the store would score it exactly
the same way next week - for the next analyst, who would spend the same twenty
minutes.

The load-bearing test is `test_a_conclusion_reached_today_changes_tomorrows_ranking`:
that is Phase 6's done-criterion stated as code.
"""
import uuid

import pytest

from dashboard_api import verdicts as vm
from dashboard_api.db import get_conn


def _mkioc(conn, **kw):
    iid = f"vd-{uuid.uuid4().hex[:10]}"
    val = kw.get("value") or f"verdict-{uuid.uuid4().hex[:8]}.test"
    conn.execute(
        "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
        "first_seen,last_seen,tags,status,sightings,intel_score,org_id) "
        "VALUES (?,'domain',?,'phishing',80,'high','feed-a','', ?,?,'[]','active',1,?,?)",
        (iid, val, kw.get("seen", "2026-07-30T00:00:00+00:00"),
         kw.get("seen", "2026-07-30T00:00:00+00:00"), kw.get("score", 0),
         kw.get("org", "org-default")))
    return iid, val


@pytest.fixture
def store():
    ids, vals = [], []
    with get_conn() as conn:
        yield conn, ids, vals
        if ids:
            ph = ",".join("?" * len(ids))
            conn.execute(f"DELETE FROM iocs WHERE id IN ({ph})", tuple(ids))
        if vals:
            ph = ",".join("?" * len(vals))
            conn.execute(f"DELETE FROM ioc_verdicts WHERE ioc_value IN ({ph})", tuple(vals))
        conn.commit()


def test_an_unknown_verdict_is_refused_rather_than_stored(store):
    """A free-text verdict field is a field nobody can aggregate."""
    conn, ids, vals = store
    with pytest.raises(ValueError):
        vm.record(conn, value="x.test", verdict="probably-bad", analyst="a@b.c")
    with pytest.raises(ValueError):
        vm.record(conn, value="", verdict=vm.CONFIRMED, analyst="a@b.c")


def test_verdicts_append_rather_than_replace(store):
    """An indicator called a false positive in March and confirmed in July has a
    story. Overwriting the first conclusion would hide it."""
    conn, ids, vals = store
    val = f"hist-{uuid.uuid4().hex[:8]}.test"
    vals.append(val)
    vm.record(conn, value=val, verdict=vm.FALSE_POSITIVE, analyst="l1@x.com", reason="ours")
    vm.record(conn, value=val, verdict=vm.CONFIRMED, analyst="l2@x.com", reason="actually c2")
    conn.commit()
    h = vm.history(conn, val)
    assert len(h) == 2
    assert {x["verdict"] for x in h} == {vm.FALSE_POSITIVE, vm.CONFIRMED}
    assert all(x["analyst"] and x["ts"] for x in h)


def test_a_false_positive_lowers_the_score_and_confirmation_raises_it():
    from dashboard_api.intel_scoring import score_indicator
    ioc = {"type": "domain", "confidence": 80, "last_seen": None, "actor": ""}
    baseline = score_indicator(ioc)["score"]
    fp = score_indicator(ioc, verdict_shift=vm.WEIGHT[vm.FALSE_POSITIVE])["score"]
    conf = score_indicator(ioc, verdict_shift=vm.WEIGHT[vm.CONFIRMED])["score"]
    assert fp < baseline < conf, f"{fp} !< {baseline} !< {conf}"


def test_an_analyst_conclusion_outweighs_any_single_feed():
    """Our own analysts looking at our own environment is better evidence than a
    list's assertion about the internet in general."""
    from dashboard_api.intel_scoring import CORROBORATION_FIRST
    assert abs(vm.WEIGHT[vm.FALSE_POSITIVE]) > CORROBORATION_FIRST
    assert vm.WEIGHT[vm.CONFIRMED] > CORROBORATION_FIRST


def test_benign_here_is_milder_than_a_wrong_feed_entry():
    """The indicator may be perfectly real - it is just expected traffic in this
    network. Suppressing it as hard as a false positive would lose that."""
    assert vm.WEIGHT[vm.FALSE_POSITIVE] < vm.WEIGHT[vm.BENIGN_HERE] < 0


def test_accumulated_verdicts_are_capped():
    """Ten analysts agreeing is not ten times the evidence of one, and without a
    cap a busy queue would drive every score to the floor."""
    huge = {vm.FALSE_POSITIVE: 50}
    assert vm.shift_for(huge) == -vm.MAX_SHIFT
    assert vm.shift_for({vm.CONFIRMED: 50}) == vm.MAX_SHIFT
    assert vm.shift_for({}) == 0


def test_opposing_verdicts_partly_cancel_rather_than_the_loudest_winning(store):
    conn, ids, vals = store
    val = f"split-{uuid.uuid4().hex[:8]}.test"
    vals.append(val)
    vm.record(conn, value=val, verdict=vm.CONFIRMED, analyst="a@x.com")
    vm.record(conn, value=val, verdict=vm.FALSE_POSITIVE, analyst="b@x.com")
    conn.commit()
    s = vm.summary(conn, val)
    assert s["total"] == 2
    expected = vm.WEIGHT[vm.CONFIRMED] + vm.WEIGHT[vm.FALSE_POSITIVE]
    assert s["shift"] == expected


def test_verdicts_are_scoped_to_a_tenant(store):
    """One customer concluding "false positive in our environment" must never
    silently suppress another customer's intel."""
    conn, ids, vals = store
    val = f"tenant-{uuid.uuid4().hex[:8]}.test"
    vals.append(val)
    vm.record(conn, value=val, verdict=vm.FALSE_POSITIVE, analyst="a@x.com", org_id="org-a")
    conn.commit()
    assert vm.summary(conn, val, "org-a")["shift"] < 0
    assert vm.summary(conn, val, "org-b")["shift"] == 0
    assert vm.history(conn, val, "org-b") == []
    assert "org-b" not in str(vm.all_shifts(conn, "org-b"))
    assert vm.all_shifts(conn, "org-b") == {} or val not in vm.all_shifts(conn, "org-b")


def test_all_shifts_is_one_query_shaped_for_the_decay_pass(store):
    """The decay pass rescores every indicator; a per-row verdict query there
    would be 315k round trips."""
    conn, ids, vals = store
    a = f"bulk-a-{uuid.uuid4().hex[:6]}.test"
    b = f"bulk-b-{uuid.uuid4().hex[:6]}.test"
    vals += [a, b]
    vm.record(conn, value=a, verdict=vm.FALSE_POSITIVE, analyst="x@y.z")
    vm.record(conn, value=b, verdict=vm.CONFIRMED, analyst="x@y.z")
    conn.commit()
    shifts = vm.all_shifts(conn)
    assert shifts[a] == vm.WEIGHT[vm.FALSE_POSITIVE]
    assert shifts[b] == vm.WEIGHT[vm.CONFIRMED]


def test_a_conclusion_reached_today_changes_tomorrows_ranking(store):
    """PHASE 6 DONE-CRITERION, as code: "a conclusion reached on Tuesday affects
    Wednesday's scoring". Before this, nothing an analyst concluded ever reached
    the store's own ranking."""
    from dashboard_api.ioc_lifecycle import decay_iocs
    conn, ids, vals = store
    iid, val = _mkioc(conn)
    ids.append(iid); vals.append(val)
    conn.commit()

    decay_iocs(conn); conn.commit()
    before = conn.execute("SELECT intel_score FROM iocs WHERE id=?", (iid,)).fetchone()[0]

    vm.record(conn, value=val, verdict=vm.FALSE_POSITIVE, analyst="l2@x.com",
              reason="internal scanner, not attacker infrastructure")
    conn.commit()

    decay_iocs(conn); conn.commit()
    after = conn.execute("SELECT intel_score FROM iocs WHERE id=?", (iid,)).fetchone()[0]
    assert after < before, (
        f"the maintenance pass ignored the analyst's conclusion: {before} -> {after}")


def test_the_score_breakdown_names_the_conclusion_and_still_reconciles():
    """A score that dropped 35 points overnight has to be explainable to the
    analyst who comes to it next."""
    from dashboard_api.intel_scoring import score_indicator
    res = score_indicator({"type": "domain", "confidence": 80, "last_seen": None,
                           "actor": ""},
                          verdict_shift=vm.WEIGHT[vm.FALSE_POSITIVE],
                          verdict_note="1 conclusion from your team")
    labels = [c["label"] for c in res["components"]]
    assert "Analyst conclusion" in labels
    assert sum(c["delta"] for c in res["components"]) == res["score"], (
        "the components no longer add up to the score")


def test_a_negative_verdict_that_floors_the_score_still_reconciles():
    """The clamp note used to say "the scale stops at 100" unconditionally, which
    is the wrong end when an analyst verdict drives the total below zero."""
    from dashboard_api.intel_scoring import score_indicator
    res = score_indicator({"type": "domain", "confidence": 10, "last_seen": None,
                           "actor": ""}, verdict_shift=-40)
    assert res["score"] == 0
    assert sum(c["delta"] for c in res["components"]) == 0
    floored = [c for c in res["components"] if c["label"] == "Floored"]
    assert floored and "starts at 0" in floored[0]["why"]


def test_api_records_a_verdict_and_rescores_immediately(client, auth):
    """An analyst who has just concluded something needs the queue to reflect it,
    or they will reasonably assume the button did nothing."""
    with get_conn() as conn:
        iid, val = _mkioc(conn, score=70)
        conn.commit()
    try:
        r = client.post(f"/cti/iocs/{iid}/verdict",
                        json={"verdict": "false-positive", "reason": "our own scanner"},
                        headers=auth)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["verdict"]["verdict"] == "false-positive"
        assert body["summary"]["total"] == 1
        assert any(c["label"] == "Analyst conclusion" for c in body["scoreComponents"])
        with get_conn() as conn:
            stored = conn.execute("SELECT intel_score FROM iocs WHERE id=?",
                                  (iid,)).fetchone()[0]
        assert stored == body["intelScore"], "the stored score was not updated"

        listed = client.get(f"/cti/iocs/{iid}/verdicts", headers=auth).json()
        assert len(listed["history"]) == 1
        assert set(listed["options"]) == set(vm.VERDICTS)
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM iocs WHERE id=?", (iid,))
            conn.execute("DELETE FROM ioc_verdicts WHERE ioc_value=?", (val,))
            conn.commit()


def test_api_rejects_a_junk_verdict_and_an_unknown_indicator(client, auth):
    with get_conn() as conn:
        iid, val = _mkioc(conn)
        conn.commit()
    try:
        bad = client.post(f"/cti/iocs/{iid}/verdict", json={"verdict": "sus"}, headers=auth)
        assert bad.status_code == 400, bad.text
        missing = client.post("/cti/iocs/nope/verdict",
                              json={"verdict": "confirmed"}, headers=auth)
        assert missing.status_code == 404
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM iocs WHERE id=?", (iid,))
            conn.execute("DELETE FROM ioc_verdicts WHERE ioc_value=?", (val,))
            conn.commit()


def test_the_detail_endpoint_surfaces_the_conclusion_history(client, auth):
    with get_conn() as conn:
        iid, val = _mkioc(conn)
        conn.commit()
    try:
        client.post(f"/cti/iocs/{iid}/verdict",
                    json={"verdict": "confirmed", "reason": "seen beaconing"}, headers=auth)
        d = client.get(f"/cti/iocs/{iid}", headers=auth).json()
        assert len(d["verdicts"]) == 1
        assert d["verdictSummary"]["latest"]["verdict"] == "confirmed"
        assert any(c["label"] == "Analyst conclusion" for c in d["scoreComponents"])
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM iocs WHERE id=?", (iid,))
            conn.execute("DELETE FROM ioc_verdicts WHERE ioc_value=?", (val,))
            conn.commit()
