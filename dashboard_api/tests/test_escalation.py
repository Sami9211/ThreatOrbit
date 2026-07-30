"""Tiered SOC queues and hand-offs.

A SOC is tiered: L1 triages, L2 investigates what L1 could not close, L3 does
attribution. The platform had RBAC capabilities and no workflow on top of them,
so "escalating" meant editing an owner field and the receiving analyst inherited
a case with no statement of what had been ruled out or why it was passed on.

The moment that matters is the HAND-OFF, and these pin it as a first-class,
append-only event rather than a field change.
"""
import uuid

import pytest

from dashboard_api import escalation as esc
from dashboard_api.db import get_conn


def _mkcase(conn, **kw):
    cid = f"esc-{uuid.uuid4().hex[:10]}"
    conn.execute(
        "INSERT INTO cases (id,title,type,severity,status,owner,sla_hours,created,"
        "updated,alert_count,description,entities,war_room,tasks,evidence,tier,org_id) "
        "VALUES (?,?,'investigation',?,?,?,?,?,?,0,'','[]','[]','[]','[]',?,?)",
        (cid, kw.get("title", f"Case {cid}"), kw.get("severity", "high"),
         kw.get("status", "open"), kw.get("owner"), kw.get("sla", 24),
         "2026-07-30T00:00:00+00:00", "2026-07-30T00:00:00+00:00",
         kw.get("tier", esc.TRIAGE), kw.get("org", "org-default")))
    return cid


@pytest.fixture
def cases():
    made = []
    with get_conn() as conn:
        yield conn, made
        if made:
            ph = ",".join("?" * len(made))
            conn.execute(f"DELETE FROM cases WHERE id IN ({ph})", tuple(made))
            conn.execute(f"DELETE FROM case_escalations WHERE case_id IN ({ph})", tuple(made))
            conn.commit()


def test_each_tier_has_its_own_sla():
    """A triage queue cleared within the hour and a research question that takes
    days cannot share one deadline - forcing them to is how SLA numbers stop
    meaning anything."""
    assert esc.sla_for(esc.TRIAGE) < esc.sla_for(esc.INVESTIGATION) < esc.sla_for(esc.RESEARCH)
    assert esc.sla_for(None) > 0 and esc.sla_for(99) > 0        # never zero


def test_a_handoff_records_who_to_whom_and_why(cases):
    conn, made = cases
    cid = _mkcase(conn, owner="l1@x.com")
    made.append(cid)
    conn.commit()
    ev = esc.escalate(conn, case_id=cid, to_tier=esc.INVESTIGATION,
                      actor="l1@x.com", to_owner="l2@x.com",
                      note="ruled out the proxy; the beacon interval is real")
    conn.commit()
    assert ev["fromTier"] == esc.TRIAGE and ev["toTier"] == esc.INVESTIGATION
    assert ev["fromOwner"] == "l1@x.com" and ev["toOwner"] == "l2@x.com"
    assert "beacon" in ev["note"]
    assert ev["actor"] == "l1@x.com" and ev["ts"]


def test_the_sla_moves_with_the_tier_and_the_clock_restarts(cases):
    """The receiving tier is not accountable for time spent before the case
    reached them."""
    conn, made = cases
    cid = _mkcase(conn, owner="l1@x.com", sla=esc.sla_for(esc.TRIAGE))
    made.append(cid)
    conn.commit()
    esc.escalate(conn, case_id=cid, to_tier=esc.RESEARCH, actor="l1@x.com")
    conn.commit()
    row = conn.execute("SELECT tier, sla_hours FROM cases WHERE id=?", (cid,)).fetchone()
    assert row["tier"] == esc.RESEARCH
    assert row["sla_hours"] == esc.sla_for(esc.RESEARCH)


def test_de_escalation_is_allowed(cases):
    """L2 establishing that something is routine and handing it back to L1 is a
    normal outcome. A workflow that only ratchets upward quietly pushes
    everything to the most expensive tier."""
    conn, made = cases
    cid = _mkcase(conn, owner="l2@x.com", tier=esc.INVESTIGATION)
    made.append(cid)
    conn.commit()
    ev = esc.escalate(conn, case_id=cid, to_tier=esc.TRIAGE, actor="l2@x.com",
                      to_owner="l1@x.com", note="routine scanner noise")
    conn.commit()
    assert ev["fromTier"] == esc.INVESTIGATION and ev["toTier"] == esc.TRIAGE


def test_history_is_append_only_and_ordered(cases):
    conn, made = cases
    cid = _mkcase(conn, owner="a@x.com")
    made.append(cid)
    conn.commit()
    esc.escalate(conn, case_id=cid, to_tier=esc.INVESTIGATION, actor="a@x.com",
                 to_owner="b@x.com")
    esc.escalate(conn, case_id=cid, to_tier=esc.RESEARCH, actor="b@x.com",
                 to_owner="c@x.com")
    conn.commit()
    h = esc.history(conn, cid)
    assert len(h) == 2, "a hand-off overwrote the previous one"
    assert h[0]["toTier"] == esc.RESEARCH, "history is not newest-first"


def test_a_no_op_handoff_is_refused_rather_than_padding_the_record(cases):
    """Recording "escalated from L2 to L2, same owner" would pad the chain of
    custody with noise."""
    conn, made = cases
    cid = _mkcase(conn, owner="a@x.com", tier=esc.INVESTIGATION)
    made.append(cid)
    conn.commit()
    with pytest.raises(ValueError):
        esc.escalate(conn, case_id=cid, to_tier=esc.INVESTIGATION, actor="a@x.com")


def test_an_unknown_tier_or_case_is_refused(cases):
    conn, made = cases
    cid = _mkcase(conn)
    made.append(cid)
    conn.commit()
    with pytest.raises(ValueError):
        esc.escalate(conn, case_id=cid, to_tier=9, actor="a@x.com")
    with pytest.raises(ValueError):
        esc.escalate(conn, case_id="nope", to_tier=esc.INVESTIGATION, actor="a@x.com")


def test_queue_counts_expose_what_nobody_has_claimed(cases):
    """The number that matters for two analysts working the same queue without
    stepping on each other is the pile with no owner."""
    conn, made = cases
    made.append(_mkcase(conn, tier=esc.TRIAGE, owner=None))
    made.append(_mkcase(conn, tier=esc.TRIAGE, owner="a@x.com"))
    made.append(_mkcase(conn, tier=esc.RESEARCH, owner=None))
    conn.commit()
    q = {row["tier"]: row for row in esc.queue_counts(conn)}
    assert set(q) == set(esc.TIERS), "every tier must appear, including empty ones"
    assert q[esc.TRIAGE]["open"] >= 2
    assert q[esc.TRIAGE]["unassigned"] >= 1
    assert q[esc.RESEARCH]["unassigned"] >= 1
    assert all(row["slaHours"] > 0 and row["name"] for row in q.values())


def test_closed_cases_leave_the_queue(cases):
    conn, made = cases
    cid = _mkcase(conn, tier=esc.TRIAGE, owner=None, status="closed")
    made.append(cid)
    conn.commit()
    before = {r["tier"]: r["open"] for r in esc.queue_counts(conn)}
    other = _mkcase(conn, tier=esc.TRIAGE, owner=None, status="open")
    made.append(other)
    conn.commit()
    after = {r["tier"]: r["open"] for r in esc.queue_counts(conn)}
    assert after[esc.TRIAGE] == before[esc.TRIAGE] + 1, "a closed case was counted"


def test_api_escalates_and_returns_the_chain_of_custody(client, auth):
    with get_conn() as conn:
        cid = _mkcase(conn, owner="l1@x.com")
        conn.commit()
    try:
        r = client.post(f"/soar/cases/{cid}/escalate",
                        json={"to_tier": 2, "to_owner": "l2@x.com",
                              "note": "needs host forensics"}, headers=auth)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["case"]["tier"] == 2
        assert body["case"]["tierName"].startswith("L2")
        assert body["case"]["owner"] == "l2@x.com"
        assert body["case"]["sla_hours"] == esc.sla_for(2)
        assert len(body["history"]) == 1
        assert body["history"][0]["note"] == "needs host forensics"

        listed = client.get(f"/soar/cases/{cid}/escalations", headers=auth).json()
        assert listed["tier"] == 2 and len(listed["history"]) == 1
        assert len(listed["tiers"]) == len(esc.TIERS)
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM cases WHERE id=?", (cid,))
            conn.execute("DELETE FROM case_escalations WHERE case_id=?", (cid,))
            conn.commit()


def test_api_rejects_a_bad_tier_and_an_unknown_case(client, auth):
    with get_conn() as conn:
        cid = _mkcase(conn)
        conn.commit()
    try:
        assert client.post(f"/soar/cases/{cid}/escalate", json={"to_tier": 42},
                           headers=auth).status_code == 400
        assert client.post("/soar/cases/nope/escalate", json={"to_tier": 2},
                           headers=auth).status_code == 404
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM cases WHERE id=?", (cid,))
            conn.commit()


def test_queues_endpoint_reports_every_tier(client, auth):
    q = client.get("/soar/queues", headers=auth).json()
    assert [row["tier"] for row in q] == list(esc.TIERS)
    assert all("unassigned" in row and "slaHours" in row for row in q)


def test_existing_cases_default_to_triage_rather_than_looking_escalated(cases):
    """The migration defaults tier to 1. A default of 2 would make every case
    that predates this feature appear to have been escalated by somebody."""
    conn, made = cases
    cid = f"esc-def-{uuid.uuid4().hex[:8]}"
    made.append(cid)
    conn.execute(
        "INSERT INTO cases (id,title,severity,status,sla_hours,created,updated) "
        "VALUES (?,?,'high','open',24,?,?)",
        (cid, "Pre-existing", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"))
    conn.commit()
    row = conn.execute("SELECT tier FROM cases WHERE id=?", (cid,)).fetchone()
    assert (row["tier"] or esc.TRIAGE) == esc.TRIAGE
