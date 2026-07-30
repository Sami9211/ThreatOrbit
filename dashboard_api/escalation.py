"""SOC tiers and hand-offs.

A SOC is tiered: L1 triages the queue, L2 investigates what L1 could not close,
L3 does attribution and threat research. The platform had RBAC capabilities and
no workflow on top of them, so "escalating" a case meant editing an owner field -
and the receiving analyst inherited a case with no statement of what had already
been ruled out or why it was being passed on.

The moment that matters in a tiered SOC is the HAND-OFF. This models it as a
first-class, append-only event: who passed it, to whom, from which tier to which,
and - the part that actually saves the next analyst's time - why.

Per-tier SLA is part of the same idea. A triage queue that has to be cleared
within an hour and a threat-research question that reasonably takes days cannot
share one deadline, and forcing them to share one is how SLA numbers stop meaning
anything.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

TRIAGE, INVESTIGATION, RESEARCH = 1, 2, 3
TIERS = (TRIAGE, INVESTIGATION, RESEARCH)

TIER_NAMES = {
    TRIAGE: "L1 · Triage",
    INVESTIGATION: "L2 · Investigation",
    RESEARCH: "L3 · Threat research",
}

# Hours to resolve, per tier. Deliberately different: an L1 queue is cleared in
# an hour or it is not a triage queue, while an attribution question that takes
# three days is normal work rather than a breach of anything.
TIER_SLA_HOURS = {TRIAGE: 4, INVESTIGATION: 24, RESEARCH: 72}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _now_precise() -> str:
    """MICROSECOND precision, unlike the second-resolution timestamps used for
    display elsewhere.

    The chain of custody is ordered by this column, and two hand-offs in the same
    second - an L1 passing to L2 who immediately passes to L3 is a completely
    ordinary sequence - are indistinguishable at second resolution, so the case's
    history comes back in arbitrary order. ISO strings sort lexicographically, so
    the extra digits give a total order for free.
    """
    return datetime.now(timezone.utc).isoformat()


def sla_for(tier: int) -> int:
    return TIER_SLA_HOURS.get(int(tier or TRIAGE), TIER_SLA_HOURS[INVESTIGATION])


def tier_name(tier: int) -> str:
    return TIER_NAMES.get(int(tier or TRIAGE), f"Tier {tier}")


def escalate(conn, *, case_id: str, to_tier: int, actor: str,
             to_owner: str | None = None, note: str | None = None) -> dict:
    """Move a case between tiers, recording the hand-off. Returns the event.

    Raises ValueError for an unknown tier or a missing case. DE-escalation is
    allowed on purpose: L2 establishing that something is routine and handing it
    back to L1 is a normal, useful outcome, and a workflow that only ratchets
    upward quietly pushes everything to the most expensive tier.
    """
    tier = int(to_tier)
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}")
    row = conn.execute("SELECT id, tier, owner, status FROM cases WHERE id=?",
                       (case_id,)).fetchone()
    if not row:
        raise ValueError("case not found")
    from_tier = row["tier"] or TRIAGE
    if from_tier == tier and (to_owner or row["owner"]) == row["owner"]:
        # Not an error, but not an event either: recording "escalated from L2 to
        # L2, same owner" would pad the chain of custody with noise.
        raise ValueError(f"case is already at {tier_name(tier)} with this owner")

    event = (str(uuid.uuid4()), case_id, from_tier, tier, row["owner"],
             to_owner or None, (note or "").strip()[:1000] or None, actor,
             _now_precise())
    conn.execute(
        "INSERT INTO case_escalations (id,case_id,from_tier,to_tier,from_owner,"
        "to_owner,note,actor,ts) VALUES (?,?,?,?,?,?,?,?,?)", event)
    # The SLA moves with the tier, and the clock restarts: the receiving tier is
    # not accountable for time spent before the case reached them.
    conn.execute(
        "UPDATE cases SET tier=?, owner=?, sla_hours=?, updated=? WHERE id=?",
        (tier, to_owner if to_owner is not None else row["owner"],
         sla_for(tier), _now(), case_id))
    return {"id": event[0], "caseId": case_id, "fromTier": from_tier,
            "toTier": tier, "fromTierName": tier_name(from_tier),
            "toTierName": tier_name(tier), "fromOwner": event[4],
            "toOwner": event[5], "note": event[6], "actor": actor, "ts": event[8]}


def history(conn, case_id: str, limit: int = 50) -> list[dict]:
    """The case's chain of custody, newest first."""
    return [{"id": r["id"], "fromTier": r["from_tier"], "toTier": r["to_tier"],
             "fromTierName": tier_name(r["from_tier"]) if r["from_tier"] else None,
             "toTierName": tier_name(r["to_tier"]),
             "fromOwner": r["from_owner"], "toOwner": r["to_owner"],
             "note": r["note"], "actor": r["actor"], "ts": r["ts"]}
            for r in conn.execute(
                "SELECT * FROM case_escalations WHERE case_id=? ORDER BY ts DESC LIMIT ?",
                (case_id, limit)).fetchall()]


def queue_counts(conn, org_id: str | None = None) -> list[dict]:
    """Open cases per tier, with how many are unassigned.

    Unassigned is the number that matters for "two analysts working the same
    queue without stepping on each other": it is the pile nobody has claimed.
    """
    clause, params = "", []
    if org_id:
        clause = " AND org_id=?"
        params = [org_id]
    rows = conn.execute(
        f"SELECT COALESCE(tier,1) AS tier, COUNT(*) AS n, "
        f"SUM(CASE WHEN owner IS NULL OR owner='' THEN 1 ELSE 0 END) AS unassigned "
        f"FROM cases WHERE status != 'closed'{clause} GROUP BY COALESCE(tier,1)",
        params).fetchall()
    by_tier = {r["tier"]: (r["n"], r["unassigned"] or 0) for r in rows}
    return [{"tier": t, "name": tier_name(t), "slaHours": sla_for(t),
             "open": by_tier.get(t, (0, 0))[0],
             "unassigned": by_tier.get(t, (0, 0))[1]}
            for t in TIERS]
