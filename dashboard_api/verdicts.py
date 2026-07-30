"""Analyst conclusions, fed back into the intel store so the platform learns.

Until now nothing an analyst concluded ever reached the intel store. An L1 could
spend twenty minutes establishing that an indicator is a false positive in this
environment, write it in a case note, and the store would go on scoring it
exactly as before - and score it the same way again next week, for the next
analyst, who would spend the same twenty minutes.

This closes that loop. A verdict is EVIDENCE, not an override:

  * it carries a reason, an author and a timestamp, and accumulates as history,
    because "two analysts disagreed" is a real state worth representing;
  * it is scoped to a tenant, because one customer concluding "false positive in
    our environment" must never silently suppress another customer's intel;
  * it moves the intel score rather than switching matching off. That is the
    difference from `known-good`, which is a hard global whitelist.

It is weighted ABOVE any third-party claim, on the same principle as local
sightings: our own analysts looking at our own environment is better evidence
than a feed's assertion about the internet in general.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

# What an analyst can conclude. Deliberately small: a vocabulary an analyst has
# to think about is a vocabulary they will use inconsistently.
CONFIRMED = "confirmed"            # really is malicious, acted on
FALSE_POSITIVE = "false-positive"  # not malicious at all - the feed is wrong
BENIGN_HERE = "benign-here"        # real elsewhere, but expected in THIS network
VERDICTS = (CONFIRMED, FALSE_POSITIVE, BENIGN_HERE)

# Score movement per verdict. Larger in magnitude than any single feed's
# contribution, because a human who looked at this deployment's own evidence
# outranks a list. `benign-here` is deliberately milder than `false-positive`:
# the indicator may be perfectly real, it is just expected traffic here, and
# suppressing it as hard as a wrong feed entry would lose that distinction.
WEIGHT = {CONFIRMED: 20, FALSE_POSITIVE: -35, BENIGN_HERE: -22}

# Cap on how far accumulated verdicts can move a score. Ten analysts agreeing is
# not ten times the evidence of one, and without a cap a busy queue could drive
# every score to the floor or the ceiling.
MAX_SHIFT = 40


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def record(conn, *, value: str, verdict: str, analyst: str,
           reason: str | None = None, org_id: str = "org-default") -> dict:
    """Append one analyst conclusion. Raises ValueError on an unknown verdict.

    Appends rather than replaces: the history is the point. An indicator that was
    called a false positive in March and confirmed in July has a story, and
    overwriting the first conclusion would hide it.
    """
    v = (verdict or "").strip().lower()
    if v not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    val = (value or "").strip()
    if not val:
        raise ValueError("value is required")
    row = (str(uuid.uuid4()), val, org_id or "org-default", v,
           (reason or "").strip()[:500] or None, analyst, _now())
    conn.execute(
        "INSERT INTO ioc_verdicts (id,ioc_value,org_id,verdict,reason,analyst,ts) "
        "VALUES (?,?,?,?,?,?,?)", row)
    return {"id": row[0], "value": val, "orgId": row[2], "verdict": v,
            "reason": row[4], "analyst": analyst, "ts": row[6]}


def history(conn, value: str, org_id: str = "org-default", limit: int = 50) -> list[dict]:
    """Every conclusion recorded for this value in this tenant, newest first."""
    val = (value or "").strip()
    if not val:
        return []
    return [{"id": r["id"], "verdict": r["verdict"], "reason": r["reason"],
             "analyst": r["analyst"], "ts": r["ts"]}
            for r in conn.execute(
                "SELECT id, verdict, reason, analyst, ts FROM ioc_verdicts "
                "WHERE ioc_value=? AND org_id=? ORDER BY ts DESC LIMIT ?",
                (val, org_id or "org-default", limit)).fetchall()]


def shift_for(counts: dict[str, int]) -> int:
    """Net score movement from a tally of verdicts, clamped to +/- MAX_SHIFT."""
    total = sum(WEIGHT.get(v, 0) * n for v, n in (counts or {}).items())
    return max(-MAX_SHIFT, min(MAX_SHIFT, total))


def summary(conn, value: str, org_id: str = "org-default") -> dict:
    """The net signal for one value: the tally, the resulting shift, and the
    latest conclusion (which is what a UI should lead with)."""
    counts: dict[str, int] = {}
    latest = None
    for r in conn.execute(
            "SELECT verdict, analyst, reason, ts FROM ioc_verdicts "
            "WHERE ioc_value=? AND org_id=? ORDER BY ts DESC",
            ((value or "").strip(), org_id or "org-default")).fetchall():
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        if latest is None:
            latest = {"verdict": r["verdict"], "analyst": r["analyst"],
                      "reason": r["reason"], "ts": r["ts"]}
    return {"counts": counts, "shift": shift_for(counts), "latest": latest,
            "total": sum(counts.values())}


def all_shifts(conn, org_id: str = "org-default") -> dict[str, int]:
    """{value -> net shift} for the whole tenant, in ONE query.

    The decay pass rescores every indicator in the store; a per-row verdict query
    there would be 315k round trips. This is the same "read it once" shape the
    corroboration and reliability lookups use.
    """
    counts: dict[str, dict[str, int]] = {}
    for r in conn.execute(
            "SELECT ioc_value, verdict, COUNT(*) AS n FROM ioc_verdicts "
            "WHERE org_id=? GROUP BY ioc_value, verdict",
            (org_id or "org-default",)).fetchall():
        counts.setdefault(r["ioc_value"], {})[r["verdict"]] = r["n"]
    return {val: shift_for(c) for val, c in counts.items()}
