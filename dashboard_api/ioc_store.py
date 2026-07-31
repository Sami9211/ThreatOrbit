"""The one place an indicator is written to the store.

Eight call sites spelled out `INSERT INTO iocs (...)` by hand: the manual API,
TAXII, the services bridge, playbooks, the connector import, the demo engine and
the seeder. Each listed its own columns, so every column added since has been
populated by some of them and not others - and the ones that go missing are
exactly the DERIVED columns, because they are the ones a caller has to remember
to compute rather than being handed.

The damage, measured rather than assumed:

  * `reg_domain` was written by NOTHING except the boot-time backfill. Sibling
    clustering - the pivot that puts `login.x.test` next to `mail.x.test`, which
    is how you see a phishing kit rather than three unrelated domains - is an
    indexed equality on that column. So it silently found nothing for every
    domain imported since the last restart. Three domains of one kit, imported
    normally, returned no pivot groups at all; the same three returned `sibling`
    the moment the backfill ran.
  * `intel_score` was written by the connector import alone. An indicator added
    by an analyst, by TAXII or by a playbook therefore sorted at the bottom of
    the score-ranked list - the DEFAULT list - until the next maintenance pass,
    which is up to LIFECYCLE_TICK_SECONDS away.
  * `ip_hex` was written by two of the eight, so an IP arriving any other way was
    invisible to the ASN range lookup and the `network` pivot.

None of that is a mistake anyone made twice; it is what a hand-copied INSERT
does over time. So the column list, the derivations and the insert live here,
and adding a column means changing one function.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from dashboard_api.db import dumps, host_of, ip_hex_of, reg_domain_of

# Canonical column order. Everything below builds tuples in exactly this order,
# and `insert_iocs` is the only thing that names them in SQL.
COLUMNS = (
    "id", "type", "value", "threat_type", "confidence", "severity",
    "source", "actor", "first_seen", "last_seen", "tags", "status",
    "sightings", "report_id", "org_id",
    # Derived from `value` + `type` - never passed in, so they cannot be forgotten.
    "host", "ip_hex", "reg_domain",
    "intel_score",
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def initial_score(*, type: str, confidence: int, last_seen: str,
                  report_id=None, actor: str = "") -> int:
    """The score a brand-new indicator deserves before anyone corroborates it.

    Scored at insert so it ranks immediately instead of sitting at zero until the
    next maintenance pass. Corroboration is not yet known for this import, so the
    score starts from the source's own claim and is raised by the decay pass once
    other sources agree."""
    from dashboard_api.intel_scoring import score_indicator
    return score_indicator(
        {"type": type, "confidence": confidence, "last_seen": last_seen,
         "report_id": report_id, "actor": actor},
        source_count=1)["score"]


def ioc_row(*, type: str, value: str, threat_type: str = "malicious-activity",
            confidence: int = 50, severity: str = "medium", source: str = "",
            actor: str = "", first_seen: str | None = None,
            last_seen: str | None = None, tags=None, status: str = "active",
            sightings: int = 1, report_id=None, org_id: str = "org-default",
            id: str | None = None, intel_score: int | None = None) -> tuple:
    """Build one row in `COLUMNS` order, deriving everything derivable.

    `host`, `ip_hex` and `reg_domain` are computed here and are NOT parameters:
    a caller that could pass them is a caller that could forget them, which is
    the whole history of this table."""
    now = _now()
    fs = first_seen or now
    ls = last_seen or now
    score = intel_score if intel_score is not None else initial_score(
        type=type, confidence=confidence, last_seen=ls,
        report_id=report_id, actor=actor)
    return (
        id or str(uuid.uuid4()), type, value, threat_type, confidence, severity,
        source, actor, fs, ls,
        tags if isinstance(tags, str) else dumps(list(tags or [])),
        status, sightings, report_id, org_id,
        host_of(value, type), ip_hex_of(value, type), reg_domain_of(value, type),
        score,
    )


# The statement itself, for the handful of callers that already hold an open
# cursor and their own execute/executemany call. Always paired with `ioc_row`,
# never spelled out again.
INSERT_IOC = (f"INSERT INTO iocs ({','.join(COLUMNS)}) "
              f"VALUES ({','.join('?' * len(COLUMNS))})")


def insert_iocs(conn, rows: list[tuple]) -> int:
    """Insert rows built by `ioc_row`. Returns how many were written."""
    if not rows:
        return 0
    conn.executemany(INSERT_IOC, rows)
    return len(rows)


def insert_ioc(conn, **kw) -> tuple:
    """Build and insert one indicator. Returns the row, so a caller that needs
    the generated id does not have to re-query for it."""
    row = ioc_row(**kw)
    insert_iocs(conn, [row])
    return row


def row_id(row: tuple) -> str:
    return row[COLUMNS.index("id")]
