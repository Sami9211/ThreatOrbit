"""Leader election for singleton background work (HA story).

The engine tick and connector/report scheduler must run on exactly one node, or
two app replicas double-generate telemetry and double-run scheduled connectors
and report deliveries. This is a small DB-backed lease: a node holds a named
lease for a TTL and renews it each tick; followers see a live lease held by
someone else and stay idle. If the leader dies, the lease expires and a follower
takes over within one TTL.

The claim is a single conditional UPDATE — atomic per row on both SQLite (global
write serialisation) and Postgres (row lock under READ COMMITTED): two nodes
racing a free/expired lease serialise on the row, the first wins, the second's
WHERE no longer matches and it gets rowcount 0. Times are integer epoch seconds
(exact on both backends; REAL/float would lose precision on PG float4).
"""
import os
import socket
import time

from dashboard_api.db import get_conn

# Lease names. The two scheduled singletons share one lease: the leader node
# runs both loops, followers run neither.
BACKGROUND = "background"

LEASE_TTL = int(os.environ.get("DASHBOARD_LEASE_TTL", "60"))   # seconds; > tick interval
# Stable per-process identity. Two replicas on the same host still differ by pid.
_HOLDER = f"{socket.gethostname()}:{os.getpid()}"
# A single-replica deployment (the default) is always its own leader; the env
# flag lets an operator force-disable election if they pin background work to one
# node by other means.
_ELECTION_ON = os.environ.get("DASHBOARD_LEADER_ELECTION", "1") != "0"


def holder_id() -> str:
    return _HOLDER


def _ensure_row(conn, name: str) -> None:
    row = conn.execute("SELECT 1 FROM leader_lease WHERE name=?", (name,)).fetchone()
    if row:
        return
    try:
        conn.execute("INSERT INTO leader_lease (name, holder, expires_at) VALUES (?,?,?)",
                     (name, "", 0))
        conn.commit()
    except Exception:
        # Another replica inserted the row concurrently; the unique PK rejected
        # ours. That's fine — the row now exists for the UPDATE below.
        pass


def acquire(name: str = BACKGROUND, ttl: int = LEASE_TTL, holder: str | None = None) -> bool:
    """Take or renew the lease. True if we now hold it. Election-disabled
    deployments always win (single active node by construction)."""
    if not _ELECTION_ON:
        return True
    holder = holder or _HOLDER
    now = int(time.time())
    with get_conn() as conn:
        _ensure_row(conn, name)
        # Claim only if it's ours already (renew) or the current lease has expired.
        cur = conn.execute(
            "UPDATE leader_lease SET holder=?, expires_at=? "
            "WHERE name=? AND (holder=? OR expires_at < ?)",
            (holder, now + ttl, name, holder, now))
        conn.commit()
        return cur.rowcount == 1


def is_leader(name: str = BACKGROUND, holder: str | None = None) -> bool:
    """True if we currently hold a live lease (read-only; doesn't renew)."""
    if not _ELECTION_ON:
        return True
    holder = holder or _HOLDER
    now = int(time.time())
    with get_conn() as conn:
        row = conn.execute("SELECT holder, expires_at FROM leader_lease WHERE name=?",
                           (name,)).fetchone()
    return bool(row) and row["holder"] == holder and int(row["expires_at"]) >= now


def release(name: str = BACKGROUND, holder: str | None = None) -> None:
    """Voluntarily give up the lease (graceful shutdown), so a follower can take
    over immediately instead of waiting out the TTL."""
    holder = holder or _HOLDER
    with get_conn() as conn:
        conn.execute("UPDATE leader_lease SET holder='', expires_at=0 WHERE name=? AND holder=?",
                     (name, holder))
        conn.commit()


def status(name: str = BACKGROUND) -> dict:
    """Lease snapshot for the /config/leader endpoint and metrics."""
    now = int(time.time())
    with get_conn() as conn:
        row = conn.execute("SELECT holder, expires_at FROM leader_lease WHERE name=?",
                           (name,)).fetchone()
    held = bool(row) and bool(row["holder"]) and int(row["expires_at"]) >= now
    return {
        "name": name,
        "electionEnabled": _ELECTION_ON,
        "holder": (row["holder"] if held else None),
        "isSelf": held and row["holder"] == _HOLDER,
        "self": _HOLDER,
        "held": held,
        "expiresInSeconds": max(0, int(row["expires_at"]) - now) if held else 0,
        "ttlSeconds": LEASE_TTL,
    }
