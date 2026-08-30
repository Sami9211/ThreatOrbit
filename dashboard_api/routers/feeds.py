"""Threat feed routes - a view over `connectors`, which is where feeds live.

There used to be a `feeds` table beside `connectors`, holding the same idea
twice. It was the loser of the two: **a row in it never imported anything.** The
scheduler reads `connectors`; nothing has ever read `feeds` to fetch an
indicator. So a "feed" an operator added here appeared in a list, reported a
reliability grade and a sync interval, and did nothing at all.

Live mode seeded no rows into it, which is how the Threat Feeds page came to
read "from 0 sources · No sources configured yet · Total IOCs 0" over a store
holding 315,185 indicators. That was patched by falling back to `connectors`
when the table was empty - and the patch left a sharper bug behind: the list now
returned CONNECTOR ids, while `PATCH /feeds/{id}` still updated the `feeds`
table. Every toggle on that page 404'd and the switch flicked back with no
error. Reproduced against a live deployment before this change: `GET /feeds`
returned connector `b687688b…`, `PATCH /feeds/b687688b…` returned 404.

So the table is gone and these routes are a view. `GET` and `/summary` read
connectors; `PATCH` toggles the connector; `POST` creates one, which is the only
way a new source has ever actually fetched anything.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user, require_perm
from dashboard_api.db import audit, get_conn

router = APIRouter(prefix="/feeds", tags=["feeds"], dependencies=[Depends(current_user)])

_FEED_TYPES = {"commercial", "opensource", "community", "internal"}

# A feed's declared format decides which fetcher can actually read it. This is
# the mapping that turns "add a feed" into a connector that pulls, rather than a
# row that decorates a list.
_FORMAT_KIND = {
    "stix": "stix", "stix 2.1": "stix", "stix 2.0": "stix", "stix2": "stix",
    "taxii": "taxii", "taxii 2.1": "taxii",
    "csv": "csv", "json": "json", "misp json": "json", "native": "json",
}


class FeedToggle(BaseModel):
    enabled: bool


class FeedCreate(BaseModel):
    name: str
    provider: str | None = None
    type: str = "opensource"
    url: str | None = None
    format: str = "STIX 2.1"
    sync_interval: int = 3600
    reliability: str = "B"


def _feed_view(r) -> dict:
    """One connector in the shape this page reads."""
    status = "active" if (r["enabled"] and r["status"] != "error") else (
        "error" if r["status"] == "error" else "paused")
    return {
        "id": r["id"], "name": r["name"], "provider": r["kind"],
        # Every connector this platform ships is an open-source feed, and a
        # bespoke one an operator adds is too as far as this field is concerned.
        "type": "opensource", "url": r["url"], "format": "native",
        "enabled": r["enabled"], "status": status,
        # The connector's own running total: what it HAS imported, not a nominal
        # daily rate.
        "indicators": r["indicator_count"] or 0,
        "last_sync": r["last_run"], "reliability": "B",
    }


def _feeds_from_connectors(conn, *, type_filter=None, status_filter=None) -> list[dict]:
    rows = conn.execute(
        "SELECT id, name, kind, url, enabled, status, last_run, indicator_count "
        "FROM connectors ORDER BY indicator_count DESC").fetchall()
    out = [_feed_view(r) for r in rows]
    if status_filter:
        out = [f for f in out if f["status"] == status_filter]
    if type_filter and type_filter != "opensource":
        out = []
    return out


@router.get("")
def list_feeds(type: str | None = None, status: str | None = None,
               user: dict = Depends(current_user)):
    with get_conn() as conn:
        return _feeds_from_connectors(conn, type_filter=type, status_filter=status)


@router.get("/summary")
def feeds_summary(user: dict = Depends(current_user)):
    # Workspace clause for the rollups - a no-op until multi-tenancy is on.
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0,
                                                  microsecond=0).isoformat()
    with get_conn() as conn:
        feeds = _feeds_from_connectors(conn)
        # Real "IOCs today" - indicators first seen since midnight UTC, not a sum
        # of per-feed nominal daily rates.
        new_today = conn.execute(
            f"SELECT COUNT(*) AS n FROM iocs WHERE first_seen >= ? {sc}", [midnight] + sp
        ).fetchone()["n"]
        # The store's OWN count, not a sum of per-source tallies. Those tallies
        # double-count anything two feeds both list, which after the
        # corroboration work is a large and growing share of the store.
        total_indicators = conn.execute(
            f"SELECT COUNT(*) AS n FROM iocs WHERE 1=1 {sc}", sp).fetchone()["n"]
    return {
        "totalFeeds": len(feeds),
        "active": sum(1 for f in feeds if f["status"] == "active"),
        "errored": sum(1 for f in feeds if f["status"] == "error"),
        "totalIndicators": total_indicators,
        "newToday": new_today,
        "byType": {"commercial": 0, "opensource": len(feeds),
                   "community": 0, "internal": 0},
    }


@router.post("", status_code=201)
def create_feed(body: FeedCreate, user: dict = Depends(require_perm("connectors.manage"))):
    """Add a source. Creates a CONNECTOR, because that is what fetches.

    This used to write a `feeds` row, which no fetcher has ever read - so a feed
    added here reported a reliability grade and a sync interval and imported
    nothing, for ever. The declared format picks the fetcher; the same SSRF
    validation the connectors API applies is applied here, because the URL is
    equally user-supplied whichever door it arrives through.
    """
    import uuid

    from dashboard_api.connectors import validate_feed_url
    from dashboard_api.net_guard import UnsafeUrlError

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Feed name is required")
    if body.type not in _FEED_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {sorted(_FEED_TYPES)}")
    if body.reliability not in ("A", "B", "C"):
        raise HTTPException(status_code=400, detail="reliability must be A, B or C")
    url = (body.url or "").strip()
    if not url:
        raise HTTPException(
            status_code=400,
            detail="A feed needs a URL to fetch from - without one there is "
                   "nothing to import, which is what the old feeds table let "
                   "you create.")
    kind = _FORMAT_KIND.get((body.format or "").strip().lower())
    if not kind:
        raise HTTPException(
            status_code=400,
            detail=f"format must be one of {sorted(set(_FORMAT_KIND))} - it "
                   f"decides which reader can parse the feed.")
    try:
        validate_feed_url(url)
    except UnsafeUrlError as e:
        raise HTTPException(status_code=400, detail=str(e))

    cid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO connectors (id,name,kind,url,api_key,enabled,interval_minutes,"
            "interval_seconds,status,indicator_count,created_at,created_by,org_id) "
            "VALUES (?,?,?,?,'',1,?,?,'idle',0,?,?,?)",
            (cid, name, kind, url, max(1, body.sync_interval // 60),
             max(60, body.sync_interval), now, user["email"], tenancy.org_of(user)))
        audit(conn, user["email"], "feed.create", cid,
              f"name={name} kind={kind} url={url}")
        conn.commit()
        row = conn.execute(
            "SELECT id, name, kind, url, enabled, status, last_run, indicator_count "
            "FROM connectors WHERE id=?", (cid,)).fetchone()
    return _feed_view(row)


@router.patch("/{feed_id}")
def toggle_feed(feed_id: str, body: FeedToggle,
                user: dict = Depends(require_perm("connectors.manage"))):
    """Enable or disable a source.

    The id is a connector id, because that is what the list returns. It used to
    update the `feeds` table, so every toggle on the Sources page 404'd against
    a live deployment and the switch silently flicked back.
    """
    with get_conn() as conn:
        cur = conn.execute("UPDATE connectors SET enabled=? WHERE id=?",
                           (1 if body.enabled else 0, feed_id))
        if not (getattr(cur, "rowcount", 0) or 0):
            raise HTTPException(status_code=404, detail="Feed not found")
        audit(conn, user["email"], "feed.toggle", feed_id, f"enabled={body.enabled}")
        conn.commit()
        row = conn.execute(
            "SELECT id, name, kind, url, enabled, status, last_run, indicator_count "
            "FROM connectors WHERE id=?", (feed_id,)).fetchone()
    return _feed_view(row)
