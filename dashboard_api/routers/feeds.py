"""Threat feed routes: list feeds/sources, toggle, and a summary."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user
from dashboard_api.db import audit, get_conn, row_to_dict, rows_to_dicts

router = APIRouter(prefix="/feeds", tags=["feeds"], dependencies=[Depends(current_user)])


class FeedToggle(BaseModel):
    enabled: bool


@router.get("")
def list_feeds(type: str | None = None, status: str | None = None):
    clauses, params = [], []
    if type:
        clauses.append("type=?"); params.append(type)
    if status:
        clauses.append("status=?"); params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM feeds {where} ORDER BY indicators DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.get("/summary")
def feeds_summary():
    with get_conn() as conn:
        rows = conn.execute("SELECT status, enabled, indicators, type FROM feeds").fetchall()
    return {
        "totalFeeds": len(rows),
        "active": sum(1 for r in rows if r["status"] == "active"),
        "errored": sum(1 for r in rows if r["status"] == "error"),
        "totalIndicators": sum(r["indicators"] for r in rows),
        "byType": {t: sum(1 for r in rows if r["type"] == t)
                   for t in ("commercial", "opensource", "community", "internal")},
    }


@router.patch("/{feed_id}")
def toggle_feed(feed_id: str, body: FeedToggle, user: dict = Depends(current_user)):
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE feeds SET enabled=?, status=? WHERE id=?",
            (1 if body.enabled else 0, "active" if body.enabled else "paused", feed_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Feed not found")
        audit(conn, user["email"], "feed.toggle", feed_id, f"enabled={body.enabled}")
        conn.commit()
        row = conn.execute("SELECT * FROM feeds WHERE id=?", (feed_id,)).fetchone()
    return row_to_dict(row)
