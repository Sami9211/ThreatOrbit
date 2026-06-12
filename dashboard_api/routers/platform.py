"""Cross-cutting platform features: notifications centre, global search,
scheduled reports, saved views, and audit/compliance export + retention.

These are the foundations every section leans on — one search box, one
notification bell, deliverable reports, persisted filters, and exportable
audit evidence with retention enforcement.
"""
import csv
import io
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from dashboard_api.auth import current_user, require_role
from dashboard_api.db import audit, dumps, get_conn, row_to_dict, rows_to_dicts

router = APIRouter(tags=["platform"], dependencies=[Depends(current_user)])


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ── Notifications centre ─────────────────────────────────────────────────────────

def notify(conn, *, type: str, title: str, severity: str = "info",
           detail: str | None = None, link: str | None = None):
    """Insert a notification (caller commits). Used by the engine + detections.
    Also pushes it to any live SSE subscribers so the bell updates in realtime."""
    conn.execute(
        "INSERT INTO notifications (id,ts,type,severity,title,detail,link,read) VALUES (?,?,?,?,?,?,?,0)",
        (str(uuid.uuid4()), _now(), type, severity, title, detail, link),
    )
    try:
        from dashboard_api.events_stream import publish
        publish("notification", {"type": type, "severity": severity, "title": title, "link": link})
    except Exception:  # streaming must never break a write path
        pass


@router.get("/notifications")
def list_notifications(limit: int = Query(30, le=100), unread_only: bool = False,
                       user: dict = Depends(current_user)):
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
    if unread_only:
        clauses.append("read=0")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM notifications {where} ORDER BY ts DESC LIMIT ?", params + [limit]
        ).fetchall()
        unread = conn.execute("SELECT COUNT(*) AS n FROM notifications WHERE read=0").fetchone()["n"]
    return {"items": rows_to_dicts(rows), "unread": unread}


class MarkRead(BaseModel):
    id: str | None = None  # mark one; omit to mark all


@router.post("/notifications/read")
def mark_read(body: MarkRead, _: dict = Depends(current_user)):
    with get_conn() as conn:
        if body.id:
            conn.execute("UPDATE notifications SET read=1 WHERE id=?", (body.id,))
        else:
            conn.execute("UPDATE notifications SET read=1 WHERE read=0")
        conn.commit()
    return {"ok": True}


# ── Global search ────────────────────────────────────────────────────────────────

@router.get("/search")
def global_search(q: str = Query(..., min_length=1), limit: int = Query(8, le=25)):
    """One box across alerts, IOCs, assets, cases, actors, and dark-web findings."""
    like = f"%{q}%"
    out: list[dict] = []
    with get_conn() as conn:
        def add(rows, kind, label_key, sub_key, link_fn, sev_key=None):
            for r in rows:
                d = dict(r)
                out.append({"kind": kind, "label": d.get(label_key), "sub": d.get(sub_key),
                            "severity": d.get(sev_key) if sev_key else None, "link": link_fn(d)})
        add(conn.execute("SELECT id,title,src_ip,severity FROM alerts WHERE title LIKE ? OR src_ip LIKE ? LIMIT ?",
                         (like, like, limit)).fetchall(), "alert", "title", "src_ip",
            lambda d: f"/dashboard/siem?q={d['src_ip'] or d['title']}", "severity")
        add(conn.execute("SELECT id,value,type,severity FROM iocs WHERE value LIKE ? LIMIT ?", (like, limit)).fetchall(),
            "ioc", "value", "type", lambda d: f"/dashboard/scanner?q={d['value']}", "severity")
        add(conn.execute("SELECT id,name,value,criticality FROM assets WHERE name LIKE ? OR value LIKE ? LIMIT ?",
                         (like, like, limit)).fetchall(), "asset", "name", "value",
            lambda d: "/dashboard/assets", "criticality")
        add(conn.execute("SELECT id,title,severity FROM cases WHERE title LIKE ? LIMIT ?", (like, limit)).fetchall(),
            "case", "title", "id", lambda d: "/dashboard/soar", "severity")
        add(conn.execute("SELECT id,name,origin FROM threat_actors WHERE name LIKE ? OR aliases LIKE ? LIMIT ?",
                         (like, like, limit)).fetchall(), "actor", "name", "origin",
            lambda d: "/dashboard/cti/actors")
        add(conn.execute("SELECT id,title,entity,severity FROM dark_web_findings WHERE title LIKE ? OR entity LIKE ? LIMIT ?",
                         (like, like, limit)).fetchall(), "darkweb", "title", "entity",
            lambda d: "/dashboard/darkweb", "severity")
    return {"query": q, "results": out}


# ── Scheduled reports ────────────────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    kind: str
    period: str = "weekly"
    cadence: str = "weekly"
    webhook_url: str | None = None
    email: str | None = None


@router.get("/report-schedules")
def list_schedules(user: dict = Depends(require_role("admin", "manager"))):
    where, params = "", []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        where, params = "WHERE org_id=?", [tenancy.org_of(user)]
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM report_schedules {where} ORDER BY created_at DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.post("/report-schedules", status_code=201)
def create_schedule(body: ScheduleCreate, user: dict = Depends(require_role("admin", "manager"))):
    from dashboard_api.reports import REPORT_KINDS
    if body.kind not in REPORT_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {REPORT_KINDS}")
    if body.cadence not in ("daily", "weekly"):
        raise HTTPException(status_code=400, detail="cadence must be daily or weekly")
    sid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO report_schedules (id,kind,period,cadence,webhook_url,email,enabled,created_at,created_by) "
            "VALUES (?,?,?,?,?,?,1,?,?)",
            (sid, body.kind, body.period, body.cadence, body.webhook_url, body.email, _now(), user["email"]),
        )
        audit(conn, user["email"], "report.schedule", sid, f"kind={body.kind} cadence={body.cadence}")
        conn.commit()
        row = conn.execute("SELECT * FROM report_schedules WHERE id=?", (sid,)).fetchone()
    return row_to_dict(row)


@router.post("/report-schedules/{schedule_id}/run")
def run_schedule(schedule_id: str, user: dict = Depends(require_role("admin", "manager"))):
    from dashboard_api.reports import build_report
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM report_schedules WHERE id=?", (schedule_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    s = dict(row)
    report = build_report(s["kind"], s["period"])
    delivered = _deliver_report(s.get("webhook_url"), report)
    emailed = _email_report(s.get("email"), report)
    with get_conn() as conn:
        conn.execute("UPDATE report_schedules SET last_run=? WHERE id=?", (_now(), schedule_id))
        notify(conn, type="report", title=f"{report['meta']['title']} generated",
               detail=f"{report['meta']['period']} · {len(report['findings'])} findings",
               link="/dashboard")
        audit(conn, user["email"], "report.run_schedule", schedule_id,
              f"delivered={delivered} emailed={emailed.get('sent')}")
        conn.commit()
    return {"generated": True, "delivered": delivered, "email": emailed,
            "title": report["meta"]["title"]}


def _email_report(email: str | None, report: dict) -> dict:
    if not email:
        return {"sent": False, "reason": "no email target"}
    from dashboard_api.mailer import send_email
    m = report["meta"]
    html = (f"<h2>{m['title']}</h2><p>{m['period']} · generated {m['generatedAt']}</p>"
            f"<p>{report['summary'].get('narrative', '')}</p>"
            f"<h3>Findings ({len(report['findings'])})</h3><ul>"
            + "".join(f"<li>{f.get('severity', '')}: {f.get('title', '')}</li>"
                      for f in report["findings"][:25]) + "</ul>")
    return send_email(email, f"[ThreatOrbit] {m['title']} — {m['period']}", html)


@router.delete("/report-schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: str, user: dict = Depends(require_role("admin", "manager"))):
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM report_schedules WHERE id=?", (schedule_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Schedule not found")
        conn.commit()
    return None


def _deliver_report(webhook_url: str | None, report: dict) -> bool:
    if not webhook_url:
        return False
    try:
        import httpx
        r = httpx.post(webhook_url, json={"event": "report.scheduled",
                                          "title": report["meta"]["title"],
                                          "period": report["meta"]["period"],
                                          "summary": report["summary"]}, timeout=8.0)
        return r.status_code < 400
    except Exception:
        return False


def run_due_report_schedules():
    """Called by the background scheduler: deliver schedules whose cadence elapsed."""
    from dashboard_api.reports import build_report
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM report_schedules WHERE enabled=1").fetchall()
    for row in rows:
        s = dict(row)
        due = True
        if s.get("last_run"):
            try:
                last = datetime.fromisoformat(s["last_run"])
                gap = timedelta(days=1 if s["cadence"] == "daily" else 7)
                due = now - last >= gap
            except ValueError:
                due = True
        if not due:
            continue
        report = build_report(s["kind"], s["period"])
        _deliver_report(s.get("webhook_url"), report)
        with get_conn() as conn:
            conn.execute("UPDATE report_schedules SET last_run=? WHERE id=?", (_now(), s["id"]))
            notify(conn, type="report", title=f"Scheduled {report['meta']['title']} delivered",
                   detail=report["meta"]["period"], link="/dashboard")
            conn.commit()


# ── Saved views ──────────────────────────────────────────────────────────────────

class ViewCreate(BaseModel):
    section: str
    name: str
    filters: dict = {}


@router.get("/saved-views")
def list_views(section: str | None = None, user: dict = Depends(current_user)):
    clause, params = "WHERE owner=?", [user["email"]]
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clause += " AND org_id=?"; params.append(tenancy.org_of(user))
    if section:
        clause += " AND section=?"; params.append(section)
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM saved_views {clause} ORDER BY created_at DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.post("/saved-views", status_code=201)
def create_view(body: ViewCreate, user: dict = Depends(current_user)):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="View name is required")
    vid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO saved_views (id,section,name,filters,owner,created_at) VALUES (?,?,?,?,?,?)",
            (vid, body.section, body.name.strip(), dumps(body.filters), user["email"], _now()),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM saved_views WHERE id=?", (vid,)).fetchone()
    return row_to_dict(row)


@router.delete("/saved-views/{view_id}", status_code=204)
def delete_view(view_id: str, user: dict = Depends(current_user)):
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM saved_views WHERE id=? AND owner=?", (view_id, user["email"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="View not found")
        conn.commit()
    return None


# ── Audit & compliance ───────────────────────────────────────────────────────────

@router.get("/config/audit-export")
def audit_export(limit: int = Query(5000, le=50000), _: dict = Depends(require_role("admin", "manager"))):
    """Download the audit trail as CSV — tamper-evident evidence for compliance."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, ts, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "ts", "actor", "action", "target", "detail"])
    for r in rows:
        w.writerow([r["id"], r["ts"], r["actor"], r["action"], r["target"], r["detail"]])
    buf.seek(0)
    fname = f"threatorbit-audit-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={fname}"})


@router.post("/config/retention/enforce")
def enforce_retention(user: dict = Depends(require_role("admin", "manager"))):
    """Purge data older than the configured retention window (data_retention_days)."""
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='data_retention_days'").fetchone()
        days = int(row["value"]) if row and str(row["value"]).isdigit() else 90
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).replace(microsecond=0).isoformat()
        purged = {}
        for table, col in (("alerts", "ts"), ("events", "ts"), ("dark_web_findings", "ts"),
                           ("scans", "ts"), ("notifications", "ts")):
            cur = conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
            purged[table] = cur.rowcount
        audit(conn, user["email"], "retention.enforce", None, f"days={days} purged={sum(purged.values())}")
        conn.commit()
    return {"retentionDays": days, "cutoff": cutoff, "purged": purged}
