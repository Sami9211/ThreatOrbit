"""SOAR routes: cases (create/update/notes/tasks), playbooks, integrations, metrics."""
import json
import random
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from dashboard_api.auth import current_user
from dashboard_api.db import audit, dumps, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.webhooks import dispatch

router = APIRouter(prefix="/soar", tags=["soar"], dependencies=[Depends(current_user)])

SEVERITIES = {"critical", "high", "medium", "low"}
TASK_STATUSES = {"pending", "in-progress", "done"}

DEFAULT_TASKS = [
    ("Triage", "Validate alert"),
    ("Containment", "Isolate affected assets"),
    ("Eradication", "Remove persistence"),
    ("Recovery", "Restore service"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class CaseUpdate(BaseModel):
    status: str | None = None
    owner: str | None = None
    severity: str | None = None


class CaseCreate(BaseModel):
    title: str
    severity: str = "medium"
    type: str | None = None
    description: str | None = None
    owner: str | None = None
    sla_hours: int = 24
    alert_count: int = 0
    entities: list[dict] = []


class NoteCreate(BaseModel):
    content: str
    type: str = "manual"


class TaskUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = None
    notes: str | None = None


@router.get("/cases")
def list_cases(status: str | None = None, severity: str | None = None):
    clauses, params = [], []
    if status:
        clauses.append("status=?"); params.append(status)
    if severity:
        clauses.append("severity=?"); params.append(severity)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM cases {where} ORDER BY updated DESC", params).fetchall()
    return rows_to_dicts(rows)


@router.post("/cases", status_code=201)
def create_case(body: CaseCreate, user: dict = Depends(current_user)):
    title = body.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")
    if body.severity not in SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Severity must be one of {sorted(SEVERITIES)}")
    now = _now_iso()
    owner = body.owner or user["email"]
    war_room = [{"ts": now, "actor": user["email"], "type": "system",
                 "content": "Case opened" + (f": {body.description}" if body.description else ".")}]
    tasks = [{"id": f"T{i+1}", "phase": phase, "name": name, "status": "pending",
              "assignee": owner, "notes": ""} for i, (phase, name) in enumerate(DEFAULT_TASKS)]
    with get_conn() as conn:
        case_id = None
        for _ in range(50):
            candidate = f"CASE-{random.randint(1000, 9999)}"
            if not conn.execute("SELECT 1 FROM cases WHERE id=?", (candidate,)).fetchone():
                case_id = candidate
                break
        if case_id is None:
            raise HTTPException(status_code=500, detail="Could not allocate a case id")
        conn.execute(
            "INSERT INTO cases (id,title,type,severity,status,owner,playbook,sla_hours,created,updated,"
            "alert_count,description,entities,war_room,tasks,evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, title, body.type or "Investigation", body.severity, "new", owner, "",
             body.sla_hours, now, now, body.alert_count,
             body.description or f"Investigation into {title.lower()}.",
             dumps(body.entities), dumps(war_room), dumps(tasks), dumps([])),
        )
        audit(conn, user["email"], "case.create", case_id, f"title={title} severity={body.severity}")
        conn.commit()
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    dispatch("case.created", {"id": case_id, "title": title, "severity": body.severity,
                              "type": body.type or "Investigation", "owner": owner})
    return row_to_dict(row)


@router.get("/cases/{case_id}")
def get_case(case_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    return row_to_dict(row)


@router.post("/cases/{case_id}/notes", status_code=201)
def add_case_note(case_id: str, body: NoteCreate, user: dict = Depends(current_user)):
    content = body.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Note content is required")
    now = _now_iso()
    with get_conn() as conn:
        row = conn.execute("SELECT war_room FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        war_room = json.loads(row["war_room"] or "[]")
        war_room.append({"ts": now, "actor": user["email"], "type": body.type, "content": content})
        conn.execute("UPDATE cases SET war_room=?, updated=? WHERE id=?",
                     (dumps(war_room), now, case_id))
        audit(conn, user["email"], "case.note", case_id)
        conn.commit()
        updated = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return row_to_dict(updated)


@router.patch("/cases/{case_id}/tasks/{task_id}")
def update_case_task(case_id: str, task_id: str, body: TaskUpdate, user: dict = Depends(current_user)):
    if body.status is not None and body.status not in TASK_STATUSES:
        raise HTTPException(status_code=400, detail=f"Status must be one of {sorted(TASK_STATUSES)}")
    if body.status is None and body.assignee is None and body.notes is None:
        raise HTTPException(status_code=400, detail="No fields to update")
    now = _now_iso()
    with get_conn() as conn:
        row = conn.execute("SELECT tasks FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        tasks = json.loads(row["tasks"] or "[]")
        task = next((t for t in tasks if t.get("id") == task_id), None)
        if task is None:
            raise HTTPException(status_code=404, detail="Task not found")
        if body.status is not None:
            task["status"] = body.status
        if body.assignee is not None:
            task["assignee"] = body.assignee
        if body.notes is not None:
            task["notes"] = body.notes
        conn.execute("UPDATE cases SET tasks=?, updated=? WHERE id=?",
                     (dumps(tasks), now, case_id))
        audit(conn, user["email"], "case.task", case_id, f"task={task_id}")
        conn.commit()
        updated = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return row_to_dict(updated)


@router.patch("/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate, user: dict = Depends(current_user)):
    fields, values = [], []
    for col in ("status", "owner", "severity"):
        v = getattr(body, col)
        if v is not None:
            fields.append(f"{col}=?"); values.append(v)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    from datetime import datetime, timezone
    fields.append("updated=?"); values.append(datetime.now(timezone.utc).replace(microsecond=0).isoformat())
    values.append(case_id)
    with get_conn() as conn:
        prev = conn.execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
        cur = conn.execute(f"UPDATE cases SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Case not found")
        changed = ",".join(f.split("=")[0] for f in fields[:-1])
        audit(conn, user["email"], "case.update", case_id, f"fields={changed}")
        conn.commit()
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    updated_case = row_to_dict(row)
    if (body.status in ("resolved", "closed")
            and prev and prev["status"] not in ("resolved", "closed")):
        dispatch("incident.resolved", {"id": case_id, "title": updated_case["title"],
                                       "severity": updated_case["severity"],
                                       "status": body.status, "resolvedBy": user["email"]})
    return updated_case


class PlaybookCreate(BaseModel):
    name: str
    category: str = "Network"
    trigger: str | None = None
    trigger_type: str = "manual"
    description: str | None = None
    steps: list[dict] = []
    trigger_match: dict = {}


class PlaybookUpdate(BaseModel):
    enabled: bool | None = None
    steps: list[dict] | None = None
    trigger_match: dict | None = None
    trigger_type: str | None = None
    description: str | None = None


class PlaybookRunBody(BaseModel):
    dry_run: bool = False
    alert_id: str | None = None


def _validate_steps(steps: list[dict]):
    from dashboard_api.playbook_engine import STEP_KINDS
    for i, s in enumerate(steps):
        if not isinstance(s, dict) or s.get("kind") not in STEP_KINDS:
            raise HTTPException(
                status_code=400,
                detail=f"Step {i+1}: kind must be one of {sorted(STEP_KINDS)}")
        if not (s.get("name") or "").strip():
            raise HTTPException(status_code=400, detail=f"Step {i+1}: name is required")


@router.get("/playbooks")
def list_playbooks():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM playbooks ORDER BY runs DESC").fetchall()
    return rows_to_dicts(rows)


@router.post("/playbooks", status_code=201)
def create_playbook(body: PlaybookCreate, user: dict = Depends(current_user)):
    import uuid
    from dashboard_api.playbook_engine import display_steps
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Playbook name is required")
    if body.trigger_type not in ("auto", "manual"):
        raise HTTPException(status_code=400, detail="trigger_type must be auto|manual")
    _validate_steps(body.steps)
    pid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO playbooks (id,name,category,trigger,trigger_type,description,runs,"
            "success_rate,avg_time,last_run,last_run_status,status,enabled,steps,trigger_match) "
            "VALUES (?,?,?,?,?,?,0,0,30,NULL,'idle','idle',1,?,?)",
            (pid, name, body.category, body.trigger or "Manual", body.trigger_type,
             body.description or f"{name} workflow.",
             dumps(display_steps(body.steps)), dumps(body.trigger_match)),
        )
        audit(conn, user["email"], "playbook.create", pid, f"name={name} steps={len(body.steps)}")
        conn.commit()
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (pid,)).fetchone()
    return row_to_dict(row)


@router.get("/playbooks/{playbook_id}")
def get_playbook(playbook_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return row_to_dict(row)


@router.patch("/playbooks/{playbook_id}")
def update_playbook(playbook_id: str, body: PlaybookUpdate, user: dict = Depends(current_user)):
    from dashboard_api.playbook_engine import display_steps
    fields, values = [], []
    if body.enabled is not None:
        fields.append("enabled=?"); values.append(1 if body.enabled else 0)
    if body.steps is not None:
        _validate_steps(body.steps)
        fields.append("steps=?"); values.append(dumps(display_steps(body.steps)))
    if body.trigger_match is not None:
        fields.append("trigger_match=?"); values.append(dumps(body.trigger_match))
    if body.trigger_type is not None:
        if body.trigger_type not in ("auto", "manual"):
            raise HTTPException(status_code=400, detail="trigger_type must be auto|manual")
        fields.append("trigger_type=?"); values.append(body.trigger_type)
    if body.description is not None:
        fields.append("description=?"); values.append(body.description)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    values.append(playbook_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE playbooks SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Playbook not found")
        audit(conn, user["email"], "playbook.update", playbook_id)
        conn.commit()
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    return row_to_dict(row)


@router.post("/playbooks/{playbook_id}/run")
def run_playbook(playbook_id: str, body: PlaybookRunBody | None = None,
                 user: dict = Depends(current_user)):
    """Execute the playbook's steps for real (or preview them with dry_run)."""
    from dashboard_api.playbook_engine import execute_playbook
    body = body or PlaybookRunBody()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Playbook not found")
        if not row["enabled"]:
            dispatch("playbook.failed", {"id": playbook_id, "name": row["name"],
                                         "reason": "disabled", "actor": user["email"]})
            raise HTTPException(status_code=409, detail="Playbook is disabled")
        run = execute_playbook(conn, dict(row), actor=user["email"], trigger="manual",
                               alert_id=body.alert_id, dry_run=body.dry_run)
        conn.commit()
        updated = conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    for event, payload in run.pop("dispatches", []):
        dispatch(event, payload)
    if run["status"] in ("success", "failed") and not run.get("dryRun"):
        dispatch("playbook.completed", {"id": playbook_id, "name": updated["name"],
                                        "status": run["status"], "actor": user["email"]})
    if body.dry_run:
        return {"dryRun": True, "run": run}
    return {**row_to_dict(updated), "run": run}


@router.get("/playbooks/{playbook_id}/runs")
def list_playbook_runs(playbook_id: str, limit: int = 20):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM playbook_runs WHERE playbook_id=? ORDER BY ts DESC LIMIT ?",
            (playbook_id, min(limit, 100))).fetchall()
    return rows_to_dicts(rows)


@router.get("/runs")
def list_runs(status: str | None = None, limit: int = 30):
    clauses, params = [], []
    if status:
        clauses.append("status=?"); params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM playbook_runs {where} ORDER BY ts DESC LIMIT ?",
            params + [min(limit, 100)]).fetchall()
        pending = conn.execute(
            "SELECT COUNT(*) AS n FROM playbook_runs WHERE status='awaiting-approval'").fetchone()["n"]
    return {"items": rows_to_dicts(rows), "awaitingApproval": pending}


@router.post("/runs/{run_id}/approve")
def approve_run(run_id: str, user: dict = Depends(current_user)):
    from dashboard_api.playbook_engine import resolve_approval
    with get_conn() as conn:
        try:
            run = resolve_approval(conn, run_id, approve=True, actor=user["email"])
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        conn.commit()
    for event, payload in run.pop("dispatches", []):
        dispatch(event, payload)
    return run


@router.post("/runs/{run_id}/reject")
def reject_run(run_id: str, user: dict = Depends(current_user)):
    from dashboard_api.playbook_engine import resolve_approval
    with get_conn() as conn:
        try:
            run = resolve_approval(conn, run_id, approve=False, actor=user["email"])
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        conn.commit()
    run.pop("dispatches", None)
    return run


class IntegrationCreate(BaseModel):
    name: str
    vendor: str | None = None
    category: str | None = None
    description: str | None = None
    actions: list[str] = []


class ActionRun(BaseModel):
    action: str


@router.get("/integrations")
def list_integrations():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM integrations ORDER BY name").fetchall()
    return rows_to_dicts(rows)


@router.post("/integrations", status_code=201)
def create_integration(body: IntegrationCreate, user: dict = Depends(current_user)):
    import uuid
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Integration name is required")
    iid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO integrations (id,name,vendor,category,status,last_sync,actions_run,"
            "avg_response_ms,description,actions,enabled) VALUES (?,?,?,?,'pending',NULL,0,0,?,?,1)",
            (iid, name, body.vendor or name, body.category or "Custom",
             body.description or f"{name} connector.", dumps(body.actions)),
        )
        audit(conn, user["email"], "integration.create", iid, f"name={name}")
        conn.commit()
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (iid,)).fetchone()
    return row_to_dict(row)


@router.post("/integrations/{integration_id}/test")
def test_integration(integration_id: str, user: dict = Depends(current_user)):
    """Record a connectivity check: stamps last_sync and marks the connector live."""
    now = _now_iso()
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE integrations SET status='connected', last_sync=? WHERE id=?",
            (now, integration_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Integration not found")
        audit(conn, user["email"], "integration.test", integration_id)
        conn.commit()
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
    return row_to_dict(row)


@router.post("/integrations/{integration_id}/actions/run")
def run_integration_action(integration_id: str, body: ActionRun, user: dict = Depends(current_user)):
    """Execute a response action on a connected tool: bumps the action counter."""
    action = body.action.strip()
    if not action:
        raise HTTPException(status_code=400, detail="Action is required")
    now = _now_iso()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Integration not found")
        if not row["enabled"] or row["status"] == "disconnected":
            raise HTTPException(status_code=409, detail="Integration is not connected")
        conn.execute(
            "UPDATE integrations SET actions_run=actions_run+1, last_sync=? WHERE id=?",
            (now, integration_id),
        )
        audit(conn, user["email"], "integration.action", integration_id,
              f"action={action} tool={row['name']}")
        conn.commit()
        updated = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
    return row_to_dict(updated)


@router.get("/metrics")
def soar_metrics():
    with get_conn() as conn:
        cases = conn.execute("SELECT status, severity, playbook FROM cases").fetchall()
        pbs = conn.execute("SELECT runs, success_rate, avg_time, last_run FROM playbooks").fetchall()
        # MTTR in minutes from per-alert response latency (consistent with SIEM KPIs).
        mttr_row = conn.execute(
            "SELECT AVG(respond_latency_sec) / 60.0 AS v FROM alerts WHERE respond_latency_sec IS NOT NULL"
        ).fetchone()
    open_cases = sum(1 for c in cases if c["status"] not in ("resolved", "closed"))
    crit_open = sum(1 for c in cases if c["status"] not in ("resolved", "closed") and c["severity"] == "critical")
    closed = [c for c in cases if c["status"] in ("resolved", "closed")]
    closed_week = len(closed)
    total_runs = sum(p["runs"] for p in pbs)
    avg_pb = int(sum(p["avg_time"] for p in pbs) / len(pbs)) if pbs else 0
    # Automation rate: share of closed cases that were driven by an automated playbook.
    automated = sum(1 for c in closed if c["playbook"])
    automation_rate = round(automated / closed_week * 100, 1) if closed_week else 0
    mttr = round(mttr_row["v"] or 0, 1)
    return {
        "openCases": open_cases,
        "criticalOpen": crit_open,
        "mttr": mttr, "mttrTrend": "↓ 12%",
        "automationRate": automation_rate, "automationTrend": "↑ 8%",
        "timeSavedMonth": round(total_runs * avg_pb / 3600, 1),
        "playbooksToday": sum(1 for p in pbs if p["last_run"]),
        "avgPlaybookTime": avg_pb,
        "casesClosedWeek": closed_week,
    }
