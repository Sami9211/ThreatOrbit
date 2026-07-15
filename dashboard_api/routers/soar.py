"""SOAR routes: cases (create/update/notes/tasks), playbooks, integrations, metrics."""
import json
import random
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from dashboard_api import tenancy
from dashboard_api.auth import current_user, require_perm
from dashboard_api.db import audit, dumps, get_conn, row_to_dict, rows_to_dicts
from dashboard_api.secretstore import encrypt
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


def _sla(case: dict) -> dict:
    """Compute SLA tracking for a case: deadline, % elapsed, and status
    (within | at-risk | breached for open; met | breached for closed)."""
    from datetime import timedelta
    try:
        created = datetime.fromisoformat(str(case["created"]).replace("Z", "+00:00"))
    except (ValueError, TypeError, KeyError):
        return {"slaDeadline": None, "slaStatus": "unknown", "slaElapsedPct": 0}
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    hours = case.get("sla_hours") or 24
    deadline = created + timedelta(hours=hours)
    closed = case.get("status") in ("resolved", "closed")
    ref_raw = case.get("updated") if closed else None
    try:
        ref = datetime.fromisoformat(str(ref_raw).replace("Z", "+00:00")) if ref_raw \
            else datetime.now(timezone.utc)
    except (ValueError, TypeError):
        ref = datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    elapsed_pct = min(999, round((ref - created).total_seconds() / (hours * 3600) * 100))
    if closed:
        status = "met" if ref <= deadline else "breached"
    else:
        status = "breached" if ref > deadline else ("at-risk" if elapsed_pct >= 75 else "within")
    return {"slaDeadline": deadline.replace(microsecond=0).isoformat(),
            "slaStatus": status, "slaElapsedPct": max(0, elapsed_pct)}


def _with_sla(case_dict: dict) -> dict:
    return {**case_dict, **_sla(case_dict)}


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
def list_cases(status: str | None = None, severity: str | None = None,
               user: dict = Depends(current_user)):
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
    if status:
        clauses.append("status=?"); params.append(status)
    if severity:
        clauses.append("severity=?"); params.append(severity)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM cases {where} ORDER BY updated DESC", params).fetchall()
    return [_with_sla(c) for c in rows_to_dicts(rows)]


@router.post("/cases", status_code=201)
def create_case(body: CaseCreate, user: dict = Depends(require_perm("soar.write"))):
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
            "alert_count,description,entities,war_room,tasks,evidence,org_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, title, body.type or "Investigation", body.severity, "new", owner, "",
             body.sla_hours, now, now, body.alert_count,
             body.description or f"Investigation into {title.lower()}.",
             dumps(body.entities), dumps(war_room), dumps(tasks), dumps([]),
             tenancy.org_of(user)),
        )
        audit(conn, user["email"], "case.create", case_id, f"title={title} severity={body.severity}")
        conn.commit()
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    dispatch("case.created", {"id": case_id, "title": title, "severity": body.severity,
                              "type": body.type or "Investigation", "owner": owner},
             org=tenancy.org_of(user))
    return row_to_dict(row)


@router.get("/cases/{case_id}")
def get_case(case_id: str, user: dict = Depends(current_user)):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row or tenancy.cross_org(row, user):
        raise HTTPException(status_code=404, detail="Case not found")
    return _with_sla(row_to_dict(row))


@router.get("/cases/{case_id}/related")
def case_related(case_id: str, user: dict = Depends(current_user)):
    """Linked evidence for a case: alerts/IOCs/playbook-runs matching its
    entities, plus a MITRE-mapped merged timeline (war room + alert activity)."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row or tenancy.cross_org(row, user):
            raise HTTPException(status_code=404, detail="Case not found")
        case = row_to_dict(row)
        values = [e.get("value") for e in (case.get("entities") or [])
                  if isinstance(e, dict) and e.get("value")]
        alerts, iocs, runs = [], [], []
        if values:
            ph = ",".join("?" * len(values))
            alerts = rows_to_dicts(conn.execute(
                f"SELECT id, ts, title, severity, status, src_ip, hostname, username, "
                f"mitre_tech_id, mitre_tactic, rule_name, risk_score FROM alerts "
                f"WHERE src_ip IN ({ph}) OR hostname IN ({ph}) OR username IN ({ph}) "
                f"ORDER BY ts DESC LIMIT 50", values * 3).fetchall())
            iocs = rows_to_dicts(conn.execute(
                f"SELECT id, type, value, severity, confidence, threat_type, source "
                f"FROM iocs WHERE value IN ({ph}) LIMIT 20", values).fetchall())
        alert_ids = [a["id"] for a in alerts]
        if alert_ids:
            ph = ",".join("?" * len(alert_ids))
            runs = rows_to_dicts(conn.execute(
                f"SELECT id, playbook_name, ts, status, trigger, actor, alert_id "
                f"FROM playbook_runs WHERE alert_id IN ({ph}) ORDER BY ts DESC LIMIT 20",
                alert_ids).fetchall())
    # MITRE-mapped merged timeline: war-room entries + linked alert activity
    timeline = [{"ts": w.get("ts"), "type": w.get("type", "note"), "actor": w.get("actor"),
                 "title": w.get("content"), "severity": None, "technique": None}
                for w in (case.get("war_room") or [])]
    timeline += [{"ts": a["ts"], "type": "alert", "actor": a.get("rule_name"),
                  "title": a["title"], "severity": a["severity"],
                  "technique": a.get("mitre_tech_id")} for a in alerts]
    timeline += [{"ts": r["ts"], "type": "playbook", "actor": r.get("actor"),
                  "title": f"Playbook run: {r.get('playbook_name')} ({r.get('status')})",
                  "severity": None, "technique": None} for r in runs]
    timeline.sort(key=lambda x: x.get("ts") or "")
    techniques: dict[str, int] = {}
    for a in alerts:
        t = a.get("mitre_tech_id")
        if t:
            techniques[t] = techniques.get(t, 0) + 1
    return {"caseId": case_id, "alerts": alerts, "iocs": iocs, "runs": runs,
            "timeline": timeline[-80:],
            "techniques": [{"technique": k, "count": v}
                           for k, v in sorted(techniques.items(), key=lambda x: -x[1])]}


@router.post("/cases/{case_id}/notes", status_code=201)
def add_case_note(case_id: str, body: NoteCreate, user: dict = Depends(require_perm("soar.write"))):
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
def update_case_task(case_id: str, task_id: str, body: TaskUpdate, user: dict = Depends(require_perm("soar.write"))):
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
def update_case(case_id: str, body: CaseUpdate, user: dict = Depends(require_perm("soar.write"))):
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
    # Org-scope the UPDATE itself so a cross-workspace id 404s without a write.
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        prev = conn.execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
        cur = conn.execute(f"UPDATE cases SET {','.join(fields)} WHERE id=? {sc}",
                           values + sp)
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
                                       "status": body.status, "resolvedBy": user["email"]},
                 org=tenancy.org_of(user))
    return updated_case


class EvidenceAdd(BaseModel):
    type: str = "note"          # note|file|ioc|screenshot|log
    name: str
    content: str | None = None


class CaseLink(BaseModel):
    case_id: str
    relation: str = "related"   # related|duplicate


class CaseMerge(BaseModel):
    source_id: str


class CaseSplit(BaseModel):
    title: str
    entities: list[dict] = []


def _load(row, col):
    return json.loads(row[col] or "[]") if isinstance(row[col], str) else (row[col] or [])


@router.post("/cases/{case_id}/evidence", status_code=201)
def add_evidence(case_id: str, body: EvidenceAdd, user: dict = Depends(require_perm("soar.write"))):
    """Attach an evidence item with tamper-evident chain-of-custody: who added
    what, when, and a SHA-256 of the content for integrity."""
    import hashlib
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Evidence name is required")
    now = _now_iso()
    content = body.content or ""
    sha = hashlib.sha256(content.encode()).hexdigest()
    item = {"id": str(__import__("uuid").uuid4()), "type": body.type, "name": name,
            "content": content[:2000], "sha256": sha, "addedBy": user["email"], "ts": now,
            "custody": [{"actor": user["email"], "action": "collected", "ts": now}]}
    with get_conn() as conn:
        row = conn.execute("SELECT evidence FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        evidence = _load(row, "evidence")
        evidence.append(item)
        conn.execute("UPDATE cases SET evidence=?, updated=? WHERE id=?",
                     (dumps(evidence), now, case_id))
        audit(conn, user["email"], "case.evidence_add", case_id, f"name={name} sha256={sha[:12]}")
        conn.commit()
        updated = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return row_to_dict(updated)


@router.get("/cases/{case_id}/evidence-bundle")
def export_evidence_bundle(case_id: str, user: dict = Depends(require_perm("soar.write"))):
    """Export the case's full investigation record as a signed, tamper-evident
    bundle: case + evidence (per-item SHA-256 custody) + war room + tasks +
    the case's audit-log slice, HMAC-SHA256-signed over canonical JSON. Any
    later modification fails `/soar/evidence/verify`."""
    from dashboard_api.evidence import build_case_bundle, sign_bundle
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        doc = build_case_bundle(conn, row_to_dict(row), exported_by=user["email"])
        audit(conn, user["email"], "case.evidence_export", case_id)
        conn.commit()
    return sign_bundle(doc)


class BundleVerify(BaseModel):
    bundle: dict
    signature: dict


@router.post("/evidence/verify")
def verify_evidence_bundle(body: BundleVerify, user: dict = Depends(current_user)):
    """Honestly verify a previously exported bundle: recompute the HMAC over
    the canonical content and compare. valid=false means the content or the
    signature changed since export."""
    from dashboard_api.evidence import verify_bundle
    sig = (body.signature or {}).get("value", "")
    return {"valid": bool(sig) and verify_bundle(body.bundle, sig)}


@router.post("/cases/{case_id}/link")
def link_case(case_id: str, body: CaseLink, user: dict = Depends(require_perm("soar.write"))):
    """Relate two cases (related|duplicate) - recorded on both sides."""
    if body.relation not in ("related", "duplicate"):
        raise HTTPException(status_code=400, detail="relation must be related|duplicate")
    if body.case_id == case_id:
        raise HTTPException(status_code=400, detail="A case cannot link to itself")
    now = _now_iso()
    with get_conn() as conn:
        a = conn.execute("SELECT linked_cases FROM cases WHERE id=?", (case_id,)).fetchone()
        b = conn.execute("SELECT linked_cases FROM cases WHERE id=?", (body.case_id,)).fetchone()
        if not a or not b:
            raise HTTPException(status_code=404, detail="Case not found")
        la = _load(a, "linked_cases")
        if not any(x.get("caseId") == body.case_id for x in la):
            la.append({"caseId": body.case_id, "relation": body.relation, "ts": now})
        lb = _load(b, "linked_cases")
        if not any(x.get("caseId") == case_id for x in lb):
            lb.append({"caseId": case_id, "relation": body.relation, "ts": now})
        conn.execute("UPDATE cases SET linked_cases=? WHERE id=?", (dumps(la), case_id))
        conn.execute("UPDATE cases SET linked_cases=? WHERE id=?", (dumps(lb), body.case_id))
        audit(conn, user["email"], "case.link", case_id, f"to={body.case_id} relation={body.relation}")
        conn.commit()
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return row_to_dict(row)


@router.post("/cases/{case_id}/merge")
def merge_case(case_id: str, body: CaseMerge, user: dict = Depends(require_perm("soar.write"))):
    """Merge a source case INTO this one: combine entities + war-room + evidence,
    sum alert counts, close the source (linked as a duplicate)."""
    if body.source_id == case_id:
        raise HTTPException(status_code=400, detail="Cannot merge a case into itself")
    now = _now_iso()
    with get_conn() as conn:
        tgt = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        src = conn.execute("SELECT * FROM cases WHERE id=?", (body.source_id,)).fetchone()
        if not tgt or not src:
            raise HTTPException(status_code=404, detail="Case not found")
        # merge entities (dedupe by value), war-room, evidence; sum alert counts
        ents = _load(tgt, "entities")
        seen = {e.get("value") for e in ents if isinstance(e, dict)}
        for e in _load(src, "entities"):
            if isinstance(e, dict) and e.get("value") not in seen:
                ents.append(e); seen.add(e.get("value"))
        war = _load(tgt, "war_room") + [{"ts": now, "actor": user["email"], "type": "system",
              "content": f"Merged case {body.source_id} ({src['title']}) into this case."}] + _load(src, "war_room")
        evidence = _load(tgt, "evidence") + _load(src, "evidence")
        links = _load(tgt, "linked_cases")
        if not any(x.get("caseId") == body.source_id for x in links):
            links.append({"caseId": body.source_id, "relation": "merged", "ts": now})
        conn.execute(
            "UPDATE cases SET entities=?, war_room=?, evidence=?, linked_cases=?, "
            "alert_count=alert_count+?, updated=? WHERE id=?",
            (dumps(ents), dumps(war), dumps(evidence), dumps(links),
             src["alert_count"] or 0, now, case_id))
        # close the source, pointing at the target
        src_links = _load(src, "linked_cases")
        src_links.append({"caseId": case_id, "relation": "merged-into", "ts": now})
        conn.execute(
            "UPDATE cases SET status='closed', linked_cases=?, updated=? WHERE id=?",
            (dumps(src_links), now, body.source_id))
        audit(conn, user["email"], "case.merge", case_id, f"source={body.source_id}")
        conn.commit()
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return row_to_dict(row)


@router.post("/cases/{case_id}/split", status_code=201)
def split_case(case_id: str, body: CaseSplit, user: dict = Depends(require_perm("soar.write"))):
    """Split selected entities off into a new child case, linked to the parent."""
    import random
    title = body.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="New case title is required")
    now = _now_iso()
    with get_conn() as conn:
        parent = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not parent:
            raise HTTPException(status_code=404, detail="Case not found")
        cid = None
        for _ in range(50):
            cand = f"CASE-{random.randint(1000, 9999)}"
            if not conn.execute("SELECT 1 FROM cases WHERE id=?", (cand,)).fetchone():
                cid = cand; break
        if cid is None:
            raise HTTPException(status_code=500, detail="Could not allocate a case id")
        war = [{"ts": now, "actor": user["email"], "type": "system",
                "content": f"Split from case {case_id} ({parent['title']})."}]
        tasks = [{"id": f"T{i+1}", "phase": p, "name": n, "status": "pending", "assignee": None, "notes": ""}
                 for i, (p, n) in enumerate([("Triage", "Validate split scope"),
                                             ("Containment", "Contain"), ("Recovery", "Restore")])]
        conn.execute(
            "INSERT INTO cases (id,title,type,severity,status,owner,playbook,sla_hours,created,updated,"
            "alert_count,description,entities,war_room,tasks,evidence,linked_cases,org_id) "
            "VALUES (?,?,?,?,'new',?,'',?,?,?,0,?,?,?,?,?,?,?)",
            (cid, title, parent["type"], parent["severity"], user["email"], parent["sla_hours"],
             now, now, f"Split from {case_id}.", dumps(body.entities or []), dumps(war),
             dumps(tasks), dumps([]), dumps([{"caseId": case_id, "relation": "split-from", "ts": now}]),
             tenancy.org_of(user)))
        plinks = _load(parent, "linked_cases")
        plinks.append({"caseId": cid, "relation": "split-into", "ts": now})
        conn.execute("UPDATE cases SET linked_cases=?, updated=? WHERE id=?", (dumps(plinks), now, case_id))
        audit(conn, user["email"], "case.split", case_id, f"child={cid}")
        conn.commit()
        row = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    return row_to_dict(row)


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


@router.get("/step-kinds")
def step_kinds():
    """The executable step kinds the visual builder offers, with display type
    and which run-context param each reads (for the param editor)."""
    from dashboard_api.playbook_engine import STEP_KINDS
    meta = {
        "enrich": {"label": "Enrich entity", "params": []},
        "condition": {"label": "Condition gate", "params": ["field", "op", "value"]},
        "block_ip": {"label": "Block IP", "params": ["ip"]},
        "isolate_host": {"label": "Isolate host", "params": ["host"]},
        "disable_user": {"label": "Disable user", "params": ["user"]},
        "create_case": {"label": "Open case", "params": ["title"]},
        "add_note": {"label": "Add case note", "params": ["content"]},
        "close_alerts": {"label": "Resolve alerts", "params": []},
        "notify": {"label": "Notify", "params": ["message"]},
        "webhook": {"label": "Webhook", "params": []},
        "approval": {"label": "Human approval", "params": ["message"]},
    }
    return [{"kind": k, "type": STEP_KINDS[k], **meta.get(k, {"label": k, "params": []})}
            for k in STEP_KINDS]


@router.get("/playbooks")
def list_playbooks(user: dict = Depends(current_user)):
    where, params = "", []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        where, params = "WHERE org_id=?", [tenancy.org_of(user)]
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM playbooks {where} ORDER BY runs DESC", params).fetchall()
    return rows_to_dicts(rows)


def _snapshot_version(conn, playbook_id: str, steps_json: str, trigger_match_json: str,
                      author: str, note: str) -> int:
    """Save a versioned snapshot of a playbook's definition. Returns the new
    version number."""
    import uuid as _uuid
    row = conn.execute("SELECT COALESCE(MAX(version),0) AS v FROM playbook_versions "
                       "WHERE playbook_id=?", (playbook_id,)).fetchone()
    version = (row["v"] or 0) + 1
    conn.execute(
        "INSERT INTO playbook_versions (id,playbook_id,version,steps,trigger_match,author,note,"
        "created_at) VALUES (?,?,?,?,?,?,?,?)",
        (str(_uuid.uuid4()), playbook_id, version, steps_json, trigger_match_json,
         author, note, _now_iso()))
    return version


@router.post("/playbooks", status_code=201)
def create_playbook(body: PlaybookCreate, user: dict = Depends(require_perm("soar.write"))):
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
            "success_rate,avg_time,last_run,last_run_status,status,enabled,steps,trigger_match,org_id) "
            "VALUES (?,?,?,?,?,?,0,0,30,NULL,'idle','idle',1,?,?,?)",
            (pid, name, body.category, body.trigger or "Manual", body.trigger_type,
             body.description or f"{name} workflow.",
             dumps(display_steps(body.steps)), dumps(body.trigger_match),
             tenancy.org_of(user)),
        )
        _snapshot_version(conn, pid, dumps(display_steps(body.steps)),
                          dumps(body.trigger_match), user["email"], "created")
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
def update_playbook(playbook_id: str, body: PlaybookUpdate, user: dict = Depends(require_perm("soar.write"))):
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
        # Snapshot a new version whenever the step definition / triggers change.
        if body.steps is not None or body.trigger_match is not None:
            cur2 = conn.execute("SELECT steps, trigger_match FROM playbooks WHERE id=?",
                               (playbook_id,)).fetchone()
            _snapshot_version(conn, playbook_id, cur2["steps"], cur2["trigger_match"],
                              user["email"], "edited")
        audit(conn, user["email"], "playbook.update", playbook_id)
        conn.commit()
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    return row_to_dict(row)


@router.get("/playbooks/{playbook_id}/versions")
def list_playbook_versions(playbook_id: str):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, version, steps, trigger_match, author, note, created_at "
            "FROM playbook_versions WHERE playbook_id=? ORDER BY version DESC",
            (playbook_id,)).fetchall()
    return rows_to_dicts(rows)


@router.post("/playbooks/{playbook_id}/revert/{version}")
def revert_playbook(playbook_id: str, version: int, user: dict = Depends(require_perm("soar.write"))):
    """Restore a playbook's step definition to a previous version (which itself
    snapshots a new version, so history is append-only)."""
    with get_conn() as conn:
        snap = conn.execute(
            "SELECT steps, trigger_match FROM playbook_versions WHERE playbook_id=? AND version=?",
            (playbook_id, version)).fetchone()
        if not snap:
            raise HTTPException(status_code=404, detail="Version not found")
        cur = conn.execute("UPDATE playbooks SET steps=?, trigger_match=? WHERE id=?",
                           (snap["steps"], snap["trigger_match"], playbook_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Playbook not found")
        new_v = _snapshot_version(conn, playbook_id, snap["steps"], snap["trigger_match"],
                                 user["email"], f"reverted to v{version}")
        audit(conn, user["email"], "playbook.revert", playbook_id, f"to_version={version}")
        conn.commit()
        row = conn.execute("SELECT * FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    return {**row_to_dict(row), "revertedTo": version, "newVersion": new_v}


@router.post("/playbooks/{playbook_id}/run")
def run_playbook(playbook_id: str, body: PlaybookRunBody | None = None,
                 user: dict = Depends(require_perm("soar.write"))):
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
def list_playbook_runs(playbook_id: str, limit: int = Query(20, le=500)):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM playbook_runs WHERE playbook_id=? ORDER BY ts DESC LIMIT ?",
            (playbook_id, min(limit, 100))).fetchall()
    return rows_to_dicts(rows)


@router.get("/runs")
def list_runs(status: str | None = None, limit: int = Query(30, le=500),
              user: dict = Depends(current_user)):
    clauses, params = [], []
    # Tenant isolation (same pattern as alerts): active only when flipped on.
    from dashboard_api import tenancy
    if tenancy.enforced():
        clauses.append("org_id=?"); params.append(tenancy.org_of(user))
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
def approve_run(run_id: str, user: dict = Depends(require_perm("soar.write"))):
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
def reject_run(run_id: str, user: dict = Depends(require_perm("soar.write"))):
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
    base_url: str | None = None
    api_key: str | None = None


class ActionRun(BaseModel):
    action: str
    params: dict = {}


def _integration_public(d: dict) -> dict:
    """Strip the credential; expose only whether one is configured."""
    d = dict(d)
    d["credentialed"] = bool(d.get("base_url") and d.get("api_key"))
    d.pop("api_key", None)
    return d


@router.get("/integrations")
def list_integrations():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM integrations ORDER BY name").fetchall()
    return [_integration_public(r) for r in rows_to_dicts(rows)]


@router.post("/integrations", status_code=201)
def create_integration(body: IntegrationCreate, user: dict = Depends(require_perm("soar.write"))):
    import uuid
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Integration name is required")
    iid = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO integrations (id,name,vendor,category,status,last_sync,actions_run,"
            "avg_response_ms,description,actions,enabled,base_url,api_key) "
            "VALUES (?,?,?,?,'pending',NULL,0,0,?,?,1,?,?)",
            (iid, name, body.vendor or name, body.category or "Custom",
             body.description or f"{name} connector.", dumps(body.actions),
             (body.base_url or "").strip() or None,
             encrypt((body.api_key or "").strip() or None)),
        )
        audit(conn, user["email"], "integration.create", iid,
              f"name={name} credentialed={bool(body.base_url and body.api_key)}")
        conn.commit()
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (iid,)).fetchone()
    return _integration_public(row_to_dict(row))


class IntegrationUpdate(BaseModel):
    base_url: str | None = None
    api_key: str | None = None   # empty string clears the stored key
    enabled: bool | None = None


@router.patch("/integrations/{integration_id}")
def update_integration(integration_id: str, body: IntegrationUpdate,
                       user: dict = Depends(require_perm("soar.write"))):
    """Credential entry for an action integration: set/clear the vendor base
    URL + API key (the key is stored, never returned - list/detail expose only
    `credentialed`) and toggle enablement."""
    fields, values = [], []
    if body.base_url is not None:
        fields.append("base_url=?"); values.append(body.base_url.strip() or None)
    if body.api_key is not None:
        fields.append("api_key=?"); values.append(encrypt(body.api_key.strip() or None))
    if body.enabled is not None:
        fields.append("enabled=?"); values.append(1 if body.enabled else 0)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    values.append(integration_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE integrations SET {','.join(fields)} WHERE id=?", values)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Integration not found")
        audit(conn, user["email"], "integration.update", integration_id,
              "credentials" if (body.base_url is not None or body.api_key is not None) else "enabled")
        conn.commit()
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
    return _integration_public(row_to_dict(row))


@router.post("/integrations/{integration_id}/test")
def test_integration(integration_id: str, user: dict = Depends(require_perm("soar.write"))):
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
    return _integration_public(row_to_dict(row))


@router.post("/integrations/{integration_id}/actions/run")
def run_integration_action(integration_id: str, body: ActionRun, user: dict = Depends(require_perm("soar.write"))):
    """Execute a real response action on the tool: when the integration is
    credentialled, calls the vendor API (CrowdStrike contain / firewall block /
    IdP suspend / Jira issue); otherwise records a `not-configured` action.
    Every attempt is written to the action audit trail."""
    from dashboard_api.integration_actions import run_action
    action = body.action.strip()
    if not action:
        raise HTTPException(status_code=400, detail="Action is required")
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Integration not found")
        if not row["enabled"] or row["status"] == "disconnected":
            raise HTTPException(status_code=409, detail="Integration is not connected")
        result = run_action(conn, dict(row), action, body.params, user["email"])
        audit(conn, user["email"], "integration.action", integration_id,
              f"action={action} tool={row['name']} status={result['status']}")
        conn.commit()
        updated = conn.execute("SELECT * FROM integrations WHERE id=?", (integration_id,)).fetchone()
    return {**_integration_public(row_to_dict(updated)), "result": result}


@router.get("/integrations/{integration_id}/actions")
def integration_action_trail(integration_id: str, limit: int = Query(50, le=500)):
    """The action audit trail for one integration - what was done, to whom, and
    whether it was a live vendor call or recorded-only."""
    with get_conn() as conn:
        if not conn.execute("SELECT 1 FROM integrations WHERE id=?", (integration_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Integration not found")
        rows = conn.execute(
            "SELECT id, action, target, status, mode, detail, actor, ts FROM integration_actions "
            "WHERE integration_id=? ORDER BY ts DESC LIMIT ?", (integration_id, min(limit, 200))).fetchall()
    return rows_to_dicts(rows)


@router.get("/metrics")
def soar_metrics(user: dict = Depends(current_user)):
    # Workspace clause for the rollups - a no-op until multi-tenancy is on.
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    now = datetime.now(timezone.utc)
    week = (now - timedelta(days=7)).replace(microsecond=0).isoformat()
    fortnight = (now - timedelta(days=14)).replace(microsecond=0).isoformat()
    month = (now - timedelta(days=30)).replace(microsecond=0).isoformat()
    with get_conn() as conn:
        cases = conn.execute(
            f"SELECT status, severity, playbook, created, updated, sla_hours FROM cases WHERE 1=1 {sc}",
            sp).fetchall()
        pbs = conn.execute(
            f"SELECT runs, success_rate, avg_time, last_run FROM playbooks WHERE 1=1 {sc}", sp).fetchall()
        # Playbook runs in the trailing 30 days - the actual basis for "time saved
        # this month". `playbooks.runs` is an all-time cumulative counter, so using
        # it (as before) reported all-time hours under a "month" label.
        runs_month = conn.execute(
            f"SELECT COUNT(*) AS n FROM playbook_runs WHERE ts >= ? {sc}", [month] + sp
        ).fetchone()["n"]
        # Runs since midnight UTC - the honest "Playbooks Run Today". Counting
        # playbooks whose last_run is non-null (as before) counted every playbook
        # that had *ever* run, not today's.
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        runs_today = conn.execute(
            f"SELECT COUNT(*) AS n FROM playbook_runs WHERE ts >= ? {sc}", [midnight] + sp
        ).fetchone()["n"]
        # MTTR in minutes from per-alert response latency (consistent with SIEM KPIs).
        mttr_row = conn.execute(
            "SELECT AVG(respond_latency_sec) / 60.0 AS v FROM alerts "
            f"WHERE respond_latency_sec IS NOT NULL {sc}", sp
        ).fetchone()
        # Real week-over-week MTTR movement: this week's average response
        # latency vs the prior week's. Null when a window has no data - the UI
        # shows "no baseline" instead of a made-up arrow.
        wow = conn.execute(
            "SELECT AVG(CASE WHEN ts >= ? THEN respond_latency_sec END) AS cur, "
            "AVG(CASE WHEN ts >= ? AND ts < ? THEN respond_latency_sec END) AS prev "
            f"FROM alerts WHERE respond_latency_sec IS NOT NULL {sc}",
            [week, fortnight, week] + sp
        ).fetchone()
    open_cases = sum(1 for c in cases if c["status"] not in ("resolved", "closed"))
    crit_open = sum(1 for c in cases if c["status"] not in ("resolved", "closed") and c["severity"] == "critical")
    sla_breached = sum(1 for c in cases if c["status"] not in ("resolved", "closed")
                       and _sla(dict(c))["slaStatus"] == "breached")
    closed = [c for c in cases if c["status"] in ("resolved", "closed")]
    closed_total = len(closed)
    # "Cases closed this week" must actually window to the week - the cases query
    # has no time filter, so len(closed) is the all-time closed count. Use the
    # `updated` timestamp as the close-time proxy (same basis as the automation
    # trend below; there's no dedicated closed_at column).
    closed_this_week = sum(1 for c in closed if (c["updated"] or "") >= week)
    total_runs = sum(p["runs"] for p in pbs)
    avg_pb = int(sum(p["avg_time"] for p in pbs) / len(pbs)) if pbs else 0
    # Automation rate: share of ALL closed cases that were driven by an automated
    # playbook (field is unqualified; its week-over-week movement is automationTrendPp).
    automated = sum(1 for c in closed if c["playbook"])
    automation_rate = round(automated / closed_total * 100, 1) if closed_total else 0
    mttr = round(mttr_row["v"] or 0, 1)
    mttr_trend_pct = (round((wow["cur"] - wow["prev"]) / wow["prev"] * 100, 1)
                      if wow["cur"] is not None and wow["prev"] else None)

    # Automation-rate movement in percentage points: closed-this-week vs
    # closed-the-week-before. Null when either window is empty.
    def _auto_rate(lo: str, hi: str | None) -> float | None:
        sel = [c for c in closed
               if (c["updated"] or "") >= lo and (hi is None or (c["updated"] or "") < hi)]
        return round(sum(1 for c in sel if c["playbook"]) / len(sel) * 100, 1) if sel else None
    cur_rate, prev_rate = _auto_rate(week, None), _auto_rate(fortnight, week)
    automation_trend_pp = (round(cur_rate - prev_rate, 1)
                           if cur_rate is not None and prev_rate is not None else None)
    return {
        "openCases": open_cases,
        "criticalOpen": crit_open,
        "slaBreached": sla_breached,
        "mttr": mttr, "mttrTrendPct": mttr_trend_pct,
        "automationRate": automation_rate, "automationTrendPp": automation_trend_pp,
        "timeSavedMonth": round(runs_month * avg_pb / 3600, 1),
        "runsMonth": runs_month,
        "totalRuns": total_runs,
        "playbooksToday": runs_today,
        "avgPlaybookTime": avg_pb,
        "casesClosedWeek": closed_this_week,
    }


def _duration_secs(start: str | None, end: str | None) -> float | None:
    try:
        a = datetime.fromisoformat((start or "").replace("Z", "+00:00"))
        b = datetime.fromisoformat((end or "").replace("Z", "+00:00"))
        return max(0.0, (b - a).total_seconds())
    except (ValueError, TypeError):
        return None


@router.get("/analysts")
def soar_analysts(user: dict = Depends(current_user)):
    """Per-analyst case workload + throughput, aggregated from the cases each one
    owns. Real data (empty until cases are assigned), so the SOC-metrics
    leaderboard / throughput is no longer a hardcoded list."""
    sc, sp = tenancy.scope_sql(tenancy.org_of(user))
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT owner, status, severity, created, updated FROM cases WHERE 1=1 {sc}", sp
        ).fetchall()
    agg: dict[str, dict] = {}
    for c in rows:
        owner = (c["owner"] or "").strip() or "Unassigned"
        a = agg.setdefault(owner, {"name": owner, "handled": 0, "closed": 0, "open": 0,
                                   "critical": 0, "_secs": []})
        a["handled"] += 1
        if c["status"] in ("resolved", "closed"):
            a["closed"] += 1
            secs = _duration_secs(c["created"], c["updated"])
            if secs is not None:
                a["_secs"].append(secs)
        else:
            a["open"] += 1
            if c["severity"] == "critical":
                a["critical"] += 1
    out = []
    for a in agg.values():
        secs = a.pop("_secs")
        a["avgResolveMins"] = round(sum(secs) / len(secs) / 60.0, 1) if secs else None
        out.append(a)
    # Real analysts first (most closed), the Unassigned bucket last.
    out.sort(key=lambda x: (x["name"] == "Unassigned", -x["closed"], -x["handled"]))
    return out
