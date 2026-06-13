"""SOAR playbook execution engine.

Playbooks stop being decorative here: each step has an executable `kind` that
acts on the platform's real stores, with a full per-step audit trail:

  enrich        → look the target entity up in the IOC store + alert history
  condition     → gate the run on the triggering alert (severity/technique/…)
  block_ip      → push the IP to the blocklist (IOC store, severity critical)
                  and record the action on a connected firewall integration
  isolate_host  → tag the asset isolated + record the action on the EDR
  disable_user  → record an identity-provider disable action
  create_case   → open a real SOAR case bound to the run's entities
  add_note      → append a war-room note to the run's case
  close_alerts  → resolve the triggering alert (+ same-entity open alerts)
  notify        → raise a platform notification
  webhook       → emit a `playbook.action` webhook event
  approval      → pause for a human approve/reject (resumable run)

Every run is persisted to `playbook_runs` with per-step status/detail, the
triggering context, and who/what started it (analyst or the automation
engine). Dry-run evaluates the same steps without writing anything.
Auto-trigger: enabled playbooks whose `trigger_match` criteria fit a fresh
alert are executed by the live engine, which is what makes the SOAR
automation rate a real number.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

from dashboard_api.db import audit, dumps

# kind → display type for the playbook canvas (check|action|decision|notify|human)
STEP_KINDS = {
    "enrich": "check",
    "condition": "decision",
    "block_ip": "action",
    "isolate_host": "action",
    "disable_user": "action",
    "create_case": "action",
    "add_note": "action",
    "close_alerts": "action",
    "notify": "notify",
    "webhook": "notify",
    "approval": "human",
}

# Canonical playbook definitions - shared by the demo seeder and the live-mode
# bootstrap so both modes run the same real automation content.
PLAYBOOK_DEFS = [
    {"name": "Phishing Email Triage", "category": "Email",
     "trigger": "Suspicious email reported", "trigger_type": "auto",
     "trigger_match": {"techniques": ["T1566"]},
     "description": "Enrich the reported sender, open a case, notify the user-awareness channel and resolve the alert.",
     "steps": [
         {"kind": "enrich", "name": "Enrich sender & URL reputation"},
         {"kind": "condition", "name": "Confirmed phishing?",
          "params": {"field": "severity", "op": "in", "value": "critical,high,medium"}},
         {"kind": "create_case", "name": "Open phishing case"},
         {"kind": "notify", "name": "Notify security-awareness channel"},
         {"kind": "close_alerts", "name": "Resolve triggering alert"},
     ]},
    {"name": "Ransomware Containment", "category": "Endpoint",
     "trigger": "Mass file encryption detected", "trigger_type": "auto",
     "trigger_match": {"severities": ["critical"], "techniques": ["T1486"]},
     "description": "Isolate the encrypting host at the EDR, open a critical case and alert the on-call.",
     "steps": [
         {"kind": "enrich", "name": "Enrich host & process telemetry"},
         {"kind": "isolate_host", "name": "Isolate host via EDR"},
         {"kind": "create_case", "name": "Open ransomware case"},
         {"kind": "notify", "name": "Page on-call responder"},
     ]},
    {"name": "Compromised Account Response", "category": "Identity",
     "trigger": "Credential-abuse detection", "trigger_type": "auto",
     "trigger_match": {"techniques": ["T1110", "T1078"]},
     "description": "Disable the abused account, open a case and resolve the triggering alerts.",
     "steps": [
         {"kind": "enrich", "name": "Enrich account activity"},
         {"kind": "disable_user", "name": "Disable account at the IdP"},
         {"kind": "create_case", "name": "Open account-compromise case"},
         {"kind": "close_alerts", "name": "Resolve credential alerts"},
         {"kind": "notify", "name": "Notify identity team"},
     ]},
    {"name": "Malware Detonation & Block", "category": "Endpoint",
     "trigger": "New malware hash observed", "trigger_type": "auto",
     "trigger_match": {"techniques": ["T1059", "T1204"]},
     "description": "Enrich the sample, push the source to the blocklist and notify the SOC.",
     "steps": [
         {"kind": "enrich", "name": "Detonate & enrich sample"},
         {"kind": "block_ip", "name": "Block source at the firewall"},
         {"kind": "notify", "name": "Notify SOC channel"},
     ]},
    {"name": "DDoS Mitigation", "category": "Network",
     "trigger": "Traffic anomaly threshold", "trigger_type": "manual",
     "trigger_match": {},
     "description": "Block the flood source and hand off to the upstream scrubbing provider.",
     "steps": [
         {"kind": "enrich", "name": "Validate traffic anomaly"},
         {"kind": "block_ip", "name": "Block source at the edge"},
         {"kind": "webhook", "name": "Hand off to scrubbing provider"},
         {"kind": "notify", "name": "Notify network operations"},
     ]},
    {"name": "Insider Threat Investigation", "category": "Identity",
     "trigger": "Manual escalation", "trigger_type": "manual",
     "trigger_match": {},
     "description": "Sensitive workflow: human approval gates the investigation case.",
     "steps": [
         {"kind": "enrich", "name": "Compile user activity timeline"},
         {"kind": "approval", "name": "Approve covert investigation",
          "params": {"message": "Legal/HR approval required before proceeding"}},
         {"kind": "create_case", "name": "Open restricted case"},
         {"kind": "add_note", "name": "Record chain-of-custody note",
          "params": {"content": "Evidence handling per IR-7 chain-of-custody procedure."}},
         {"kind": "notify", "name": "Notify CISO"},
     ]},
    {"name": "C2 Beacon Isolation", "category": "Network",
     "trigger": "Known C2 IP beacon", "trigger_type": "auto",
     "trigger_match": {"severities": ["critical"], "techniques": ["T1071"]},
     "description": "Full containment: block the C2, isolate the beaconing host, case + resolve.",
     "steps": [
         {"kind": "enrich", "name": "Enrich C2 infrastructure"},
         {"kind": "condition", "name": "Confirmed critical/high?",
          "params": {"field": "severity", "op": "in", "value": "critical,high"}},
         {"kind": "block_ip", "name": "Block C2 destination"},
         {"kind": "isolate_host", "name": "Isolate beaconing host"},
         {"kind": "create_case", "name": "Open intrusion case"},
         {"kind": "close_alerts", "name": "Resolve beacon alerts"},
         {"kind": "notify", "name": "Notify SOC channel"},
     ]},
    {"name": "Data Exfil Investigation", "category": "Network",
     "trigger": "Anomalous egress volume", "trigger_type": "manual",
     "trigger_match": {},
     "description": "Approval-gated: block the egress destination and open an investigation.",
     "steps": [
         {"kind": "enrich", "name": "Profile egress destination"},
         {"kind": "approval", "name": "Approve egress block",
          "params": {"message": "Blocking may impact a business integration - approve?"}},
         {"kind": "block_ip", "name": "Block egress destination"},
         {"kind": "create_case", "name": "Open exfiltration case"},
         {"kind": "notify", "name": "Notify data-protection officer"},
     ]},
]


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def display_steps(steps: list[dict]) -> list[dict]:
    """Stamp the display type (+ idle status) onto authored steps."""
    out = []
    for s in steps:
        out.append({**s, "type": STEP_KINDS.get(s.get("kind", ""), "action"),
                    "status": s.get("status", "idle"), "duration": s.get("duration", 5)})
    return out


def seed_builtin_playbooks():
    """Insert the canonical playbooks if absent (live-mode bootstrap, idempotent)."""
    from dashboard_api.db import get_conn
    with get_conn() as conn:
        for d in PLAYBOOK_DEFS:
            if conn.execute("SELECT 1 FROM playbooks WHERE name=?", (d["name"],)).fetchone():
                continue
            conn.execute(
                "INSERT INTO playbooks (id,name,category,trigger,trigger_type,description,runs,"
                "success_rate,avg_time,last_run,last_run_status,status,enabled,steps,trigger_match) "
                "VALUES (?,?,?,?,?,?,0,0,45,NULL,'idle','idle',1,?,?)",
                (str(uuid.uuid4()), d["name"], d["category"], d["trigger"], d["trigger_type"],
                 d["description"], dumps(display_steps(d["steps"])), dumps(d["trigger_match"])),
            )
        conn.commit()


# ── Context ──────────────────────────────────────────────────────────────────────

def build_context(conn, alert_id: str | None) -> dict:
    """Assemble the run context from the triggering alert (if any)."""
    ctx = {"alert": None, "entity": None, "case_id": None}
    if alert_id:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if row:
            a = dict(row)
            ctx["alert"] = {k: a.get(k) for k in
                            ("id", "title", "severity", "src_ip", "hostname", "username",
                             "mitre_tech_id", "mitre_tactic", "rule_name", "rule_id", "risk_score")}
            if a.get("src_ip"):
                ctx["entity"] = {"type": "ip", "value": a["src_ip"]}
            elif a.get("hostname"):
                ctx["entity"] = {"type": "host", "value": a["hostname"]}
            elif a.get("username"):
                ctx["entity"] = {"type": "user", "value": a["username"]}
    return ctx


def _integration_action(conn, keywords: tuple, action: str, dry_run: bool) -> str:
    """Record an action on the first connected integration matching a keyword.
    Returns a suffix describing where the action landed."""
    rows = conn.execute(
        "SELECT id, name, category, vendor FROM integrations "
        "WHERE enabled=1 AND status='connected'").fetchall()
    target = None
    for r in rows:
        hay = f"{r['name']} {r['category']} {r['vendor']}".lower()
        if any(k in hay for k in keywords):
            target = r
            break
    if target is None:
        return " (no connected integration - recorded locally)"
    if not dry_run:
        conn.execute("UPDATE integrations SET actions_run=actions_run+1, last_sync=? WHERE id=?",
                     (_now(), target["id"]))
    return f" via {target['name']}"


# ── Step implementations ─────────────────────────────────────────────────────────
# Each returns (status, detail). status: success | skipped | failed.

def _step_enrich(conn, ctx, params, dry_run):
    ent = ctx.get("entity")
    if not ent:
        return "skipped", "No entity in run context to enrich"
    val = ent["value"]
    ioc = conn.execute("SELECT severity, confidence, threat_type FROM iocs WHERE value=?",
                       (val,)).fetchone()
    related = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE src_ip=? OR hostname=? OR username=?",
        (val, val, val)).fetchone()["n"]
    ctx["enrichment"] = {"ioc": dict(ioc) if ioc else None, "relatedAlerts": related}
    if ioc:
        return "success", (f"{val}: known {ioc['threat_type'] or 'malicious'} IOC "
                           f"(confidence {ioc['confidence']}) · {related} related alerts")
    return "success", f"{val}: no IOC record · {related} related alerts"


def _step_condition(conn, ctx, params, dry_run):
    from dashboard_api.rule_engine import matches_event
    alert = ctx.get("alert")
    cond = {"field": params.get("field", "severity"), "op": params.get("op", "in"),
            "value": params.get("value", "critical,high")}
    ok = bool(alert) and matches_event(alert, {"conditions": [cond], "logic": "and"})
    have = (alert or {}).get(cond["field"])
    if ok:
        return "success", f"Condition met: {cond['field']}={have}"
    return "gate", f"Condition not met ({cond['field']}={have}, wanted {cond['op']} {cond['value']}) - run gated"


def _step_block_ip(conn, ctx, params, dry_run):
    ip = params.get("ip") or ((ctx.get("entity") or {}).get("value")
                              if (ctx.get("entity") or {}).get("type") == "ip" else None) \
        or (ctx.get("alert") or {}).get("src_ip")
    if not ip:
        return "skipped", "No IP in run context to block"
    where = _integration_action(conn, ("firewall", "palo", "fortinet", "network", "cloudflare", "edge"),
                                f"block {ip}", dry_run)
    if dry_run:
        return "success", f"Would push {ip} to the blocklist{where}"
    existing = conn.execute("SELECT 1 FROM iocs WHERE value=?", (ip,)).fetchone()
    if existing:
        conn.execute("UPDATE iocs SET severity='critical', last_seen=? WHERE value=?", (_now(), ip))
    else:
        conn.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
            "first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), "ip", ip, "soar-blocked", 95, "critical",
             "SOAR playbook", "", _now(), _now(), dumps(["blocked", "soar"])))
    return "success", f"{ip} pushed to blocklist{where}"


def _step_isolate_host(conn, ctx, params, dry_run):
    host = params.get("host") or (ctx.get("alert") or {}).get("hostname") \
        or ((ctx.get("entity") or {}).get("value")
            if (ctx.get("entity") or {}).get("type") == "host" else None)
    if not host:
        return "skipped", "No hostname in run context to isolate"
    where = _integration_action(conn, ("edr", "crowdstrike", "sentinel", "defender", "endpoint"),
                                f"isolate {host}", dry_run)
    if dry_run:
        return "success", f"Would isolate {host}{where}"
    row = conn.execute("SELECT id, tags FROM assets WHERE name=?", (host,)).fetchone()
    if row:
        try:
            tags = json.loads(row["tags"] or "[]")
        except (ValueError, TypeError):
            tags = []
        if "isolated" not in tags:
            tags.append("isolated")
        conn.execute("UPDATE assets SET tags=? WHERE id=?", (dumps(tags), row["id"]))
        return "success", f"{host} isolated{where} (asset tagged)"
    return "success", f"{host} isolation requested{where} (no managed asset record)"


def _step_disable_user(conn, ctx, params, dry_run):
    user = params.get("user") or (ctx.get("alert") or {}).get("username") \
        or ((ctx.get("entity") or {}).get("value")
            if (ctx.get("entity") or {}).get("type") == "user" else None)
    if not user:
        return "skipped", "No username in run context to disable"
    where = _integration_action(conn, ("identity", "okta", "azure", "directory", "iam"),
                                f"disable {user}", dry_run)
    if dry_run:
        return "success", f"Would disable account {user}{where}"
    return "success", f"Account {user} disable requested{where}"


def _step_create_case(conn, ctx, params, dry_run):
    import random
    alert = ctx.get("alert") or {}
    pb_name = ctx.get("_playbook_name", "Playbook")
    title = params.get("title") or (f"{pb_name}: {alert['title']}" if alert.get("title")
                                    else f"{pb_name} response")
    severity = alert.get("severity") if alert.get("severity") in ("critical", "high", "medium", "low") else "medium"
    if dry_run:
        return "success", f"Would open a {severity} case “{title[:60]}”"
    now = _now()
    cid = None
    for _ in range(50):
        cand = f"CASE-{random.randint(1000, 9999)}"
        if not conn.execute("SELECT 1 FROM cases WHERE id=?", (cand,)).fetchone():
            cid = cand
            break
    if cid is None:
        return "failed", "Could not allocate a case id"
    entities = [ctx["entity"]] if ctx.get("entity") else []
    war = [{"ts": now, "actor": "playbook-engine", "type": "system",
            "content": f"Case opened by playbook “{pb_name}”."}]
    tasks = [{"id": f"T{i+1}", "phase": p, "name": n, "status": "pending", "assignee": None, "notes": ""}
             for i, (p, n) in enumerate([("Triage", "Validate playbook findings"),
                                         ("Containment", "Verify automated containment"),
                                         ("Eradication", "Remove persistence"),
                                         ("Recovery", "Restore service")])]
    conn.execute(
        "INSERT INTO cases (id,title,type,severity,status,owner,playbook,sla_hours,created,updated,"
        "alert_count,description,entities,war_room,tasks,evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (cid, title, "Automated Response", severity, "new", "", pb_name,
         4 if severity == "critical" else 8, now, now, 1 if alert.get("id") else 0,
         f"Opened automatically by the “{pb_name}” playbook."
         + (f" Triggering alert: {alert.get('title')}." if alert.get("title") else ""),
         dumps(entities), dumps(war), dumps(tasks), dumps([])),
    )
    ctx["case_id"] = cid
    return "success", f"Case {cid} opened ({severity})"


def _step_add_note(conn, ctx, params, dry_run):
    cid = ctx.get("case_id")
    content = params.get("content") or "Playbook checkpoint."
    if not cid:
        return "skipped", "No case in run context for the note"
    if dry_run:
        return "success", f"Would add a war-room note to {cid}"
    row = conn.execute("SELECT war_room FROM cases WHERE id=?", (cid,)).fetchone()
    if not row:
        return "failed", f"Case {cid} not found"
    war = json.loads(row["war_room"] or "[]")
    war.append({"ts": _now(), "actor": "playbook-engine", "type": "system", "content": content})
    conn.execute("UPDATE cases SET war_room=?, updated=? WHERE id=?", (dumps(war), _now(), cid))
    return "success", f"War-room note added to {cid}"


def _step_close_alerts(conn, ctx, params, dry_run):
    alert = ctx.get("alert")
    ent = ctx.get("entity")
    if not alert and not ent:
        return "skipped", "No alert/entity in run context to resolve"
    if dry_run:
        return "success", "Would resolve the triggering alert (+ same-entity open alerts)"
    closed = 0
    if alert and alert.get("id"):
        closed += conn.execute(
            "UPDATE alerts SET status='resolved', disposition='true-positive' "
            "WHERE id=? AND status NOT IN ('resolved','closed')", (alert["id"],)).rowcount
    if ent:
        closed += conn.execute(
            "UPDATE alerts SET status='resolved', disposition='true-positive' "
            "WHERE (src_ip=? OR hostname=? OR username=?) AND status NOT IN ('resolved','closed')",
            (ent["value"], ent["value"], ent["value"])).rowcount
    return "success", f"{closed} alert(s) resolved as contained"


def _step_notify(conn, ctx, params, dry_run):
    pb_name = ctx.get("_playbook_name", "Playbook")
    alert = ctx.get("alert") or {}
    msg = params.get("message") or (f"{pb_name} responded to: {alert['title']}" if alert.get("title")
                                    else f"{pb_name} run completed")
    if dry_run:
        return "success", f"Would notify: “{msg[:70]}”"
    from dashboard_api.routers.platform import notify
    notify(conn, type="playbook", severity=alert.get("severity") or "info",
           title=msg, detail=ctx.get("case_id"), link="/dashboard/soar/playbooks")
    return "success", f"Notification sent: “{msg[:70]}”"


def _step_webhook(conn, ctx, params, dry_run):
    pb_name = ctx.get("_playbook_name", "Playbook")
    if dry_run:
        return "success", "Would emit a playbook.action webhook event"
    ctx.setdefault("_dispatches", []).append(
        ("playbook.action", {"playbook": pb_name, "step": params.get("name", "webhook"),
                             "entity": ctx.get("entity"), "caseId": ctx.get("case_id")}))
    return "success", "playbook.action webhook event queued"


_STEP_FNS = {
    "enrich": _step_enrich, "condition": _step_condition, "block_ip": _step_block_ip,
    "isolate_host": _step_isolate_host, "disable_user": _step_disable_user,
    "create_case": _step_create_case, "add_note": _step_add_note,
    "close_alerts": _step_close_alerts, "notify": _step_notify, "webhook": _step_webhook,
}


# ── Executor ─────────────────────────────────────────────────────────────────────

def _exec_from(conn, steps: list[dict], results: list[dict], start: int,
               ctx: dict, dry_run: bool) -> str:
    """Execute steps[start:], appending one result per step.
    Returns the run status: success | failed | awaiting-approval."""
    gated = False
    failed = False
    for i in range(start, len(steps)):
        s = steps[i]
        kind = s.get("kind")
        name = s.get("name") or kind or f"Step {i+1}"
        params = s.get("params") or {}
        if gated or failed:
            results.append({"idx": i, "kind": kind, "name": name, "status": "skipped",
                            "detail": "Gated by an earlier step" if gated else "Skipped after failure",
                            "ts": _now()})
            continue
        if kind == "approval" and not dry_run:
            results.append({"idx": i, "kind": kind, "name": name, "status": "pending-approval",
                            "detail": params.get("message") or "Awaiting human approval",
                            "ts": _now()})
            return "awaiting-approval"
        if kind == "approval" and dry_run:
            results.append({"idx": i, "kind": kind, "name": name, "status": "success",
                            "detail": "Would pause for human approval", "ts": _now()})
            continue
        fn = _STEP_FNS.get(kind)
        if fn is None:
            results.append({"idx": i, "kind": kind, "name": name, "status": "skipped",
                            "detail": "No executable action for this step", "ts": _now()})
            continue
        try:
            status, detail = fn(conn, ctx, params, dry_run)
        except Exception as exc:  # a step error fails the run, never the API
            status, detail = "failed", f"Step error: {exc}"
        if status == "gate":
            results.append({"idx": i, "kind": kind, "name": name, "status": "success",
                            "detail": detail, "ts": _now()})
            gated = True
            continue
        results.append({"idx": i, "kind": kind, "name": name, "status": status,
                        "detail": detail, "ts": _now()})
        if status == "failed":
            failed = True
    return "failed" if failed else "success"


def _save_run(conn, run: dict):
    conn.execute(
        "INSERT OR REPLACE INTO playbook_runs (id,playbook_id,playbook_name,ts,finished,status,"
        "trigger,actor,alert_id,current_step,context,steps) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (run["id"], run["playbook_id"], run["playbook_name"], run["ts"], run.get("finished"),
         run["status"], run["trigger"], run.get("actor"), run.get("alert_id"),
         run.get("current_step", 0), dumps({k: v for k, v in run["context"].items()
                                            if not k.startswith("_")}),
         dumps(run["steps"])))


def _finish_playbook(conn, playbook_id: str, ok: bool):
    row = conn.execute("SELECT runs, success_rate FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    if not row:
        return
    runs = max(1, row["runs"])
    new_rate = round(((row["success_rate"] * (runs - 1)) + (1.0 if ok else 0.0)) / runs, 3)
    conn.execute("UPDATE playbooks SET success_rate=?, last_run_status=?, status='idle' WHERE id=?",
                 (new_rate, "success" if ok else "failure", playbook_id))


def execute_playbook(conn, pb: dict, *, actor: str, trigger: str = "manual",
                     alert_id: str | None = None, dry_run: bool = False) -> dict:
    """Run a playbook's steps. Persists a run record (unless dry_run) and
    returns it; webhook dispatches are queued on run['dispatches']."""
    steps = pb.get("steps") or []
    if isinstance(steps, str):
        try:
            steps = json.loads(steps)
        except (ValueError, TypeError):
            steps = []
    ctx = build_context(conn, alert_id)
    ctx["_playbook_name"] = pb["name"]
    results: list[dict] = []
    status = _exec_from(conn, steps, results, 0, ctx, dry_run)
    now = _now()
    run = {"id": str(uuid.uuid4()), "playbook_id": pb["id"], "playbook_name": pb["name"],
           "ts": now, "finished": None if status == "awaiting-approval" else now,
           "status": status, "trigger": trigger, "actor": actor, "alert_id": alert_id,
           "current_step": next((r["idx"] for r in results if r["status"] == "pending-approval"),
                                len(results)),
           "context": ctx, "steps": results,
           "dispatches": ctx.get("_dispatches", [])}
    if dry_run:
        run["dryRun"] = True
        return run
    _save_run(conn, run)
    conn.execute("UPDATE playbooks SET runs=runs+1, last_run=?, status=? WHERE id=?",
                 (now, "running" if status == "awaiting-approval" else "idle", pb["id"]))
    if status == "awaiting-approval":
        conn.execute("UPDATE playbooks SET last_run_status='running' WHERE id=?", (pb["id"],))
        from dashboard_api.routers.platform import notify
        notify(conn, type="approval", severity="high",
               title=f"Approval required: {pb['name']}",
               detail=run["id"], link="/dashboard/soar/playbooks")
    else:
        _finish_playbook(conn, pb["id"], status == "success")
    audit(conn, actor, "playbook.execute", pb["id"],
          f"name={pb['name']} trigger={trigger} status={status}")
    return run


def resolve_approval(conn, run_id: str, *, approve: bool, actor: str) -> dict | None:
    """Approve (resume) or reject a run paused at an approval step.
    Returns the updated run, or None if not found. Raises ValueError when the
    run is not awaiting approval."""
    row = conn.execute("SELECT * FROM playbook_runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        return None
    if row["status"] != "awaiting-approval":
        raise ValueError("Run is not awaiting approval")
    pb = conn.execute("SELECT * FROM playbooks WHERE id=?", (row["playbook_id"],)).fetchone()
    steps = json.loads(pb["steps"] or "[]") if pb else []
    results = json.loads(row["steps"] or "[]")
    ctx = json.loads(row["context"] or "{}")
    ctx["_playbook_name"] = row["playbook_name"]
    idx = row["current_step"]
    # stamp the approval step
    for r in results:
        if r["idx"] == idx and r["status"] == "pending-approval":
            r["status"] = "success" if approve else "failed"
            r["detail"] = f"{'Approved' if approve else 'Rejected'} by {actor}"
            r["ts"] = _now()
    if approve:
        status = _exec_from(conn, steps, results, idx + 1, ctx, dry_run=False)
    else:
        for i in range(idx + 1, len(steps)):
            results.append({"idx": i, "kind": steps[i].get("kind"),
                            "name": steps[i].get("name") or f"Step {i+1}",
                            "status": "skipped", "detail": "Run rejected", "ts": _now()})
        status = "rejected"
    run = {"id": run_id, "playbook_id": row["playbook_id"], "playbook_name": row["playbook_name"],
           "ts": row["ts"], "finished": _now(), "status": status, "trigger": row["trigger"],
           "actor": row["actor"], "alert_id": row["alert_id"], "current_step": len(results),
           "context": ctx, "steps": results, "dispatches": ctx.get("_dispatches", [])}
    _save_run(conn, run)
    if pb:
        _finish_playbook(conn, pb["id"], status == "success")
    audit(conn, actor, "playbook.approval", run_id,
          f"decision={'approve' if approve else 'reject'} playbook={row['playbook_name']}")
    return run


# ── Automation triggers ──────────────────────────────────────────────────────────

def _alert_matches(match: dict, alert: dict) -> bool:
    sevs = match.get("severities")
    if sevs and alert.get("severity") not in sevs:
        return False
    techs = match.get("techniques")
    if techs:
        tid = alert.get("mitre_tech_id") or ""
        if not any(tid.startswith(t) for t in techs):
            return False
    rule = match.get("rule")
    if rule and rule.lower() not in (alert.get("rule_name") or "").lower():
        return False
    return bool(sevs or techs or rule)


def auto_trigger_playbooks(conn, max_runs: int = 2) -> tuple[int, list]:
    """Run enabled auto playbooks whose trigger_match fits a fresh open alert
    that has no run yet. Returns (runs_started, webhook_dispatches)."""
    pbs = conn.execute(
        "SELECT * FROM playbooks WHERE enabled=1 AND trigger_type='auto'").fetchall()
    candidates = []
    for p in pbs:
        try:
            match = json.loads(p["trigger_match"] or "{}")
        except (ValueError, TypeError):
            match = {}
        if match:
            candidates.append((dict(p), match))
    if not candidates:
        return 0, []
    since = (datetime.now(timezone.utc) - timedelta(minutes=15)).replace(microsecond=0).isoformat()
    alerts = conn.execute(
        "SELECT * FROM alerts WHERE ts >= ? AND status NOT IN ('resolved','closed') "
        "ORDER BY ts DESC LIMIT 100", (since,)).fetchall()
    started = 0
    dispatches: list = []
    for pb, match in candidates:
        if started >= max_runs:
            break
        for a in alerts:
            alert = dict(a)
            if not _alert_matches(match, alert):
                continue
            if conn.execute("SELECT 1 FROM playbook_runs WHERE playbook_id=? AND alert_id=?",
                            (pb["id"], alert["id"])).fetchone():
                continue
            run = execute_playbook(conn, pb, actor="automation-engine", trigger="auto",
                                   alert_id=alert["id"])
            dispatches.extend(run.get("dispatches", []))
            started += 1
            break
    return started, dispatches
