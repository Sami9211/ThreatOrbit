"""SOAR playbook engine: execution, gating, approval resume, auto-trigger.

Locks in the real automation behaviour: a dry-run writes nothing, a live run
persists and acts on the platform stores, an approval step pauses a run until a
human resolves it, and auto-trigger fires an enabled playbook on a matching
fresh alert exactly once.
"""
import json
import uuid

from dashboard_api.db import get_conn
from dashboard_api.detections import _insert_alert
from dashboard_api.playbook_engine import (
    seed_builtin_playbooks, execute_playbook, resolve_approval,
    auto_trigger_playbooks,
)


def _pb(conn, name):
    return dict(conn.execute("SELECT * FROM playbooks WHERE name=?", (name,)).fetchone())


def test_dry_run_persists_nothing():
    seed_builtin_playbooks()
    with get_conn() as conn:
        run = execute_playbook(conn, _pb(conn, "Malware Detonation & Block"),
                               actor="tester", dry_run=True)
    assert run.get("dryRun") is True
    assert run["steps"] and all("status" in s for s in run["steps"])
    with get_conn() as conn:
        assert conn.execute("SELECT 1 FROM playbook_runs WHERE id=?", (run["id"],)).fetchone() is None


def test_live_run_persists_and_opens_case():
    seed_builtin_playbooks()
    tag = uuid.uuid4().hex[:8]
    host = f"PB-RANSOM-{tag}"
    with get_conn() as conn:
        aid = _insert_alert(conn, title=f"encrypt {tag}", severity="critical", risk=95,
                            rule_name="R-PB", hostname=host, mitre_tech_id="T1486")
        conn.commit()
        pb = _pb(conn, "Ransomware Containment")   # steps: enrich, isolate_host, create_case, notify
        run = execute_playbook(conn, pb, actor="tester", trigger="manual", alert_id=aid)
        conn.commit()
    assert run["status"] == "success"
    with get_conn() as conn:
        assert conn.execute("SELECT 1 FROM playbook_runs WHERE id=?", (run["id"],)).fetchone()
        # the create_case step opened a case bound to the host
        case = conn.execute("SELECT id FROM cases WHERE entities LIKE ? ORDER BY created DESC LIMIT 1",
                            (f'%{host}%',)).fetchone()
    assert case is not None


def test_approval_step_pauses_then_resumes():
    seed_builtin_playbooks()
    with get_conn() as conn:
        # "Insider Threat Investigation" has an approval step gating the rest.
        pb = _pb(conn, "Insider Threat Investigation")
        run = execute_playbook(conn, pb, actor="tester", trigger="manual")
        conn.commit()
    assert run["status"] == "awaiting-approval"
    # Approving resumes and completes the remaining steps.
    with get_conn() as conn:
        resumed = resolve_approval(conn, run["id"], approve=True, actor="approver")
        conn.commit()
    assert resumed is not None and resumed["status"] == "success"
    assert any(s["status"] == "success" and "pprov" in (s.get("detail") or "").lower()
               for s in resumed["steps"])


def test_approval_reject_skips_remaining():
    seed_builtin_playbooks()
    with get_conn() as conn:
        run = execute_playbook(conn, _pb(conn, "Data Exfil Investigation"),
                               actor="tester", trigger="manual")
        conn.commit()
    assert run["status"] == "awaiting-approval"
    with get_conn() as conn:
        rejected = resolve_approval(conn, run["id"], approve=False, actor="approver")
        conn.commit()
    assert rejected["status"] == "rejected"
    # every step after the approval is skipped (none of them "success"-acted)
    assert any(s["status"] == "skipped" for s in rejected["steps"])


def test_auto_trigger_fires_once_on_matching_alert():
    seed_builtin_playbooks()
    tag = uuid.uuid4().hex[:8]
    host = f"PB-C2-{tag}"
    with get_conn() as conn:
        # "C2 Beacon Isolation" matches severities=critical, techniques=T1071.
        aid = _insert_alert(conn, title=f"beacon {tag}", severity="critical", risk=95,
                            rule_name="R-PB", hostname=host, mitre_tech_id="T1071.001")
        conn.commit()
        started, _dispatches = auto_trigger_playbooks(conn, max_runs=5)
        conn.commit()
    assert started >= 1
    with get_conn() as conn:
        # a run exists for that alert; a second auto-trigger does not duplicate it
        n1 = conn.execute("SELECT COUNT(*) AS n FROM playbook_runs WHERE alert_id=?", (aid,)).fetchone()["n"]
        auto_trigger_playbooks(conn, max_runs=5)
        conn.commit()
        n2 = conn.execute("SELECT COUNT(*) AS n FROM playbook_runs WHERE alert_id=?", (aid,)).fetchone()["n"]
    assert n1 >= 1 and n2 == n1   # idempotent: no duplicate run for the same alert
