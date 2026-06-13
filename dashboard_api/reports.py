"""Structured report generator (Nessus/Acunetix-style).

Each report is a structured document - cover metadata, an executive summary
with headline metrics and a narrative, severity breakdowns, detailed findings,
and recommendations - built over a time window (daily / weekly / custom). The
frontend renders this into a clean, paginated, print-to-PDF layout; nothing
here is a raw CSV dump.

Report kinds: executive, siem, soar, cti, assets, darkweb.
"""
from datetime import datetime, timedelta, timezone

from dashboard_api.db import get_conn

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {"critical": "#FF2E97", "high": "#FF4D6D", "medium": "#FFB23E",
              "low": "#34F5C5", "info": "#7A3CFF"}


def _window(period: str, frm: str | None, to: str | None) -> tuple[str, str, str]:
    """Return (since_iso, until_iso, label) for the report window."""
    now = datetime.now(timezone.utc)
    if period == "custom" and frm:
        since = frm
        until = to or now.replace(microsecond=0).isoformat()
        return since, until, f"{frm[:10]} → {until[:10]}"
    days = {"daily": 1, "weekly": 7, "monthly": 30}.get(period, 7)
    since_dt = now - timedelta(days=days)
    label = {"daily": "Last 24 hours", "weekly": "Last 7 days",
             "monthly": "Last 30 days"}.get(period, "Last 7 days")
    return since_dt.replace(microsecond=0).isoformat(), now.replace(microsecond=0).isoformat(), label


def _sev_breakdown(rows, key="severity") -> list[dict]:
    counts = {s: 0 for s in _SEV_ORDER}
    for r in rows:
        s = (r[key] if isinstance(r, dict) else r[key])
        if s in counts:
            counts[s] += 1
    return [{"severity": s, "count": counts[s], "color": _SEV_COLOR[s]}
            for s in _SEV_ORDER if counts[s] or s in ("critical", "high", "medium", "low")]


def _meta(kind: str, title: str, label: str, since: str, until: str) -> dict:
    return {
        "kind": kind, "title": title, "period": label,
        "from": since, "to": until,
        "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


# ── Per-kind builders ───────────────────────────────────────────────────────────

def _siem_report(conn, since, until, label) -> dict:
    rows = conn.execute(
        "SELECT * FROM alerts WHERE ts >= ? AND ts <= ? ORDER BY risk_score DESC",
        (since, until),
    ).fetchall()
    alerts = [dict(r) for r in rows]
    total = len(alerts)
    crit = sum(1 for a in alerts if a["severity"] == "critical")
    high = sum(1 for a in alerts if a["severity"] == "high")
    open_ = sum(1 for a in alerts if a["status"] not in ("resolved", "closed"))
    # top techniques
    tech: dict[str, int] = {}
    for a in alerts:
        t = a.get("mitre_tech") or a.get("mitre_tech_id")
        if t:
            tech[t] = tech.get(t, 0) + 1
    top_tech = sorted(tech.items(), key=lambda x: -x[1])[:8]
    findings = [{
        "title": a["title"], "severity": a["severity"], "score": a["risk_score"],
        "ts": a["ts"], "entity": a.get("src_ip") or a.get("hostname") or a.get("username") or "-",
        "technique": a.get("mitre_tech_id"), "tactic": a.get("mitre_tactic"),
        "rule": a.get("rule_name"), "status": a["status"],
        "detail": a.get("description") or "",
    } for a in alerts[:50]]
    return {
        "meta": _meta("siem", "SIEM Detection Report", label, since, until),
        "summary": {
            "headline": [
                {"label": "Total alerts", "value": total},
                {"label": "Critical", "value": crit, "color": _SEV_COLOR["critical"]},
                {"label": "High", "value": high, "color": _SEV_COLOR["high"]},
                {"label": "Still open", "value": open_},
            ],
            "narrative": (
                f"During {label.lower()}, the platform raised {total} alerts "
                f"({crit} critical, {high} high). {open_} remain open. "
                + (f"The most observed technique was {top_tech[0][0]} ({top_tech[0][1]} alerts). "
                   if top_tech else "")
                + ("Immediate triage of the critical alerts below is recommended."
                   if crit else "No critical alerts in this window.")
            ),
        },
        "breakdowns": [
            {"heading": "Alerts by severity", "type": "severity", "data": _sev_breakdown(alerts)},
            {"heading": "Top MITRE ATT&CK techniques", "type": "bars",
             "data": [{"label": k, "count": v} for k, v in top_tech]},
        ],
        "findings": findings,
        "recommendations": [
            "Triage and disposition all critical alerts within SLA.",
            "Review the top techniques against your detection coverage for gaps.",
            "Escalate correlated critical alerts to SOAR cases for tracked response.",
        ],
    }


def _soar_report(conn, since, until, label) -> dict:
    rows = conn.execute("SELECT * FROM cases WHERE created >= ? AND created <= ?",
                        (since, until)).fetchall()
    cases = [dict(r) for r in rows]
    total = len(cases)
    closed = sum(1 for c in cases if c["status"] in ("resolved", "closed"))
    open_ = total - closed
    crit = sum(1 for c in cases if c["severity"] == "critical")
    findings = [{
        "title": c["title"], "severity": c["severity"], "status": c["status"],
        "ts": c["created"], "entity": c.get("type") or "-", "owner": c.get("owner") or "Unassigned",
        "detail": c.get("description") or "", "score": c.get("alert_count") or 0,
        "rule": f"{c.get('alert_count', 0)} alerts",
    } for c in cases[:50]]
    return {
        "meta": _meta("soar", "SOAR Incident Response Report", label, since, until),
        "summary": {
            "headline": [
                {"label": "Cases opened", "value": total},
                {"label": "Critical", "value": crit, "color": _SEV_COLOR["critical"]},
                {"label": "Closed", "value": closed, "color": _SEV_COLOR["low"]},
                {"label": "Still open", "value": open_},
            ],
            "narrative": (
                f"{total} incident cases were opened during {label.lower()} "
                f"({crit} critical). {closed} have been resolved; {open_} remain in progress. "
                + ("Auto-escalation from correlated alerts is functioning."
                   if any(c.get("owner") == "" for c in cases) else "")
            ),
        },
        "breakdowns": [
            {"heading": "Cases by severity", "type": "severity", "data": _sev_breakdown(cases)},
            {"heading": "Cases by status", "type": "bars",
             "data": [{"label": s, "count": sum(1 for c in cases if c["status"] == s)}
                      for s in ("new", "assigned", "in-progress", "pending", "resolved", "closed")
                      if any(c["status"] == s for c in cases)]},
        ],
        "findings": findings,
        "recommendations": [
            "Close or progress all open critical cases within SLA.",
            "Attach playbooks to recurring case types to raise the automation rate.",
            "Document lessons learned for resolved critical incidents.",
        ],
    }


def _cti_report(conn, since, until, label) -> dict:
    iocs = [dict(r) for r in conn.execute(
        "SELECT * FROM iocs WHERE last_seen >= ? AND last_seen <= ? ORDER BY confidence DESC",
        (since, until)).fetchall()]
    actors = [dict(r) for r in conn.execute("SELECT name, type, threat_level, ioc_count FROM threat_actors").fetchall()]
    total = len(iocs)
    by_type: dict[str, int] = {}
    for i in iocs:
        by_type[i["type"]] = by_type.get(i["type"], 0) + 1
    findings = [{
        "title": f"{i['type'].upper()} · {i['value']}", "severity": i.get("severity") or "medium",
        "score": i.get("confidence") or 0, "ts": i.get("last_seen"),
        "entity": i.get("actor") or "-", "rule": i.get("source"),
        "detail": i.get("threat_type") or "", "status": "active",
    } for i in iocs[:50]]
    return {
        "meta": _meta("cti", "Threat Intelligence Report", label, since, until),
        "summary": {
            "headline": [
                {"label": "Indicators", "value": total},
                {"label": "Tracked actors", "value": len(actors)},
                {"label": "High-confidence", "value": sum(1 for i in iocs if (i.get("confidence") or 0) >= 80)},
                {"label": "Sources", "value": len({i.get("source") for i in iocs})},
            ],
            "narrative": (
                f"{total} indicators were observed or updated during {label.lower()}, "
                f"across {len(by_type)} indicator types and "
                f"{len({i.get('source') for i in iocs})} sources. "
                + (f"The largest category was {max(by_type, key=by_type.get)} "
                   f"({max(by_type.values())} indicators)." if by_type else "")
            ),
        },
        "breakdowns": [
            {"heading": "Indicators by type", "type": "bars",
             "data": [{"label": k, "count": v} for k, v in sorted(by_type.items(), key=lambda x: -x[1])]},
            {"heading": "Indicators by severity", "type": "severity", "data": _sev_breakdown(iocs)},
        ],
        "findings": findings,
        "recommendations": [
            "Push high-confidence indicators to detection and blocking controls.",
            "Review indicators attributed to active actors targeting your sectors.",
            "Expire or down-weight stale low-confidence indicators.",
        ],
    }


def _assets_report(conn, since, until, label) -> dict:
    assets = [dict(r) for r in conn.execute(
        "SELECT * FROM assets ORDER BY risk_score DESC").fetchall()]
    import json as _json
    total = len(assets)
    at_risk = sum(1 for a in assets if a["status"] in ("at-risk", "critical"))
    cve_tot = 0
    for a in assets:
        c = a["cves"] if isinstance(a["cves"], dict) else _json.loads(a["cves"] or "{}")
        cve_tot += sum(c.values())
    avg = round(sum(a["risk_score"] for a in assets) / total, 1) if total else 0
    findings = [{
        "title": f"{a['name']} ({a['value']})", "severity": a["criticality"],
        "score": a["risk_score"], "ts": a.get("last_scan"), "entity": a["type"],
        "rule": a.get("owner") or "-", "status": a["status"],
        "detail": f"Risk {a['risk_score']}/100 · {a.get('alerts', 0)} open alerts",
    } for a in assets[:50]]
    return {
        "meta": _meta("assets", "Asset Risk & Exposure Report", label, since, until),
        "summary": {
            "headline": [
                {"label": "Assets", "value": total},
                {"label": "At risk", "value": at_risk, "color": _SEV_COLOR["high"]},
                {"label": "Open CVEs", "value": cve_tot},
                {"label": "Avg risk", "value": avg},
            ],
            "narrative": (
                f"The inventory holds {total} assets with a mean risk of {avg}/100. "
                f"{at_risk} are at-risk or critical, carrying {cve_tot} open CVEs. "
                "Prioritise patching and exposure reduction on the highest-risk assets below."
            ),
        },
        "breakdowns": [
            {"heading": "Assets by criticality", "type": "severity",
             "data": _sev_breakdown(assets, key="criticality")},
        ],
        "findings": findings,
        "recommendations": [
            "Patch the critical-risk, internet-facing assets first.",
            "Reduce exposed services on high-risk hosts.",
            "Re-run risk recompute after remediation to confirm score reduction.",
        ],
    }


def _darkweb_report(conn, since, until, label) -> dict:
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM dark_web_findings WHERE ts >= ? AND ts <= ? ORDER BY ts DESC",
        (since, until)).fetchall()]
    total = len(rows)
    creds = sum(1 for r in rows if r["category"] == "credential-leak")
    crit = sum(1 for r in rows if r["severity"] == "critical")
    by_cat: dict[str, int] = {}
    for r in rows:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    findings = [{
        "title": r["title"], "severity": r["severity"], "ts": r["ts"],
        "entity": r.get("entity") or "-", "rule": r.get("source"),
        "status": r["status"], "detail": r.get("detail") or "", "score": 0,
    } for r in rows[:50]]
    return {
        "meta": _meta("darkweb", "Dark Web Exposure Report", label, since, until),
        "summary": {
            "headline": [
                {"label": "Findings", "value": total},
                {"label": "Credential leaks", "value": creds, "color": _SEV_COLOR["critical"]},
                {"label": "Critical", "value": crit, "color": _SEV_COLOR["critical"]},
                {"label": "Categories", "value": len(by_cat)},
            ],
            "narrative": (
                f"{total} dark-web findings affected the organisation during {label.lower()}, "
                f"including {creds} credential leaks. "
                + ("Force password resets for leaked accounts immediately."
                   if creds else "No credential leaks in this window.")
            ),
        },
        "breakdowns": [
            {"heading": "Findings by category", "type": "bars",
             "data": [{"label": k, "count": v} for k, v in sorted(by_cat.items(), key=lambda x: -x[1])]},
            {"heading": "Findings by severity", "type": "severity", "data": _sev_breakdown(rows)},
        ],
        "findings": findings,
        "recommendations": [
            "Reset and rotate credentials for every leaked account.",
            "Open takedown requests for data-for-sale and brand-abuse listings.",
            "Brief leadership on actor chatter targeting the organisation.",
        ],
    }


def _executive_report(conn, since, until, label) -> dict:
    siem = _siem_report(conn, since, until, label)
    soar = _soar_report(conn, since, until, label)
    cti = _cti_report(conn, since, until, label)
    assets = _assets_report(conn, since, until, label)
    dw = _darkweb_report(conn, since, until, label)

    def hv(rep, i):
        return rep["summary"]["headline"][i]["value"]

    return {
        "meta": _meta("executive", "Executive Security Summary", label, since, until),
        "summary": {
            "headline": [
                {"label": "Alerts", "value": hv(siem, 0), "color": _SEV_COLOR["high"]},
                {"label": "Open cases", "value": hv(soar, 3)},
                {"label": "New indicators", "value": hv(cti, 0)},
                {"label": "Dark-web findings", "value": hv(dw, 0), "color": _SEV_COLOR["critical"]},
            ],
            "narrative": (
                f"Executive summary for {label.lower()}. Detection raised {hv(siem,0)} alerts "
                f"({hv(siem,1)} critical); {hv(soar,0)} incident cases were opened. "
                f"Threat intelligence tracked {hv(cti,0)} indicators. Asset risk averages "
                f"{hv(assets,3)}/100 with {hv(assets,1)} assets at risk. Dark-web monitoring "
                f"surfaced {hv(dw,0)} findings including {hv(dw,1)} credential leaks. "
                "Section detail and recommendations follow."
            ),
        },
        "breakdowns": [
            {"heading": "Alerts by severity", "type": "severity", "data": siem["breakdowns"][0]["data"]},
        ],
        # Executive report stitches each section's top findings together.
        "findings": (siem["findings"][:8] + soar["findings"][:5] + dw["findings"][:5]),
        "recommendations": list(dict.fromkeys(
            siem["recommendations"][:1] + soar["recommendations"][:1]
            + cti["recommendations"][:1] + assets["recommendations"][:1]
            + dw["recommendations"][:1])),
        "sections": [siem["meta"]["title"], soar["meta"]["title"], cti["meta"]["title"],
                     assets["meta"]["title"], dw["meta"]["title"]],
    }


_BUILDERS = {
    "executive": _executive_report, "siem": _siem_report, "soar": _soar_report,
    "cti": _cti_report, "assets": _assets_report, "darkweb": _darkweb_report,
}

REPORT_KINDS = list(_BUILDERS)


def build_report(kind: str, period: str = "weekly",
                 frm: str | None = None, to: str | None = None) -> dict:
    if kind not in _BUILDERS:
        raise ValueError(f"unknown report kind: {kind}")
    since, until, label = _window(period, frm, to)
    with get_conn() as conn:
        return _BUILDERS[kind](conn, since, until, label)


def build_incident_report(case_id: str) -> dict:
    """Post-incident report for one case: what happened (MITRE-mapped
    timeline), how the response went (actions, SLA verdict), and a
    lessons-learned scaffold. Raises ValueError when the case is unknown."""
    from dashboard_api.routers.soar import _sla, case_related
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise ValueError(f"unknown case: {case_id}")
        from dashboard_api.db import row_to_dict
        case = row_to_dict(row)
    related = case_related(case_id)
    sla = _sla(case)
    alerts = related["alerts"]
    runs = related["runs"]
    closed = case["status"] in ("resolved", "closed")
    sla_verdict = {"met": "SLA met", "breached": "SLA BREACHED",
                   "within": "within SLA", "at-risk": "SLA at risk"}.get(sla["slaStatus"], "-")

    findings = []
    for t in related["timeline"]:
        findings.append({
            "title": t["title"] or "-",
            "severity": t["severity"] or ("info" if t["type"] in ("system", "note", "manual") else "low"),
            "score": 0, "ts": t["ts"],
            "entity": None, "technique": t.get("technique"), "tactic": None,
            "rule": t.get("actor"), "status": t["type"], "detail": "",
        })

    auto_runs = sum(1 for r in runs if r.get("trigger") == "auto")
    recs = [
        "Hold a post-incident review with all responders within 5 business days.",
        "Verify containment actions held: blocked indicators stayed blocked, isolated hosts were rebuilt before reconnecting.",
    ]
    if related["techniques"]:
        top = related["techniques"][0]["technique"]
        recs.append(f"Review detection coverage for {top} - the dominant technique in this incident - and backtest tuned rules.")
    if not case.get("playbook"):
        recs.append("No playbook drove this case: author an automation trigger so the next occurrence is contained automatically.")
    if sla["slaStatus"] == "breached":
        recs.append("The response breached its SLA - review escalation routing and on-call staffing for this alert class.")
    recs.append("Capture lessons learned in the runbook: what detected it, what slowed response, what to automate next.")

    return {
        "meta": _meta("incident", f"Post-Incident Report - {case['id']}",
                      f"{case['title']}", case["created"], case.get("updated") or case["created"]),
        "summary": {
            "headline": [
                {"label": "Severity", "value": case["severity"],
                 "color": _SEV_COLOR.get(case["severity"], "#fff")},
                {"label": "Linked alerts", "value": len(alerts)},
                {"label": "Response actions", "value": len(runs)},
                {"label": "SLA", "value": sla_verdict,
                 "color": "#FF4D6D" if sla["slaStatus"] == "breached" else "#34F5C5"},
            ],
            "narrative": (
                f"Case {case['id']} (“{case['title']}”, {case['severity']}) was opened "
                f"{case['created'][:16].replace('T', ' ')} and is "
                f"{'closed' if closed else 'still open'} ({case['status']}). "
                f"{len(alerts)} alerts and {len(related['iocs'])} indicators are linked to its entities; "
                f"{len(runs)} playbook run(s) responded ({auto_runs} automatic). "
                + (f"Driven by the “{case['playbook']}” playbook. " if case.get("playbook") else "")
                + f"The response is currently {sla_verdict} "
                  f"({sla['slaElapsedPct']}% of the {case.get('sla_hours', 24)}h SLA elapsed)."
            ),
        },
        "breakdowns": [
            {"heading": "Linked alerts by severity", "type": "severity", "data": _sev_breakdown(alerts)},
            {"heading": "MITRE ATT&CK techniques observed", "type": "bars",
             "data": [{"label": t["technique"], "count": t["count"]} for t in related["techniques"][:8]]},
        ],
        "findings": findings,
        "recommendations": recs,
    }
