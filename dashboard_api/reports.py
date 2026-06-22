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
    """Asset risk + a real, prioritised vulnerability picture.

    Rather than dumping asset rows, this synthesises the open scanner findings
    (`vuln_findings`) into something a reader can act on: severity breakdown,
    how many CVEs are actively exploited (CISA KEV) and on how many assets, the
    most-affected hosts, and a CVE list ordered by real-world exploitability
    (KEV first, then public exploit, then CVSS, then blast radius)."""
    assets = [dict(r) for r in conn.execute(
        "SELECT * FROM assets ORDER BY risk_score DESC").fetchall()]
    total = len(assets)
    at_risk = sum(1 for a in assets if a["status"] in ("at-risk", "critical"))
    avg = round(sum(a["risk_score"] for a in assets) / total, 1) if total else 0
    avg_patch = round((conn.execute("SELECT AVG(patch_age) AS a FROM assets").fetchone()["a"]) or 0)

    vrows = [dict(r) for r in conn.execute(
        "SELECT v.cve, v.product, v.version, v.severity, v.cvss, v.fixed_in, v.kev, v.exploit, "
        "a.name AS asset_name FROM vuln_findings v LEFT JOIN assets a ON a.id = v.asset_id "
        "WHERE v.status='open'").fetchall()]
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vrows:
        if v["severity"] in by_sev:
            by_sev[v["severity"]] += 1

    cves: dict[str, dict] = {}
    for v in vrows:
        g = cves.setdefault(v["cve"], {
            "cve": v["cve"], "cvss": v["cvss"] or 0, "severity": v["severity"] or "medium",
            "kev": False, "exploit": False, "fixed_in": v["fixed_in"], "assets": set(), "products": set(),
        })
        g["kev"] = g["kev"] or bool(v["kev"])
        g["exploit"] = g["exploit"] or bool(v["exploit"])
        g["cvss"] = max(g["cvss"], v["cvss"] or 0)
        if v["asset_name"]:
            g["assets"].add(v["asset_name"])
        if v["product"]:
            g["products"].add(f"{v['product']} {v['version'] or ''}".strip())
    distinct = len(cves)
    kev_cves = sum(1 for g in cves.values() if g["kev"])
    exploit_cves = sum(1 for g in cves.values() if g["exploit"])
    kev_assets = len({a for g in cves.values() if g["kev"] for a in g["assets"]})

    ranked = sorted(cves.values(),
                    key=lambda g: (g["kev"], g["exploit"], g["cvss"], len(g["assets"])), reverse=True)
    findings = []
    for g in ranked[:40]:
        flags = [f for f, on in (("CISA KEV", g["kev"]), ("public exploit", g["exploit"])) if on]
        n = len(g["assets"])
        detail = (
            f"CVSS {g['cvss']}"
            + (f" · {' · '.join(flags)}" if flags else "")
            + f" · {n} asset{'s' if n != 1 else ''} affected"
            + (f" · fix: {g['fixed_in']}" if g["fixed_in"] else " · no vendor fix listed")
            + (f" · {', '.join(sorted(g['products'])[:2])}" if g["products"] else "")
        )
        entity = (sorted(g["assets"])[0] + (f" +{n - 1} more" if n > 1 else "")) if g["assets"] else "-"
        findings.append({
            "title": g["cve"], "severity": g["severity"], "score": g["cvss"], "ts": None,
            "entity": entity, "rule": ("CISA KEV" if g["kev"] else "exploit available" if g["exploit"] else None),
            "status": "open", "detail": detail,
        })

    asset_cve_count: dict[str, int] = {}
    for g in cves.values():
        for a in g["assets"]:
            asset_cve_count[a] = asset_cve_count.get(a, 0) + 1
    top_assets = sorted(asset_cve_count.items(), key=lambda x: -x[1])[:8]

    narrative = (
        f"The inventory holds {total} assets (mean risk {avg}/100; {at_risk} at-risk or critical). "
        f"Scanners report {len(vrows)} open findings spanning {distinct} distinct CVEs "
        f"({by_sev['critical']} critical, {by_sev['high']} high). "
        + (f"{kev_cves} are actively exploited in the wild (CISA KEV) across {kev_assets} "
           f"asset{'s' if kev_assets != 1 else ''} and must be patched first; "
           f"{exploit_cves} have a public exploit. " if kev_cves or exploit_cves
           else "None are currently CISA-KEV-listed. ")
        + f"Average patch age is {avg_patch} days. The CVE list below is ordered by real-world "
          "exploitability (KEV, then public exploit, then CVSS and blast radius)."
    )
    return {
        "meta": _meta("assets", "Asset Risk & Vulnerability Report", label, since, until),
        "summary": {
            "headline": [
                {"label": "Assets", "value": total},
                {"label": "Distinct CVEs", "value": distinct, "color": _SEV_COLOR["high"]},
                {"label": "Actively exploited", "value": kev_cves, "color": _SEV_COLOR["critical"]},
                {"label": "Avg patch age", "value": f"{avg_patch}d"},
            ],
            "narrative": narrative,
        },
        "breakdowns": [
            {"heading": "Open CVEs by severity", "type": "severity",
             "data": [{"severity": s, "count": by_sev[s], "color": _SEV_COLOR[s]}
                      for s in ("critical", "high", "medium", "low")]},
            {"heading": "Assets by criticality", "type": "severity",
             "data": _sev_breakdown(assets, key="criticality")},
        ] + ([{"heading": "Most-affected assets (open CVEs)", "type": "bars",
               "data": [{"label": a, "count": c} for a, c in top_assets]}] if top_assets else []),
        "findings": findings,
        "recommendations": [
            (f"Patch the {kev_cves} actively-exploited (CISA KEV) CVE(s) first - they are being used in "
             "real-world attacks right now." if kev_cves
             else "Keep watching the CISA KEV catalogue; none of your open CVEs are actively exploited today."),
            "Remediate critical/high CVEs on internet-facing assets next, and retire or segment exposed services.",
            f"Bring the average patch age ({avg_patch} days) down - start with the most-affected assets above.",
            "Re-run the scanner and risk recompute after patching to confirm findings close and risk scores drop.",
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
    """The consolidated, platform-wide "overall" report: one read across SIEM,
    SOAR, CTI, asset/vulnerability and dark-web posture, with the cross-domain
    priorities stitched into a single narrative, findings list and action set."""
    siem = _siem_report(conn, since, until, label)
    soar = _soar_report(conn, since, until, label)
    cti = _cti_report(conn, since, until, label)
    assets = _assets_report(conn, since, until, label)
    dw = _darkweb_report(conn, since, until, label)

    def hv(rep, want, default=0):
        for h in rep["summary"]["headline"]:
            if h["label"] == want:
                return h["value"]
        return default

    alerts = hv(siem, "Total alerts")
    crit_alerts = hv(siem, "Critical")
    open_cases = hv(soar, "Still open")
    crit_cases = hv(soar, "Critical")
    indicators = hv(cti, "Indicators")
    distinct_cves = hv(assets, "Distinct CVEs")
    kev_cves = hv(assets, "Actively exploited")
    dw_findings = hv(dw, "Findings")
    cred_leaks = hv(dw, "Credential leaks")
    avg_risk = round((conn.execute("SELECT AVG(risk_score) AS a FROM assets").fetchone()["a"]) or 0, 1)

    narrative = (
        f"Overall security posture for {label.lower()}. Detection raised {alerts} alerts "
        f"({crit_alerts} critical); {open_cases} incident case(s) are still open ({crit_cases} critical). "
        f"Threat intelligence tracked {indicators} indicators. The fleet carries {distinct_cves} distinct "
        f"open CVEs"
        + (f", of which {kev_cves} are actively exploited in the wild (CISA KEV) and should be patched first"
           if kev_cves else " with none currently CISA-KEV-listed")
        + f"; mean asset risk is {avg_risk}/100. Dark-web monitoring surfaced {dw_findings} finding(s)"
        + (f" including {cred_leaks} credential leak(s) - rotate those accounts now. "
           if cred_leaks else ". ")
        + "The prioritised findings and actions below combine the most urgent items from every domain."
    )

    # Highest-signal cross-domain findings: top alerts, the exploitable CVEs,
    # open critical cases, and the worst dark-web exposure.
    findings = siem["findings"][:5] + assets["findings"][:4] + soar["findings"][:3] + dw["findings"][:3]

    breakdowns = [{"heading": "Alerts by severity", "type": "severity", "data": siem["breakdowns"][0]["data"]},
                  {"heading": "Open CVEs by severity", "type": "severity", "data": assets["breakdowns"][0]["data"]}]
    if dw["breakdowns"] and dw["breakdowns"][0]["data"]:
        breakdowns.append({"heading": "Dark-web exposure by category", "type": "bars",
                           "data": dw["breakdowns"][0]["data"]})

    # Consolidated, de-duplicated priority actions (most urgent first).
    recommendations = list(dict.fromkeys(
        ([assets["recommendations"][0]] if kev_cves else [])      # patch KEV first
        + ([dw["recommendations"][0]] if cred_leaks else [])      # reset leaked creds
        + siem["recommendations"][:1]                              # triage criticals
        + soar["recommendations"][:1]                              # progress open cases
        + cti["recommendations"][:1]                               # push high-confidence intel
        + assets["recommendations"][1:2]                           # internet-facing remediation
    ))

    return {
        "meta": _meta("executive", "Overall Security Report", label, since, until),
        "summary": {
            "headline": [
                {"label": "Critical alerts", "value": crit_alerts, "color": _SEV_COLOR["critical"]},
                {"label": "Open cases", "value": open_cases, "color": _SEV_COLOR["high"]},
                {"label": "Exploited CVEs", "value": kev_cves, "color": _SEV_COLOR["critical"]},
                {"label": "Credential leaks", "value": cred_leaks, "color": _SEV_COLOR["critical"]},
            ],
            "narrative": narrative,
        },
        "breakdowns": breakdowns,
        "findings": findings,
        "recommendations": recommendations,
        "sections": [siem["meta"]["title"], soar["meta"]["title"], cti["meta"]["title"],
                     assets["meta"]["title"], dw["meta"]["title"]],
    }


_BUILDERS = {
    "executive": _executive_report, "siem": _siem_report, "soar": _soar_report,
    "cti": _cti_report, "assets": _assets_report, "darkweb": _darkweb_report,
}

REPORT_KINDS = list(_BUILDERS)


AUDIENCES = ["technical", "executive", "compliance"]

# Control families each domain's findings evidence, for the compliance audience.
_COMPLIANCE_CONTROLS = {
    "siem": [{"control": "Security event logging & monitoring", "framework": "ISO 27001 A.8.15-8.16 · SOC 2 CC7.2"}],
    "soar": [{"control": "Incident response & management", "framework": "ISO 27001 A.5.24-5.26 · SOC 2 CC7.3-CC7.4"}],
    "cti":  [{"control": "Threat intelligence", "framework": "ISO 27001 A.5.7"}],
    "assets": [{"control": "Vulnerability & asset management", "framework": "ISO 27001 A.8.8-8.9 · SOC 2 CC7.1"}],
    "darkweb": [{"control": "Information exposure monitoring", "framework": "ISO 27001 A.5.7 · SOC 2 CC7.2"}],
}
_COMPLIANCE_CONTROLS["executive"] = [c for cs in
    ("siem", "soar", "cti", "assets", "darkweb") for c in _COMPLIANCE_CONTROLS[cs]]


def apply_audience(report: dict, audience: str = "technical") -> dict:
    """Reshape a built report for its reader. Technical = full depth (default);
    Executive = compact (top findings, severity breakdowns, exec framing);
    Compliance = evidence framing + a control-mapping section."""
    audience = (audience or "technical").lower()
    if audience not in AUDIENCES:
        audience = "technical"
    out = {**report, "meta": {**report.get("meta", {}), "audience": audience}}
    if audience == "executive":
        out["findings"] = (report.get("findings") or [])[:8]
        out["breakdowns"] = [b for b in (report.get("breakdowns") or []) if b.get("type") == "severity"][:2]
        nar = report.get("summary", {}).get("narrative", "")
        out["summary"] = {**report.get("summary", {}), "narrative": "Executive summary — " + nar}
    elif audience == "compliance":
        kind = report.get("meta", {}).get("kind", "")
        out["compliance"] = _COMPLIANCE_CONTROLS.get(kind, _COMPLIANCE_CONTROLS["executive"])
        nar = report.get("summary", {}).get("narrative", "")
        out["summary"] = {**report.get("summary", {}),
                          "narrative": nar + " Prepared for compliance review; the findings below evidence "
                                             "the effectiveness of the mapped controls."}
    return out


def build_report(kind: str, period: str = "weekly",
                 frm: str | None = None, to: str | None = None,
                 audience: str = "technical") -> dict:
    if kind not in _BUILDERS:
        raise ValueError(f"unknown report kind: {kind}")
    since, until, label = _window(period, frm, to)
    with get_conn() as conn:
        report = _BUILDERS[kind](conn, since, until, label)
    return apply_audience(report, audience)


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
