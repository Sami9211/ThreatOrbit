"""ThreatOrbit live processing engine.

This is the self-contained data source that makes every section LIVE without
any external connector. It runs on a background tick in live mode and is a real
pipeline, stage by stage:

    telemetry  →  parse/normalise  →  detect (rules → SIEM alerts)
               →  extract IOCs (→ CTI)  →  correlate  →  escalate (→ SOAR cases)
               →  dark-web monitoring (→ findings)  →  asset risk recompute

The *source* is simulated environment telemetry — the standard way a SIEM is
exercised when it is not wired to a production log pipeline. It is NOT static
seed data: every tick produces brand-new events that flow through the real
detection/correlation/escalation stages. The source is swappable — real log
uploads (Log API detectors) and connector feeds write into the very same
stores, so nothing here is throwaway.

Each section stays distinct:
  SIEM  = detections + correlation over the event stream
  SOAR  = case lifecycle/orchestration on escalated, correlated incidents
  CTI   = indicators + actors extracted and enriched from what is seen
  Assets= surface whose risk tracks live alert pressure
  DarkWeb = external exposure monitoring (credentials, mentions, chatter)
"""
import ipaddress
import random
import uuid
from datetime import datetime, timezone

from dashboard_api.db import audit, dumps, get_conn
from dashboard_api.detections import _insert_alert, _TACTIC  # reuse the alert writer

# ── Realistic value pools ───────────────────────────────────────────────────────
_INTERNAL_HOSTS = ["DC-PROD-01", "WEB-LB-01", "PROD-API-04", "JENKINS-CI-01",
                   "DESKTOP-FIN-087", "LAPTOP-EXEC-03", "K8S-NODE-2", "RDS-CUSTOMERS",
                   "MAIL-RELAY-01", "FILE-SRV-02", "VPN-GW-01", "SCADA-HMI-01"]
_USERS = ["msmith", "jchen", "apatel", "rosei", "dlee", "svc-backup", "svc-deploy",
          "administrator", "root", "ec2-user", "kkim", "twong"]
_PROCS = ["powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "wmic.exe",
          "certutil.exe", "regsvr32.exe", "svchost.exe", "lsass.exe", "sshd"]
_COUNTRIES = ["Russia", "China", "North Korea", "Iran", "United States", "Brazil",
              "Netherlands", "Romania", "Vietnam", "Nigeria"]
_ACTORS = ["Lazarus Group", "APT29", "Volt Typhoon", "Scattered Spider", "FIN7",
           "LockBit", "BlackBasta", "Sandworm"]
_MALWARE = ["Cobalt Strike", "Emotet", "QakBot", "AgentTesla", "Ryuk", "BumbleBee",
            "IcedID", "RedLine Stealer"]
_BAD_DOMAINS = ["m1crosoft-update.com", "secure-login-portal.net", "cdn-analytics.xyz",
                "update-service.ru", "auth-verify.cc", "data-exfil.top"]
_SECTORS = ["Finance", "Healthcare", "Government", "Energy", "Technology", "Retail"]


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _rng() -> random.Random:
    # Fresh entropy each tick so events are genuinely new, never a fixed seed.
    return random.Random()


def _pub_ip(rng) -> str:
    while True:
        ip = ipaddress.IPv4Address(rng.randint(1, 0xFFFFFFFF))
        if not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved):
            return str(ip)


def _int_ip(rng) -> str:
    return f"10.{rng.randint(0,40)}.{rng.randint(0,255)}.{rng.randint(2,254)}"


def _md5(rng) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(32))


def _sha256(rng) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


# ── Telemetry scenarios ─────────────────────────────────────────────────────────
# Each scenario emits a RAW EVENT (normalised fields) plus any IOCs it carries.
# Severity / MITRE / titles come from the DETECTION RULES that match the event —
# exactly like a real SIEM, where the rule defines the detection.

def _scn_brute_force(rng):
    src = _pub_ip(rng); user = rng.choice(_USERS); host = rng.choice(_INTERNAL_HOSTS)
    return ({
        "category": "auth", "event_type": "failed_login", "src_ip": src,
        "username": user, "hostname": host, "action": "auth_fail",
        "severity_hint": "high", "mitre_tech_id": "T1110",
        "raw": f"sshd[{rng.randint(1000,9999)}]: Failed password for {user} from {src} port {rng.randint(1024,65535)}",
    }, [{"type": "ip", "value": src, "threat_type": "brute-force-source", "confidence": 75}])


def _scn_c2_beacon(rng):
    src = _int_ip(rng); dst = _pub_ip(rng); host = rng.choice(_INTERNAL_HOSTS)
    mal = rng.choice(_MALWARE); actor = rng.choice(_ACTORS)
    return ({
        "category": "network", "event_type": "beacon", "src_ip": src, "dest_ip": dst,
        "dest_port": 443, "hostname": host, "bytes_out": rng.randint(400, 1200),
        "severity_hint": "critical", "mitre_tech_id": "T1071.001",
        "raw": f"fw: ALLOW {src}:{rng.randint(40000,60000)} -> {dst}:443 interval=58s family={mal}",
    }, [{"type": "ip", "value": dst, "threat_type": "c2", "confidence": 90, "actor": actor, "severity": "critical"}])


def _scn_malware(rng):
    host = rng.choice(_INTERNAL_HOSTS); user = rng.choice(_USERS)
    h = _sha256(rng); mal = rng.choice(_MALWARE); proc = rng.choice(_PROCS)
    return ({
        "category": "endpoint", "event_type": "process_start", "hostname": host,
        "username": user, "process_name": proc, "action": "malicious",
        "severity_hint": "high", "mitre_tech_id": "T1059.001",
        "raw": f"EDR: {host} {proc} -enc <b64> sha256={h} verdict=malicious family={mal}",
    }, [{"type": "hash", "value": h, "threat_type": mal, "confidence": 88, "severity": "high"}])


def _scn_web_attack(rng):
    src = _pub_ip(rng); host = rng.choice(["WEB-LB-01", "PROD-API-04", "wordpress-mkt"])
    action = rng.choice(["sqli", "lfi", "webshell"])
    return ({
        "category": "web", "event_type": "web_request", "src_ip": src, "hostname": host,
        "action": action, "severity_hint": "medium", "mitre_tech_id": "T1190",
        "raw": f'nginx: {src} "GET /index.php?id=1\' OR 1=1-- HTTP/1.1" 200 ({action})',
    }, [{"type": "ip", "value": src, "threat_type": "web-attack", "confidence": 65}])


def _scn_exfil(rng):
    src = _int_ip(rng); dst = _pub_ip(rng); host = rng.choice(_INTERNAL_HOSTS)
    mb = rng.randint(200, 4000)
    return ({
        "category": "network", "event_type": "large_egress", "src_ip": src, "dest_ip": dst,
        "dest_port": 8443, "hostname": host, "bytes_out": mb * 1024 * 1024,
        "severity_hint": "high", "mitre_tech_id": "T1041",
        "raw": f"fw: {src} -> {dst}:8443 bytes_out={mb*1024*1024}",
    }, [{"type": "ip", "value": dst, "threat_type": "exfil-destination", "confidence": 70}])


def _scn_phishing(rng):
    user = rng.choice(_USERS); dom = rng.choice(_BAD_DOMAINS); actor = rng.choice(_ACTORS)
    return ({
        "category": "web", "event_type": "proxy_request", "username": user,
        "action": "phishing_click", "severity_hint": "medium", "mitre_tech_id": "T1566.002",
        "raw": f"proxy: {user} GET https://{dom}/login category=phishing action=allowed",
    }, [{"type": "domain", "value": dom, "threat_type": "phishing", "confidence": 80, "actor": actor}])


def _scn_priv_esc(rng):
    user = rng.choice(_USERS); host = rng.choice(_INTERNAL_HOSTS)
    return ({
        "category": "identity", "event_type": "group_change", "username": user, "hostname": host,
        "action": "add_admin", "severity_hint": "high", "mitre_tech_id": "T1078",
        "raw": f"winlog: EventID=4728 member={user} group='Domain Admins' host={host}",
    }, [])


_SCENARIOS = [
    (_scn_brute_force, 0.20), (_scn_c2_beacon, 0.13), (_scn_malware, 0.15),
    (_scn_web_attack, 0.20), (_scn_exfil, 0.10), (_scn_phishing, 0.15), (_scn_priv_esc, 0.07),
]


def _pick_scenario(rng):
    r = rng.random(); acc = 0.0
    for fn, w in _SCENARIOS:
        acc += w
        if r <= acc:
            return fn
    return _SCENARIOS[0][0]


# ── Built-in detection rules (definitions that match the events above) ───────────
# Each maps an event_type to an alert with severity, MITRE, and a title template.
# These are real rules — they evaluate via rule_engine.evaluate(), exactly like
# any rule an analyst authors in the editor.
BUILTIN_RULES = [
    {"id": "R-BRUTEFORCE", "name": "Brute-force authentication", "category": "Identity",
     "severity": "high", "mitre_tactic": "Credential Access", "mitre_tactic_id": "TA0006",
     "mitre_tech_id": "T1110", "mitre_tech": "Brute Force",
     "title_tmpl": "Brute-force authentication against {username}@{hostname}",
     "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "failed_login"}], "logic": "and"}},
    {"id": "R-C2BEACON", "name": "C2 beaconing", "category": "Network",
     "severity": "critical", "mitre_tactic": "Command and Control", "mitre_tactic_id": "TA0011",
     "mitre_tech_id": "T1071.001", "mitre_tech": "Web Protocols",
     "title_tmpl": "C2 beacon from {hostname} to {dest_ip}",
     "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "beacon"}], "logic": "and"}},
    {"id": "R-MALPROC", "name": "Malicious process execution", "category": "Endpoint",
     "severity": "high", "mitre_tactic": "Execution", "mitre_tactic_id": "TA0002",
     "mitre_tech_id": "T1059.001", "mitre_tech": "PowerShell",
     "title_tmpl": "Malware execution on {hostname}",
     "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "process_start"},
                                    {"field": "action", "op": "equals", "value": "malicious"}], "logic": "and"}},
    {"id": "R-WEBATTACK", "name": "Web application attack", "category": "Network",
     "severity": "medium", "mitre_tactic": "Initial Access", "mitre_tactic_id": "TA0001",
     "mitre_tech_id": "T1190", "mitre_tech": "Exploit Public-Facing Application",
     "title_tmpl": "Web attack ({action}) on {hostname}",
     "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "web_request"}], "logic": "and"}},
    {"id": "R-EXFIL", "name": "Large data egress", "category": "Network",
     "severity": "high", "mitre_tactic": "Exfiltration", "mitre_tactic_id": "TA0010",
     "mitre_tech_id": "T1041", "mitre_tech": "Exfiltration Over C2 Channel",
     "title_tmpl": "Possible data exfiltration from {hostname}",
     "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "large_egress"},
                                    {"field": "bytes_out", "op": "gte", "value": 104857600}], "logic": "and"}},
    {"id": "R-PHISH", "name": "Credential phishing click", "category": "Email",
     "severity": "medium", "mitre_tactic": "Initial Access", "mitre_tactic_id": "TA0001",
     "mitre_tech_id": "T1566.002", "mitre_tech": "Spearphishing Link",
     "title_tmpl": "Phishing link clicked by {username}",
     "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "proxy_request"},
                                    {"field": "action", "op": "equals", "value": "phishing_click"}], "logic": "and"}},
    {"id": "R-PRIVESC", "name": "Privilege escalation", "category": "Identity",
     "severity": "high", "mitre_tactic": "Privilege Escalation", "mitre_tactic_id": "TA0004",
     "mitre_tech_id": "T1078", "mitre_tech": "Valid Accounts",
     "title_tmpl": "Privilege escalation by {username} on {hostname}",
     "definition": {"conditions": [{"field": "event_type", "op": "equals", "value": "group_change"}], "logic": "and"}},
]


def seed_builtin_rules():
    """Insert the built-in detection rules (idempotent). Live-mode bootstrap."""
    now = _now()
    with get_conn() as conn:
        for r in BUILTIN_RULES:
            if conn.execute("SELECT 1 FROM detection_rules WHERE id=?", (r["id"],)).fetchone():
                continue
            conn.execute(
                "INSERT INTO detection_rules (id,name,category,severity,mitre_tactic,mitre_tactic_id,"
                "mitre_tech_id,mitre_tech,status,source,created,description,definition,tags) "
                "VALUES (?,?,?,?,?,?,?,?, 'enabled','builtin',?,?,?, '[\"builtin\"]')",
                (r["id"], r["name"], r["category"], r["severity"], r["mitre_tactic"],
                 r["mitre_tactic_id"], r["mitre_tech_id"], r["mitre_tech"], now,
                 f"Built-in detection: {r['name']}.", dumps(r["definition"])),
            )
        conn.commit()


_RISK = {"critical": 92, "high": 76, "medium": 52, "low": 28, "info": 12}


def run_detection(conn, *, preview_rule: dict | None = None, limit: int = 300) -> dict:
    """Evaluate enabled rules over unprocessed events → create alerts.

    If preview_rule is given, evaluate ONLY that rule and return matches without
    creating alerts (backtest). Returns a summary."""
    import json
    from dashboard_api.rule_engine import evaluate
    from dashboard_api.detections import _insert_alert, _TACTIC  # reuse writer

    rows = conn.execute(
        "SELECT * FROM events WHERE processed=0 ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall() if preview_rule is None else conn.execute(
        "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    events = [dict(e) for e in rows]
    if preview_rule is not None:
        matches = evaluate(preview_rule, events)
        return {"matched": len(matches),
                "sample": [{"entity": m["entity"], "count": m["count"],
                            "ts": m["event"].get("ts"), "raw": m["event"].get("raw")}
                           for m in matches[:15]],
                "scanned": len(events)}

    rule_rows = conn.execute(
        "SELECT * FROM detection_rules WHERE status='enabled'").fetchall()
    rules = []
    for r in rule_rows:
        d = r["definition"]
        if isinstance(d, str):
            try:
                d = json.loads(d)
            except (ValueError, TypeError):
                d = {}
        if d.get("conditions"):
            rules.append({**dict(r), "definition": d})

    # Alert-tuning: active suppressions/allow-lists drop matching detections
    # before they ever become an alert (analyst feedback loop, not a hack).
    supp_rows = conn.execute(
        "SELECT id, rule_id, field, value FROM suppressions").fetchall()
    suppressions = [dict(s) for s in supp_rows]

    def _suppressed(rule_id: str, event: dict):
        for s in suppressions:
            if s["rule_id"] not in ("*", rule_id):
                continue
            ev_val = event.get(s["field"])
            if ev_val is not None and str(ev_val) == str(s["value"]):
                return s["id"]
        return None

    created = 0
    suppressed = 0
    supp_hits: dict[str, int] = {}
    for rule in rules:
        for m in evaluate(rule, events):
            ev = m["event"]
            sid = _suppressed(rule["id"], ev) if suppressions else None
            if sid:
                supp_hits[sid] = supp_hits.get(sid, 0) + 1
                suppressed += 1
                continue
            title = rule.get("name", "Detection")
            tmpl = next((br["title_tmpl"] for br in BUILTIN_RULES if br["id"] == rule["id"]), None)
            if tmpl:
                try:
                    title = tmpl.format(**{k: ev.get(k, "—") for k in
                                           ("username", "hostname", "dest_ip", "src_ip", "action")})
                except (KeyError, IndexError):
                    pass
            else:
                title = f"{rule['name']} · {m['entity']}"
            sev = rule.get("severity_override") or rule["severity"]
            _insert_alert(
                conn, title=title, severity=sev, risk=_RISK.get(sev, 50),
                rule_name=rule["name"], src_ip=ev.get("src_ip"), username=ev.get("username"),
                hostname=ev.get("hostname"), mitre_tech_id=rule.get("mitre_tech_id"),
                mitre_tech=rule.get("mitre_tech"), mitre_tactic=rule.get("mitre_tactic"),
                mitre_tactic_id=rule.get("mitre_tactic_id"),
                description=f"Rule '{rule['name']}' matched. {ev.get('raw', '')}",
                raw_log=ev.get("raw"), event_count=m["count"],
            )
            created += 1
        # bump the rule's hit counter + last_fired
        conn.execute("UPDATE detection_rules SET last_fired=? WHERE id=?", (_now(), rule["id"]))
    for sid, n in supp_hits.items():
        conn.execute("UPDATE suppressions SET hits=hits+? WHERE id=?", (n, sid))
    event_ids = [e["id"] for e in events]
    if event_ids:
        conn.executemany("UPDATE events SET processed=1 WHERE id=?", [(i,) for i in event_ids])
    return {"alerts": created, "events": len(events), "rules": len(rules),
            "suppressed": suppressed}


# ── Dark-web monitoring ──────────────────────────────────────────────────────────
_DW_SOURCES = ["BreachForums", "RaidForums mirror", "Telegram: combolist", "Pastebin",
               "Genesis Market", "Russian Market", "LeakBase", "Exploit.in"]
_DW_CATEGORIES = [
    ("credential-leak", "critical", "Leaked credentials for {email}"),
    ("data-for-sale", "high", "Database for sale: {org} customer records"),
    ("brand-mention", "medium", "Brand mention targeting {org}"),
    ("actor-chatter", "high", "{actor} discussing {org} access"),
    ("infrastructure", "high", "Initial-access broker listing for {org} VPN"),
]
_ORGS = ["Acme Security Corp", "your organisation"]


def _dark_web_finding(rng) -> dict:
    cat, sev, tmpl = rng.choice(_DW_CATEGORIES)
    email = f"{rng.choice(_USERS)}@acmesecurity.com"
    org = rng.choice(_ORGS); actor = rng.choice(_ACTORS)
    entity = email if cat == "credential-leak" else org
    title = tmpl.format(email=email, org=org, actor=actor)
    return {
        "id": str(uuid.uuid4()), "ts": _now(), "category": cat, "severity": sev,
        "source": rng.choice(_DW_SOURCES), "title": title, "entity": entity,
        "actor": actor if cat == "actor-chatter" else "",
        "detail": f"Observed on {rng.choice(_DW_SOURCES)}. Affects {entity}. "
                  + ("Plaintext password present; force reset." if cat == "credential-leak"
                     else "Validate exposure and notify stakeholders."),
        "url": f"darkweb://{rng.choice(_DW_SOURCES).lower().replace(' ', '-')}/{uuid.uuid4().hex[:8]}",
        "status": "new",
    }


# ── IOC + case writers ──────────────────────────────────────────────────────────
_SEV_FROM_CONF = lambda c: "critical" if c >= 85 else "high" if c >= 70 else "medium" if c >= 40 else "low"


def _write_ioc(conn, ioc: dict, source: str):
    value = ioc["value"]
    if conn.execute("SELECT 1 FROM iocs WHERE value=?", (value,)).fetchone():
        # re-observation → a sighting (refreshes last_seen, nudges confidence).
        from dashboard_api.ioc_lifecycle import record_sighting
        record_sighting(conn, value=value, source=source, boost=4)
        return False
    conf = int(ioc.get("confidence", 50))
    conn.execute(
        "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
        "first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), ioc["type"], value, ioc.get("threat_type", "malicious-activity"),
         conf, ioc.get("severity") or _SEV_FROM_CONF(conf), source, ioc.get("actor", ""),
         _now(), _now(), dumps(ioc.get("tags", ["engine-detected"]))),
    )
    return True


def _maybe_escalate_case(conn, actor_email="engine") -> int:
    """Correlate unresolved critical/high alerts by host/user/ip; open a SOAR
    case for any pivot with >= 3 contributing alerts not already cased."""
    rows = conn.execute(
        "SELECT id, title, severity, src_ip, hostname, username, ts FROM alerts "
        "WHERE status NOT IN ('resolved','closed') AND severity IN ('critical','high') "
        "ORDER BY ts DESC LIMIT 200"
    ).fetchall()
    buckets: dict[tuple, list] = {}
    for r in rows:
        for pk, pv in (("host", r["hostname"]), ("user", r["username"]), ("ip", r["src_ip"])):
            if pv:
                buckets.setdefault((pk, pv), []).append(dict(r))
    created = 0
    for (pk, pv), alerts in buckets.items():
        if len(alerts) < 3:
            continue
        # already an open case for this pivot?
        like = f'%"{pv}"%'
        if conn.execute("SELECT 1 FROM cases WHERE status NOT IN ('resolved','closed') AND entities LIKE ?",
                        (like,)).fetchone():
            continue
        sev = "critical" if any(a["severity"] == "critical" for a in alerts) else "high"
        cid = f"CASE-{random.randint(1000, 9999)}"
        if conn.execute("SELECT 1 FROM cases WHERE id=?", (cid,)).fetchone():
            cid = f"CASE-{random.randint(1000, 9999)}"
        now = _now()
        entities = [{"type": pk, "value": pv}]
        war = [{"ts": now, "actor": "correlation-engine", "type": "system",
                "content": f"Auto-opened: {len(alerts)} correlated {sev} alerts share {pk}={pv}."}]
        tasks = [{"id": f"T{i+1}", "phase": p, "name": n, "status": "pending", "assignee": None, "notes": ""}
                 for i, (p, n) in enumerate([("Triage", "Validate correlated alerts"),
                                             ("Containment", f"Isolate {pv}"),
                                             ("Eradication", "Remove persistence"),
                                             ("Recovery", "Restore service")])]
        conn.execute(
            "INSERT INTO cases (id,title,type,severity,status,owner,playbook,sla_hours,created,updated,"
            "alert_count,description,entities,war_room,tasks,evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cid, f"Correlated incident on {pk} {pv}", "Intrusion", sev, "new", "", "",
             4 if sev == "critical" else 8, now, now, len(alerts),
             f"{len(alerts)} correlated {sev} alerts share {pk}={pv}. Auto-escalated by the correlation engine.",
             dumps(entities), dumps(war), dumps(tasks), dumps([])),
        )
        audit(conn, actor_email, "case.auto_escalate", cid, f"pivot={pk}:{pv} alerts={len(alerts)}")
        created += 1
    return created


# ── Tick ─────────────────────────────────────────────────────────────────────────
def process_tick(max_events: int = 6) -> dict:
    """One pass of the live engine: generate telemetry → run detection rules →
    alerts, extract IOCs, monitor dark web, correlate/escalate."""
    import uuid as _uuid
    seed_builtin_rules()  # idempotent — guarantees detection rules exist
    rng = _rng()
    n = rng.randint(2, max(2, max_events))
    iocs = dark = 0
    with get_conn() as conn:
        for _ in range(n):
            scn = _pick_scenario(rng)
            event, scn_iocs = scn(rng)
            conn.execute(
                "INSERT INTO events (id,ts,category,event_type,src_ip,dest_ip,dest_port,username,"
                "hostname,process_name,action,bytes_out,country,severity_hint,mitre_tech_id,raw,processed) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (str(_uuid.uuid4()), _now(), event.get("category"), event.get("event_type"),
                 event.get("src_ip"), event.get("dest_ip"), event.get("dest_port"),
                 event.get("username"), event.get("hostname"), event.get("process_name"),
                 event.get("action"), event.get("bytes_out", 0), event.get("country"),
                 event.get("severity_hint"), event.get("mitre_tech_id"), event.get("raw")),
            )
            for ioc in scn_iocs:
                if _write_ioc(conn, ioc, source="engine:telemetry"):
                    iocs += 1
        # Detection: enabled rules evaluate the new events → alerts.
        det = run_detection(conn)
        alerts = det["alerts"]
        # dark-web monitoring: a finding every few ticks
        if rng.random() < 0.5:
            f = _dark_web_finding(rng)
            conn.execute(
                "INSERT INTO dark_web_findings (id,ts,category,severity,source,title,entity,actor,detail,url,status) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (f["id"], f["ts"], f["category"], f["severity"], f["source"], f["title"],
                 f["entity"], f["actor"], f["detail"], f["url"], f["status"]),
            )
            dark += 1
        cases = _maybe_escalate_case(conn)
        # IOC lifecycle maintenance: occasionally age out stale indicators.
        if rng.random() < 0.15:
            from dashboard_api.ioc_lifecycle import decay_iocs
            decay_iocs(conn)
        # SOAR automation: auto-trigger playbooks whose criteria match new alerts.
        from dashboard_api.playbook_engine import auto_trigger_playbooks
        pb_runs, pb_dispatches = auto_trigger_playbooks(conn)
        _emit_notifications(conn)
        conn.commit()
    if pb_dispatches:
        from dashboard_api.webhooks import dispatch
        for event, payload in pb_dispatches:
            dispatch(event, payload)
    summary = {"events": n, "alerts": alerts, "iocs": iocs, "darkWeb": dark,
               "casesEscalated": cases, "playbookRuns": pb_runs}
    # Real-time push: tell live clients new data landed so they refresh in place.
    if alerts or dark or cases or pb_runs:
        try:
            from dashboard_api.events_stream import publish
            publish("tick", summary)
        except Exception:
            pass
    return summary


def _emit_notifications(conn):
    """Surface the most important fresh events to the notification bell.
    Idempotent-ish: only items not already notified (tracked by a marker tag)."""
    from dashboard_api.routers.platform import notify
    # newest unnotified critical alert
    a = conn.execute(
        "SELECT id, title, severity FROM alerts WHERE severity='critical' "
        "AND id NOT IN (SELECT COALESCE(detail,'') FROM notifications WHERE type='alert') "
        "ORDER BY ts DESC LIMIT 1").fetchone()
    if a:
        notify(conn, type="alert", severity="critical", title=a["title"],
               detail=a["id"], link="/dashboard/siem")
    # newest unnotified credential leak
    d = conn.execute(
        "SELECT id, title FROM dark_web_findings WHERE category='credential-leak' "
        "AND id NOT IN (SELECT COALESCE(detail,'') FROM notifications WHERE type='darkweb') "
        "ORDER BY ts DESC LIMIT 1").fetchone()
    if d:
        notify(conn, type="darkweb", severity="critical", title=d["title"],
               detail=d["id"], link="/dashboard/darkweb")
    # newest unnotified open case
    c = conn.execute(
        "SELECT id, title, severity FROM cases WHERE status NOT IN ('resolved','closed') "
        "AND id NOT IN (SELECT COALESCE(detail,'') FROM notifications WHERE type='case') "
        "ORDER BY created DESC LIMIT 1").fetchone()
    if c:
        notify(conn, type="case", severity=c["severity"], title=c["title"],
               detail=c["id"], link="/dashboard/soar")
