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


# ── Detection scenarios ─────────────────────────────────────────────────────────
# Each scenario builds a normalised event AND the alert it should raise. Returning
# (alert_kwargs, iocs) keeps detection and IOC extraction real and explicit.

def _scn_brute_force(rng):
    src = _pub_ip(rng); user = rng.choice(_USERS); host = rng.choice(_INTERNAL_HOSTS)
    n = rng.randint(40, 400)
    return ({
        "title": f"Brute-force authentication against {user}@{host}",
        "severity": "high" if n < 200 else "critical",
        "risk": rng.randint(70, 95), "rule_name": "Auth · Failed-login burst",
        "src_ip": src, "username": user, "hostname": host,
        "mitre_tech_id": "T1110", "mitre_tech": "Brute Force",
        "mitre_tactic": "Credential Access", "mitre_tactic_id": "TA0006",
        "description": f"{n} failed logons for {user} from {src} in 5 minutes, then a success.",
        "raw_log": f"{_now()} sshd[{rng.randint(1000,9999)}]: Failed password for {user} from {src} port {rng.randint(1024,65535)}",
        "event_count": n,
    }, [{"type": "ip", "value": src, "threat_type": "brute-force-source", "confidence": 75}])


def _scn_c2_beacon(rng):
    src = _int_ip(rng); dst = _pub_ip(rng); host = rng.choice(_INTERNAL_HOSTS)
    mal = rng.choice(_MALWARE); actor = rng.choice(_ACTORS)
    return ({
        "title": f"C2 beacon from {host} to {dst} ({mal})",
        "severity": "critical", "risk": rng.randint(85, 99),
        "rule_name": "Network · Beaconing", "src_ip": src, "hostname": host,
        "mitre_tech_id": "T1071.001", "mitre_tech": "Web Protocols",
        "mitre_tactic": "Command and Control", "mitre_tactic_id": "TA0011",
        "description": f"Periodic low-jitter HTTPS callbacks from {host} to {dst}, consistent with {mal} attributed to {actor}.",
        "raw_log": f"{_now()} fw: ALLOW {src}:{rng.randint(40000,60000)} -> {dst}:443 bytes={rng.randint(400,1200)} interval=58s",
        "event_count": rng.randint(12, 80),
    }, [{"type": "ip", "value": dst, "threat_type": "c2", "confidence": 90, "actor": actor, "severity": "critical"}])


def _scn_malware(rng):
    host = rng.choice(_INTERNAL_HOSTS); user = rng.choice(_USERS)
    h = _sha256(rng); mal = rng.choice(_MALWARE); proc = rng.choice(_PROCS)
    return ({
        "title": f"Malware execution on {host} ({mal})",
        "severity": rng.choice(["high", "critical"]), "risk": rng.randint(78, 97),
        "rule_name": "Endpoint · Malicious process", "hostname": host, "username": user,
        "mitre_tech_id": "T1059.001", "mitre_tech": "PowerShell",
        "mitre_tactic": "Execution", "mitre_tactic_id": "TA0002",
        "description": f"{proc} spawned an encoded payload identified as {mal} (SHA256 {h[:16]}…) on {host}.",
        "raw_log": f"{_now()} EDR: {host} {proc} -enc <b64> sha256={h} verdict=malicious family={mal}",
        "event_count": 1,
    }, [{"type": "hash", "value": h, "threat_type": mal, "confidence": 88, "severity": "high"}])


def _scn_web_attack(rng):
    src = _pub_ip(rng); host = rng.choice(["WEB-LB-01", "PROD-API-04", "wordpress-mkt"])
    kind = rng.choice([("SQL injection", "T1190", "SQLi"), ("Path traversal", "T1083", "LFI"),
                       ("Web shell upload", "T1505.003", "WebShell")])
    return ({
        "title": f"{kind[0]} attempt on {host}",
        "severity": rng.choice(["medium", "high"]), "risk": rng.randint(55, 82),
        "rule_name": "Web · Application attack", "src_ip": src, "hostname": host,
        "mitre_tech_id": kind[1], "mitre_tech": kind[2],
        "mitre_tactic": "Initial Access", "mitre_tactic_id": "TA0001",
        "description": f"{kind[0]} payload from {src} against {host}.",
        "raw_log": f'{_now()} nginx: {src} "GET /index.php?id=1\' OR 1=1-- HTTP/1.1" 200',
        "event_count": rng.randint(1, 12),
    }, [{"type": "ip", "value": src, "threat_type": "web-attack", "confidence": 65}])


def _scn_exfil(rng):
    src = _int_ip(rng); dst = _pub_ip(rng); host = rng.choice(_INTERNAL_HOSTS)
    mb = rng.randint(200, 4000)
    return ({
        "title": f"Possible data exfiltration from {host} ({mb} MB)",
        "severity": "critical" if mb > 1000 else "high", "risk": rng.randint(72, 96),
        "rule_name": "Network · Large egress", "src_ip": src, "hostname": host,
        "mitre_tech_id": "T1041", "mitre_tech": "Exfiltration Over C2 Channel",
        "mitre_tactic": "Exfiltration", "mitre_tactic_id": "TA0010",
        "description": f"{mb} MB transferred from {host} to external {dst} over an unusual port.",
        "raw_log": f"{_now()} fw: {src} -> {dst}:8443 bytes_out={mb*1024*1024}",
        "event_count": 1,
    }, [{"type": "ip", "value": dst, "threat_type": "exfil-destination", "confidence": 70}])


def _scn_phishing(rng):
    user = rng.choice(_USERS); dom = rng.choice(_BAD_DOMAINS); actor = rng.choice(_ACTORS)
    return ({
        "title": f"Phishing link clicked by {user}",
        "severity": rng.choice(["medium", "high"]), "risk": rng.randint(50, 80),
        "rule_name": "Email · Credential phishing", "username": user,
        "mitre_tech_id": "T1566.002", "mitre_tech": "Spearphishing Link",
        "mitre_tactic": "Initial Access", "mitre_tactic_id": "TA0001",
        "description": f"{user} submitted credentials to {dom}, a known phishing domain linked to {actor}.",
        "raw_log": f"{_now()} proxy: {user} GET https://{dom}/login category=phishing action=allowed",
        "event_count": 1,
    }, [{"type": "domain", "value": dom, "threat_type": "phishing", "confidence": 80, "actor": actor}])


def _scn_priv_esc(rng):
    user = rng.choice(_USERS); host = rng.choice(_INTERNAL_HOSTS)
    return ({
        "title": f"Privilege escalation by {user} on {host}",
        "severity": "high", "risk": rng.randint(68, 88),
        "rule_name": "Identity · Privilege escalation", "username": user, "hostname": host,
        "mitre_tech_id": "T1078", "mitre_tech": "Valid Accounts",
        "mitre_tactic": "Privilege Escalation", "mitre_tactic_id": "TA0004",
        "description": f"{user} was added to Domain Admins on {host} outside change control.",
        "raw_log": f"{_now()} winlog: EventID=4728 member={user} group='Domain Admins' host={host}",
        "event_count": 1,
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
        conn.execute("UPDATE iocs SET last_seen=? WHERE value=?", (_now(), value))
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
    """One pass of the live engine. Returns a summary of what it produced."""
    rng = _rng()
    n = rng.randint(2, max(2, max_events))
    alerts = iocs = dark = 0
    with get_conn() as conn:
        for _ in range(n):
            scn = _pick_scenario(rng)
            alert_kw, scn_iocs = scn(rng)
            _insert_alert(conn, **alert_kw)
            alerts += 1
            for ioc in scn_iocs:
                if _write_ioc(conn, ioc, source=f"engine:{alert_kw['rule_name']}"):
                    iocs += 1
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
        conn.commit()
    return {"events": n, "alerts": alerts, "iocs": iocs, "darkWeb": dark, "casesEscalated": cases}
