"""Deterministic seed data for the dashboard API.

Generates a realistic, internally-consistent dataset: users, assets, SIEM alerts
that reference real MITRE techniques and real assets/users as owners, SOAR cases
that reference alerts and playbooks, threat actors with campaigns, IOCs tied to
actors, detection rules, log sources, feeds, and integrations.

Idempotent: running it is a no-op once the users table is populated, unless
``force=True`` is passed (which wipes and rebuilds every table).
"""
import random
import uuid
from datetime import datetime, timedelta, timezone

from dashboard_api.auth import hash_password
from dashboard_api.config import SEED_ADMIN_EMAIL, SEED_ADMIN_PASSWORD, SEED_RANDOM
from dashboard_api.db import dumps, get_conn
from dashboard_api.scoring import asset_risk, recompute_asset_risk, risk_band

UTC = timezone.utc


def _now():
    return datetime.now(UTC)


def _iso(dt):
    return dt.replace(microsecond=0).isoformat()


def _ago(rng, max_hours, min_minutes=1):
    mins = rng.randint(min_minutes, max_hours * 60)
    return _iso(_now() - timedelta(minutes=mins))


# --- Reference data ---------------------------------------------------------
MITRE = [
    ("Initial Access", "TA0001", "T1566", "Phishing"),
    ("Initial Access", "TA0001", "T1190", "Exploit Public-Facing Application"),
    ("Execution", "TA0002", "T1059", "Command and Scripting Interpreter"),
    ("Persistence", "TA0003", "T1547", "Boot or Logon Autostart Execution"),
    ("Privilege Escalation", "TA0004", "T1068", "Exploitation for Privilege Escalation"),
    ("Defense Evasion", "TA0005", "T1070", "Indicator Removal"),
    ("Credential Access", "TA0006", "T1110", "Brute Force"),
    ("Credential Access", "TA0006", "T1003", "OS Credential Dumping"),
    ("Discovery", "TA0007", "T1046", "Network Service Discovery"),
    ("Lateral Movement", "TA0008", "T1021", "Remote Services"),
    ("Collection", "TA0009", "T1560", "Archive Collected Data"),
    ("Command and Control", "TA0011", "T1071", "Application Layer Protocol"),
    ("Exfiltration", "TA0010", "T1041", "Exfiltration Over C2 Channel"),
    ("Impact", "TA0040", "T1486", "Data Encrypted for Impact"),
]
TACTIC_COLOR = {
    "Initial Access": "#FF2E97", "Execution": "#FF6B6B", "Persistence": "#FFB23E",
    "Privilege Escalation": "#FFD23E", "Defense Evasion": "#A3E635", "Credential Access": "#2DD4BF",
    "Discovery": "#38BDF8", "Lateral Movement": "#7A3CFF", "Collection": "#C084FC",
    "Command and Control": "#F472B6", "Exfiltration": "#FB7185", "Impact": "#EF4444",
}
COUNTRIES = ["RU", "CN", "KP", "IR", "US", "BR", "NL", "DE", "IN", "VN", "UA", "RO"]
SEVERITIES = ["critical", "high", "medium", "low"]
AVATAR_COLORS = ["#FF2E97", "#7A3CFF", "#2DD4BF", "#FFB23E", "#38BDF8", "#F472B6"]


def _rand_ip(rng):
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def _hash_value(rng):
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


# --- Seeders ----------------------------------------------------------------
def _seed_users(conn, rng):
    people = [
        (SEED_ADMIN_EMAIL, "Admin Operator", "admin", SEED_ADMIN_PASSWORD),
        ("sarah.chen@threatorbit.space", "Sarah Chen", "manager", "Password123!"),
        ("marcus.webb@threatorbit.space", "Marcus Webb", "analyst", "Password123!"),
        ("priya.nair@threatorbit.space", "Priya Nair", "analyst", "Password123!"),
        ("diego.ramos@threatorbit.space", "Diego Ramos", "analyst", "Password123!"),
        ("lena.fischer@threatorbit.space", "Lena Fischer", "analyst", "Password123!"),
        ("tom.okafor@threatorbit.space", "Tom Okafor", "viewer", "Password123!"),
    ]
    users = []
    for i, (email, name, role, pw) in enumerate(people):
        ph, salt = hash_password(pw)
        uid = str(uuid.uuid4())
        users.append((name, email, role))
        conn.execute(
            "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
            "avatar_color,mfa_enabled,last_login,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uid, email, name, role, "active", ph, salt, AVATAR_COLORS[i % len(AVATAR_COLORS)],
             1 if role in ("admin", "manager") else 0, _ago(rng, 48), _iso(_now() - timedelta(days=rng.randint(30, 400)))),
        )
    return [u[0] for u in users]  # analyst display names


def _seed_assets(conn, rng):
    base = [
        ("web-prod-01", "server", "10.0.1.20", "critical", "Ubuntu 22.04 LTS"),
        ("web-prod-02", "server", "10.0.1.21", "critical", "Ubuntu 22.04 LTS"),
        ("db-prod-primary", "database", "10.0.2.10", "critical", "PostgreSQL 15 / RHEL 9"),
        ("db-prod-replica", "database", "10.0.2.11", "high", "PostgreSQL 15 / RHEL 9"),
        ("threatorbit.space", "domain", "threatorbit.space", "critical", "-"),
        ("api.threatorbit.space", "domain", "api.threatorbit.space", "high", "-"),
        ("k8s-node-01", "cloud", "10.0.4.5", "high", "AKS / Ubuntu 20.04"),
        ("k8s-node-02", "cloud", "10.0.4.6", "high", "AKS / Ubuntu 20.04"),
        ("vpn-gateway", "server", "203.0.113.7", "critical", "pfSense 2.7"),
        ("jump-host", "server", "10.0.0.9", "high", "Debian 12"),
        ("ws-finance-14", "endpoint", "10.0.20.14", "medium", "Windows 11 Pro"),
        ("ws-eng-22", "endpoint", "10.0.21.22", "medium", "Windows 11 Pro"),
        ("ws-hr-03", "endpoint", "10.0.22.3", "low", "Windows 10 Pro"),
        ("mail-relay", "server", "10.0.3.4", "high", "Postfix / Debian 12"),
        ("backup-vault", "cloud", "10.0.5.2", "high", "AWS S3 + Glacier"),
        ("legacy-app-01", "server", "10.0.6.30", "medium", "CentOS 7"),
    ]
    owners = ["sarah.chen", "marcus.webb", "priya.nair", "diego.ramos", "lena.fischer"]
    port_pool = [22, 80, 443, 3306, 5432, 3389, 8080, 8443, 53, 25, 6379, 9200]
    # Installed software per asset - some deliberately vulnerable versions so the
    # vuln scanner produces genuine CVE findings; others patched (no findings).
    software_map = {
        "web-prod-01": [{"product": "nginx", "version": "1.17.6"}, {"product": "openssl", "version": "3.0.5"}],
        "legacy-app-01": [{"product": "log4j", "version": "2.14.1"}, {"product": "openssl", "version": "1.0.1f"}],
        "jump-host": [{"product": "openssh", "version": "9.6"}, {"product": "sudo", "version": "1.9.4"}],
        "mail-relay": [{"product": "exim", "version": "4.90"}, {"product": "openssl", "version": "3.0.7"}],
        "web-prod-02": [{"product": "apache httpd", "version": "2.4.49"}],
    }
    safe_default = [{"product": "openssl", "version": "3.0.13"}, {"product": "openssh", "version": "9.8"}]
    asset_names = []
    for name, typ, value, crit, os_ in base:
        software = software_map.get(name, safe_default if typ in ("server", "database", "cloud") else [])
        cves = {
            "critical": rng.randint(0, 2 if crit in ("critical", "high") else 1),
            "high": rng.randint(0, 4), "medium": rng.randint(0, 8), "low": rng.randint(0, 12),
        }
        patch_age = rng.randint(0, 180)
        ports = sorted(rng.sample(port_pool, rng.randint(2, 6)))
        tags = rng.sample(["prod", "pci", "internet-facing", "crown-jewel", "legacy", "monitored"], rng.randint(1, 3))
        # Provisional risk from the scoring model (alert pressure is filled in by
        # recompute_asset_risk once alerts exist). Status follows the same bands.
        alerts = rng.randint(0, 3) if crit in ("low", "medium") else rng.randint(1, 6)
        risk = asset_risk(cves=cves, criticality=crit, patch_age=patch_age,
                          open_alerts=alerts, open_ports=ports, tags=tags)
        status = "scanning" if rng.random() < 0.08 else risk_band(risk)
        conn.execute(
            "INSERT INTO assets (id,name,type,value,criticality,status,risk_score,last_scan,"
            "alerts,cves,open_ports,os,owner,patch_age,tags,uptime,created_at,software) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), name, typ, value, crit, status, risk, _ago(rng, 72),
             alerts, dumps(cves), dumps(ports), os_, rng.choice(owners), patch_age,
             dumps(tags),
             round(rng.uniform(97.5, 100.0), 2), _iso(_now() - timedelta(days=rng.randint(1, 300))),
             dumps(software)),
        )
        asset_names.append((name, value, crit))
    return asset_names


def _seed_rules(conn, rng):
    catalog = [
        ("Impossible Travel Detected", "Identity", "high"),
        ("Brute Force - SSH", "Network", "high"),
        ("Suspicious PowerShell Encoded Command", "Endpoint", "critical"),
        ("Mass File Encryption Behaviour", "Endpoint", "critical"),
        ("DNS Tunneling Pattern", "Network", "high"),
        ("New Admin Account Created", "Identity", "medium"),
        ("Cloud Storage Public Exposure", "Cloud", "high"),
        ("Known C2 IP Beacon", "Threat Intel", "critical"),
        ("Lateral Movement via SMB", "Network", "high"),
        ("Credential Dumping (LSASS Access)", "Endpoint", "critical"),
        ("Anomalous Data Egress Volume", "Network", "medium"),
        ("Disabled Security Tooling", "Endpoint", "high"),
        ("Multiple Failed MFA Challenges", "Identity", "medium"),
        ("Public-Facing Exploit Attempt", "Network", "high"),
    ]
    rule_refs = []
    for name, cat, sev in catalog:
        tactic, tac_id, tech_id, tech = rng.choice(MITRE)
        rid = "RULE-" + str(rng.randint(1000, 9999))
        enabled = rng.random() > 0.12
        status = "enabled" if enabled else rng.choice(["disabled", "suppressed"])
        conn.execute(
            "INSERT INTO detection_rules (id,name,category,severity,mitre_tactic,mitre_tech_id,"
            "mitre_tech,hits_24h,fired_last_7d,fp_rate,status,source,last_fired,created,updated_by,"
            "description,kql,suppression_window,severity_override,tags) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, name, cat, sev, tactic, tech_id, tech, rng.randint(0, 40), rng.randint(0, 220),
             round(rng.uniform(0.01, 0.25), 3), status, rng.choice(["Sigma", "Custom", "Elastic", "Splunk"]),
             _ago(rng, 168), _iso(_now() - timedelta(days=rng.randint(20, 500))),
             rng.choice(["sarah.chen", "marcus.webb", "priya.nair"]),
             f"Detects {name.lower()} based on correlated telemetry.",
             f'SecurityEvent | where Activity == "{name}" | summarize count() by Account, Computer',
             rng.choice([0, 5, 15, 30, 60]), "", dumps([cat.lower(), tactic.lower().replace(" ", "-")])),
        )
        rule_refs.append((rid, name, tactic, tac_id, tech_id, tech, sev))
    return rule_refs


def _seed_alerts(conn, rng, rule_refs, assets, analysts):
    services = {22: "ssh", 443: "https", 3389: "rdp", 3306: "mysql", 5432: "postgres", 445: "smb"}
    procs = ["powershell.exe", "cmd.exe", "rundll32.exe", "sshd", "python3", "wmic.exe", "mshta.exe"]
    n = 140
    weights = [0.12, 0.28, 0.38, 0.22]  # critical, high, medium, low
    statuses = ["new", "assigned", "in-progress", "pending", "resolved", "closed"]
    for _ in range(n):
        rid, rname, tactic, tac_id, tech_id, tech, _sev = rng.choice(rule_refs)
        sev = rng.choices(SEVERITIES, weights=weights)[0]
        asset_name, asset_val, asset_crit = rng.choice(assets)
        status = rng.choices(statuses, weights=[0.18, 0.16, 0.14, 0.1, 0.18, 0.24])[0]
        owner = "" if status == "new" else rng.choice(analysts)
        risk = {"critical": rng.randint(80, 99), "high": rng.randint(60, 85),
                "medium": rng.randint(35, 65), "low": rng.randint(10, 40)}[sev]
        dport = rng.choice(list(services.keys()) + [8080, 8443, 53])
        disp = "undetermined" if status in ("new", "assigned", "in-progress") else \
            rng.choice(["true-positive", "false-positive", "benign", "duplicate"])
        # SOC latency model (seconds). Detection is fast; higher severity is
        # acknowledged/responded to faster (analysts prioritise it). Only the
        # stages the alert has actually reached are populated.
        sev_factor = {"critical": 0.6, "high": 0.8, "medium": 1.0, "low": 1.3, "info": 1.5}[sev]
        detect_lat = int(rng.randint(45, 540) * sev_factor)  # ~1-9 min before scaling
        ack_lat = int(rng.randint(120, 1500) * sev_factor) if status != "new" else None
        respond_lat = int(rng.randint(600, 2700) * sev_factor) if status in (
            "resolved", "closed", "pending") else None
        conn.execute(
            "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,rule_id,"
            "rule_name,mitre_tactic,mitre_tactic_id,mitre_tech,mitre_tech_id,src_ip,src_country,"
            "src_port,src_hostname,src_asn,dest_ip,dest_port,dest_service,username,hostname,"
            "host_criticality,process_name,cmd_line,description,raw_log,event_count,ti_hits,bytes_out,"
            "detect_latency_sec,ack_latency_sec,respond_latency_sec) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), _ago(rng, 168), rname, sev, status, disp, owner, risk, rid, rname,
             tactic, tac_id, tech, tech_id, _rand_ip(rng), rng.choice(COUNTRIES), rng.randint(1024, 65535),
             f"host-{rng.randint(10,99)}", f"AS{rng.randint(1000,65000)}", asset_val if "." in asset_val else _rand_ip(rng),
             dport, services.get(dport, "http"), rng.choice(analysts).split(".")[0] if rng.random() > 0.3 else f"svc-{rng.randint(1,9)}",
             asset_name, asset_crit, rng.choice(procs),
             "powershell -enc JABzAD0ATgBlAHcA..." if rng.random() > 0.6 else "/usr/sbin/sshd -D",
             f"{rname} observed on {asset_name} from a {rng.choice(COUNTRIES)} source.",
             f'{_iso(_now())} {asset_name} {rname} src={_rand_ip(rng)} dport={dport}',
             rng.randint(1, 50), rng.randint(0, 5), rng.randint(0, 5_000_000),
             detect_lat, ack_lat, respond_lat),
        )


def _seed_log_sources(conn, rng):
    src = [
        ("Palo Alto Firewall", "CEF/ArcSight", "fw-pa-01.corp"),
        ("Windows Domain Controllers", "Windows Event", "dc-cluster"),
        ("Linux Syslog Fleet", "Syslog", "syslog-collector"),
        ("AWS CloudTrail", "S3 Bucket", "s3://to-cloudtrail"),
        ("Okta System Log", "API Pull", "to.okta.com"),
        ("CrowdStrike Falcon", "API Pull", "falcon.crowdstrike.com"),
        ("Zeek Network Sensor", "Kafka", "kafka://zeek-topic"),
        ("Office 365 Audit", "API Pull", "graph.microsoft.com"),
    ]
    for name, typ, host in src:
        eps = round(rng.uniform(50, 4200), 1)
        status = rng.choices(["healthy", "degraded", "offline", "paused"], weights=[0.7, 0.15, 0.08, 0.07])[0]
        conn.execute(
            "INSERT INTO log_sources (id,name,type,host,status,eps_avg,eps_peak,last_event,"
            "total_events_24h,latency_ms,parse_success,format,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), name, typ, host, status, eps, round(eps * rng.uniform(1.5, 3), 1),
             _ago(rng, 2) if status != "offline" else _ago(rng, 48),
             int(eps * 86400 * rng.uniform(0.6, 1.0)), rng.randint(20, 800),
             round(rng.uniform(92, 100), 1), typ, dumps([typ.split("/")[0].lower()])),
        )


def _seed_playbooks(conn, rng):
    """Insert the canonical executable playbooks with showcase run counters.
    Step definitions come from the playbook engine, so demo and live mode run
    the exact same real automation content."""
    from dashboard_api.playbook_engine import PLAYBOOK_DEFS, display_steps
    pb_names = []
    for d in PLAYBOOK_DEFS:
        steps = display_steps(d["steps"])
        runs = rng.randint(20, 900)
        sr = round(rng.uniform(0.82, 0.99), 3)
        avg = int(len(steps) * rng.uniform(8, 25))
        conn.execute(
            "INSERT INTO playbooks (id,name,category,trigger,trigger_type,description,runs,success_rate,"
            "avg_time,last_run,last_run_status,status,enabled,steps,trigger_match) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), d["name"], d["category"], d["trigger"], d["trigger_type"],
             d["description"], runs, sr, avg, _ago(rng, 72),
             rng.choice(["success", "success", "success", "failure"]),
             "idle", 1, dumps(steps), dumps(d["trigger_match"])),
        )
        pb_names.append(d["name"])
    return pb_names


def _seed_cases(conn, rng, playbooks, analysts, assets):
    titles = [
        ("Ransomware on finance endpoint", "Ransomware", "critical"),
        ("Phishing campaign targeting execs", "Phishing", "high"),
        ("Compromised VPN credentials", "Account Compromise", "high"),
        ("Data exfiltration via DNS", "Data Exfiltration", "critical"),
        ("Crypto-mining on k8s node", "Malware", "medium"),
        ("Brute-force against RDP", "Brute Force", "medium"),
        ("Suspicious admin escalation", "Privilege Escalation", "high"),
        ("Insider data access anomaly", "Insider Threat", "high"),
        ("C2 beacon from jump host", "C2", "critical"),
        ("Public S3 bucket exposure", "Misconfiguration", "high"),
        ("Malicious OAuth grant", "Account Compromise", "medium"),
        ("Web shell on legacy app", "Web Attack", "critical"),
    ]
    statuses = ["new", "assigned", "in-progress", "pending", "resolved", "closed"]
    for title, typ, sev in titles:
        created = _now() - timedelta(hours=rng.randint(2, 240))
        updated = created + timedelta(hours=rng.randint(1, 48))
        status = rng.choices(statuses, weights=[0.15, 0.18, 0.2, 0.1, 0.17, 0.2])[0]
        asset = rng.choice(assets)
        entities = [
            {"type": "host", "value": asset[0]},
            {"type": "ip", "value": _rand_ip(rng)},
            {"type": "user", "value": rng.choice(analysts).split(".")[0]},
        ]
        war = [{"ts": _iso(created + timedelta(minutes=m * 7)),
                "actor": rng.choice(analysts + ["playbook-engine"]),
                "type": rng.choice(["auto", "manual", "system"]),
                "content": c} for m, c in enumerate(
            ["Case opened from correlated alerts.", "Playbook auto-triage executed.",
             "Host isolated via EDR.", "Analyst confirmed true positive."][:rng.randint(2, 4)])]
        phases = ["Triage", "Containment", "Eradication", "Recovery"]
        tasks = [{"id": f"T{i+1}", "phase": phases[i % 4], "name": n,
                  "status": rng.choice(["done", "done", "in-progress", "pending"]),
                  "assignee": rng.choice(analysts), "notes": ""}
                 for i, n in enumerate(["Validate alert", "Isolate host", "Collect forensics",
                                        "Remove persistence", "Restore service"][:rng.randint(3, 5)])]
        evidence = [{"name": f"{asset[0]}-memdump.raw", "type": "memory", "added": _iso(updated),
                     "by": rng.choice(analysts)},
                    {"name": "ioc-list.csv", "type": "ioc", "added": _iso(updated), "by": rng.choice(analysts)}]
        conn.execute(
            "INSERT INTO cases (id,title,type,severity,status,owner,playbook,sla_hours,created,updated,"
            "alert_count,description,entities,war_room,tasks,evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("CASE-" + str(rng.randint(1000, 9999)), title, typ, sev, status,
             rng.choice(analysts),
             rng.choice(playbooks) if rng.random() > 0.35 else "",  # ~35% handled manually
             rng.choice([4, 8, 24, 48]),
             _iso(created), _iso(updated), rng.randint(1, 18),
             f"Investigation into {title.lower()} affecting {asset[0]}.",
             dumps(entities), dumps(war), dumps(tasks), dumps(evidence)),
        )


def _seed_integrations(conn, rng):
    items = [
        ("CrowdStrike Falcon", "CrowdStrike", "EDR", ["Isolate host", "Kill process", "Quarantine file"]),
        ("Palo Alto NGFW", "Palo Alto", "Firewall", ["Block IP", "Block URL", "Update policy"]),
        ("Splunk Enterprise", "Splunk", "SIEM", ["Run search", "Create notable"]),
        ("Jira Service Mgmt", "Atlassian", "Ticketing", ["Create ticket", "Update ticket"]),
        ("Slack", "Slack", "Communication", ["Post message", "Open war room"]),
        ("VirusTotal", "Google", "Threat Intel", ["Lookup hash", "Lookup IP", "Lookup domain"]),
        ("Okta", "Okta", "Identity", ["Suspend user", "Reset MFA", "Revoke session"]),
        ("AWS Security Hub", "AWS", "Cloud", ["Isolate instance", "Snapshot volume"]),
    ]
    for name, vendor, cat, actions in items:
        status = rng.choices(["connected", "degraded", "disconnected", "pending"], weights=[0.7, 0.12, 0.1, 0.08])[0]
        conn.execute(
            "INSERT INTO integrations (id,name,vendor,category,status,last_sync,actions_run,"
            "avg_response_ms,description,actions,enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), name, vendor, cat, status, _ago(rng, 6),
             rng.randint(50, 5000), rng.randint(80, 1200),
             f"{vendor} {cat} integration.", dumps(actions), 1 if status != "disconnected" else 0),
        )


def _seed_actors(conn, rng):
    """Demo actors come from the same curated reference library live mode uses,
    so identity is consistent across modes. Demo then layers on illustrative
    campaigns/last-seen; real activity (ioc_count) is filled from attributed
    indicators after the IOC seed runs."""
    from dashboard_api.threat_actor_library import ACTOR_LIBRARY, seed_actor_library
    seed_actor_library(conn)
    actor_names = [a[0] for a in ACTOR_LIBRARY]
    # Demo flavour: give each actor a couple of illustrative campaigns + a
    # plausible recent last-seen so the CTI page has texture before live data.
    for name in actor_names:
        campaigns = [{"year": 2024 - i,
                      "name": f"Operation {rng.choice(['Ghost','Tide','Echo','Cobalt','Frost'])} {rng.randint(1,9)}",
                      "note": "Targeted intrusion campaign."} for i in range(rng.randint(1, 3))]
        conn.execute(
            "UPDATE threat_actors SET first_seen=?, last_seen=?, campaign_count=?, "
            "campaigns=?, iocs=? WHERE name=?",
            (f"{2008 + rng.randint(0,12)}-01-01", _ago(rng, 720), len(campaigns),
             dumps(campaigns), dumps([_rand_ip(rng) for _ in range(3)]), name))
    return actor_names


def _seed_iocs(conn, rng, actors):
    types = ["ip", "domain", "url", "hash", "email"]
    for _ in range(120):
        t = rng.choice(types)
        if t == "ip":
            value = _rand_ip(rng)
        elif t == "domain":
            value = f"{rng.choice(['secure','update','cdn','mail','login'])}-{rng.randint(10,99)}.{rng.choice(['com','net','xyz','ru','cn'])}"
        elif t == "url":
            value = f"http://{_rand_ip(rng)}/{rng.choice(['gate','panel','c2','beacon'])}.php"
        elif t == "hash":
            value = _hash_value(rng)
        else:
            value = f"{rng.choice(['hr','it','ceo','billing'])}@{rng.choice(['acme-corp','mail-secure'])}.com"
        conn.execute(
            "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
            "first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), t, value, rng.choice(["C2", "Phishing", "Malware", "Scanning", "Exfil"]),
             rng.randint(40, 99), rng.choice(SEVERITIES), rng.choice(["OTX", "abuse.ch", "MISP", "Internal", "VirusTotal"]),
             rng.choice(actors) if rng.random() > 0.4 else "", _ago(rng, 720), _ago(rng, 72),
             dumps(rng.sample(["malicious", "active", "confirmed", "high-conf"], rng.randint(1, 2)))),
        )


def _seed_feeds(conn, rng):
    feeds = [
        ("AlienVault OTX", "AT&T", "opensource", "otx.alienvault.com/api/v1", "A"),
        ("abuse.ch MalwareBazaar", "abuse.ch", "community", "mb-api.abuse.ch/api/v1", "A"),
        ("MISP OSINT", "CIRCL", "opensource", "circl.lu/doc/misp/feed-osint", "B"),
        ("Recorded Future", "Recorded Future", "commercial", "api.recordedfuture.com/v2", "A"),
        ("Mandiant Threat Intel", "Google", "commercial", "api.intelligence.mandiant.com", "A"),
        ("Shodan Stream", "Shodan", "commercial", "stream.shodan.io", "B"),
        ("NVD CVE Feed", "NIST", "opensource", "nvd.nist.gov/feeds/json/cve/1.1", "A"),
        ("Internal Honeypot", "ThreatOrbit", "internal", "internal://honeypot", "A"),
    ]
    for name, prov, typ, url, rel in feeds:
        status = rng.choices(["active", "paused", "error"], weights=[0.78, 0.14, 0.08])[0]
        conn.execute(
            "INSERT INTO feeds (id,name,provider,type,status,enabled,indicators,last_sync,"
            "sync_interval,reliability,url,format) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), name, prov, typ, status, 1 if status != "paused" else 0,
             rng.randint(500, 250000), _ago(rng, 12), rng.choice([300, 900, 3600, 86400]),
             rel, url, rng.choice(["STIX 2.1", "JSON", "CSV", "TAXII"])),
        )


def _seed_settings(conn):
    defaults = {
        "platform_name": "ThreatOrbit Production",
        "organization": "Acme Security Corp",
        "timezone": "UTC",
        "data_retention_days": "90",
        "feed_update_interval": "3",
        "experience_mode": "power",
    }
    for k, v in defaults.items():
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (k, v))


def _seed_hunts(conn, rng):
    hunts = [
        ("siem", "Beaconing to rare ASNs", "Detect periodic outbound connections to uncommon ASNs", "T1071"),
        ("siem", "LOLBins execution", "Living-off-the-land binary abuse", "T1059"),
        ("siem", "Kerberoasting", "Service ticket requests for offline cracking", "T1558"),
        ("cti", "APT29 infrastructure overlap", "Pivot on shared TLS certs", "T1583"),
        ("cti", "Credential phishing kits", "Track kit reuse across campaigns", "T1566"),
    ]
    for domain, name, desc, tech in hunts:
        hits = rng.randint(0, 240)
        status = rng.choice(["idle", "idle", "complete", "scheduled"])
        progress = 100 if status == "complete" else (rng.randint(10, 90) if status == "running" else 0)
        conn.execute(
            "INSERT INTO saved_hunts (id,domain,name,description,query,technique,last_run,hit_count,author,status,progress,created) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), domain, name, desc,
             f'index=* | where technique=="{tech}" | stats count by src_ip',
             tech, _ago(rng, 96), hits, rng.choice(["sarah.chen", "marcus.webb", "priya.nair"]),
             status, progress, _ago(rng, 720)),
        )


def seed(force: bool = False):
    """Populate the database. No-op if users exist unless force=True."""
    rng = random.Random(SEED_RANDOM)
    with get_conn() as conn:
        existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing and not force:
            return False
        if force:
            for tbl in ("users", "assets", "alerts", "detection_rules", "log_sources",
                        "saved_hunts", "cases", "playbooks", "integrations", "threat_actors",
                        "iocs", "feeds", "api_keys", "settings", "jobs", "audit_log"):
                conn.execute(f"DELETE FROM {tbl}")

        analyst_names = _seed_users(conn, rng)
        analyst_logins = ["sarah.chen", "marcus.webb", "priya.nair", "diego.ramos", "lena.fischer"]
        assets = _seed_assets(conn, rng)
        rules = _seed_rules(conn, rng)
        _seed_alerts(conn, rng, rules, assets, analyst_logins)
        _seed_log_sources(conn, rng)
        playbooks = _seed_playbooks(conn, rng)
        _seed_cases(conn, rng, playbooks, analyst_logins, assets)
        _seed_integrations(conn, rng)
        actors = _seed_actors(conn, rng)
        _seed_iocs(conn, rng, actors)
        # Fill each actor's activity from the indicators just attributed to it,
        # so the Top Threat Actors ranking is real (not a random ioc_count).
        from dashboard_api.threat_actor_library import recompute_actor_activity
        recompute_actor_activity(conn)
        _seed_feeds(conn, rng)
        _seed_hunts(conn, rng)
        _seed_settings(conn)
        # Now that alerts exist, align each asset's risk/status/alert-count with
        # real alert pressure so the stored scores match the live model.
        recompute_asset_risk(conn)
        # Run the real vulnerability scanner over the seeded software inventories
        # so vuln findings are genuine catalogue matches, not invented counts.
        from dashboard_api.vuln_scanner import scan_all
        scan_all(conn)
        recompute_asset_risk(conn)
        # Place all seeded users in the default workspace (multi-tenancy foundation).
        from dashboard_api.tenancy import ensure_default_org
        ensure_default_org(conn)
        conn.commit()
    return True


def bootstrap_live():
    """Live-mode bootstrap: create the admin user, default settings, and the
    real feed catalogue - but NO demo alerts/actors/assets. Indicators arrive
    from the connector engine. Idempotent (no-op once a user exists)."""
    from dashboard_api.auth import hash_password
    from dashboard_api.threat_actor_library import seed_actor_library, recompute_actor_activity
    with get_conn() as conn:
        first = not conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if first:
            ph, salt = hash_password(SEED_ADMIN_PASSWORD)
            conn.execute(
                "INSERT INTO users (id,email,name,role,status,password_hash,password_salt,"
                "avatar_color,mfa_enabled,last_login,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), SEED_ADMIN_EMAIL, "Admin Operator", "admin", "active",
                 ph, salt, "#FF2E97", 1, None, _iso(_now())),
            )
            _seed_settings(conn)
            from dashboard_api.tenancy import ensure_default_org
            ensure_default_org(conn)
        # Reference actor knowledge base + real attributed activity - every boot
        # (idempotent), so existing live deployments get backfilled too.
        seed_actor_library(conn)
        recompute_actor_activity(conn)
        conn.commit()
    return first


if __name__ == "__main__":
    import sys
    if "--live" in sys.argv:
        print("Live bootstrap done" if bootstrap_live() else "Already bootstrapped")
    else:
        init_msg = seed(force=True)
        print("Seeded" if init_msg else "Already seeded")
