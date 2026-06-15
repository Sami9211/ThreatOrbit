"""Native log-source ingestion - the collector side of the SIEM.

Accepts raw log lines (syslog, Apache/Nginx, JSON, key=value, or generic),
parses them into normalised `events` rows, and lets the detection rule engine
fire on them. This is how production logs stream into the SIEM (an agent or
syslog forwarder POSTs lines to /siem/ingest), distinct from the deep-analysis
path that hands a whole file to the Log API's ML detectors.

JSON ingest additionally recognises two high-value source shapes and maps their
distinctive fields onto the native vocabulary so the same rules fire on them:
**Windows Security events** (raw EVTX-JSON or winlog/Beats; EventID → event_type,
e.g. 4625 → failed_login, 4732 → group_change) and **AWS CloudTrail** records
(eventName → event_type, e.g. CreateAccessKey → create_access_key).

Every parser returns the same normalised event shape the rule engine reads:
{category, event_type, src_ip, dest_ip, dest_port, username, hostname,
 process_name, action, bytes_out, severity_hint, mitre_tech_id, raw}.
"""
import json
import re
import uuid
from datetime import datetime, timezone

from dashboard_api.db import get_conn

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER = re.compile(r"(?:user(?:name)?|account|for)\s*[=:]?\s*([A-Za-z0-9._\\-]+)", re.I)
_HOST = re.compile(r"\bhost(?:name)?\s*[=:]\s*([A-Za-z0-9._-]+)", re.I)

# Content → (event_type, category, severity_hint, mitre) inference. First match wins.
_SIGNATURES = [
    (re.compile(r"failed password|authentication failure|invalid user|login failed", re.I),
     ("failed_login", "auth", "high", "T1110")),
    (re.compile(r"accepted password|session opened|login success", re.I),
     ("login_success", "auth", "low", "T1078")),
    (re.compile(r"sql(?:i| injection)|union select|' or '1'='1|1=1--", re.I),
     ("web_request", "web", "high", "T1190")),
    (re.compile(r"\.\./|directory traversal|/etc/passwd", re.I),
     ("web_request", "web", "high", "T1083")),
    (re.compile(r"powershell.{0,40}-enc|invoke-expression|downloadstring|mimikatz", re.I),
     ("process_start", "endpoint", "high", "T1059.001")),
    (re.compile(r"malware|trojan|ransom|verdict=malicious|virus", re.I),
     ("process_start", "endpoint", "critical", "T1204")),
    (re.compile(r"beacon|c2|command.?and.?control|cobalt", re.I),
     ("beacon", "network", "critical", "T1071.001")),
    (re.compile(r"added to .*(admin|sudoers)|EventID=4728|privilege", re.I),
     ("group_change", "identity", "high", "T1078")),
    (re.compile(r"port ?scan|nmap|masscan", re.I),
     ("port_scan", "network", "medium", "T1046")),
]


def _infer(text: str) -> tuple[str, str, str, str | None]:
    for rx, meta in _SIGNATURES:
        if rx.search(text):
            return meta
    return ("log", "generic", "info", None)


# Windows Security Event ID → normalised event_type (+ ATT&CK where notable), so
# Windows logs land on the same vocabulary the detection rules read (e.g. 4625
# → failed_login feeds the brute-force rule, 4728/4732 → group_change).
_WIN_EVENTID = {
    4624: ("login_success", "T1078"), 4625: ("failed_login", "T1110"),
    4634: ("logoff", None), 4647: ("logoff", None), 4648: ("login_success", "T1078"),
    4672: ("privileged_login", "T1078"), 4688: ("process_start", None),
    4689: ("process_end", None), 4720: ("user_created", "T1136"),
    4726: ("user_deleted", None), 4728: ("group_change", "T1098"),
    4732: ("group_change", "T1098"), 4756: ("group_change", "T1098"),
    4738: ("user_changed", None), 1102: ("log_cleared", "T1070.001"),
    4719: ("policy_change", "T1562"), 7045: ("service_install", "T1543.003"),
    4697: ("service_install", "T1543.003"),
}

# AWS CloudTrail eventName → normalised event_type (high-value control-plane
# actions; CreateAccessKey feeds the cloud-persistence rule, StopLogging the
# defense-evasion path).
_CT_EVENTNAME = {
    "CreateAccessKey": ("create_access_key", "T1098.001"),
    "CreateLoginProfile": ("create_access_key", "T1098.001"),
    "CreateUser": ("user_created", "T1136.003"), "DeleteUser": ("user_deleted", None),
    "AttachUserPolicy": ("policy_change", "T1098.003"),
    "PutUserPolicy": ("policy_change", "T1098.003"),
    "AuthorizeSecurityGroupIngress": ("firewall_change", "T1562.007"),
    "StopLogging": ("log_cleared", "T1562.008"), "DeleteTrail": ("log_cleared", "T1562.008"),
    "RunInstances": ("instance_launch", None), "GetSecretValue": ("secret_access", "T1552.005"),
}


def _is_ip(s) -> bool:
    s = str(s)
    if _IPV4.fullmatch(s):
        return True
    return ":" in s and all(c in "0123456789abcdefABCDEF:." for c in s)  # rough IPv6


def _base_event(raw: str) -> dict:
    et, cat, sev, mitre = _infer(raw)
    ips = _IPV4.findall(raw)
    user_m = _USER.search(raw)
    host_m = _HOST.search(raw)
    return {
        "category": cat, "event_type": et, "severity_hint": sev, "mitre_tech_id": mitre,
        "src_ip": ips[0] if ips else None,
        "dest_ip": ips[1] if len(ips) > 1 else None,
        "username": user_m.group(1) if user_m else None,
        "hostname": host_m.group(1) if host_m else None,
        "raw": raw[:1000],
    }


def _flatten(obj: dict, prefix: str = "") -> dict:
    """Flatten nested JSON to dotted keys: {"source": {"ip": x}} → {"source.ip": x}.
    This is how ECS documents arrive (Beats/Logstash emit nested objects)."""
    out: dict = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{key}."))
        else:
            out[key] = v
    return out


# Native integer fields (everything else stores as text).
_INT_FIELDS = {"dest_port", "bytes_out"}


def _apply_ecs(ev: dict, obj: dict, weak: set[str]) -> None:
    """ECS ingest-time normalisation: resolve Elastic Common Schema names -
    nested ({"source": {"ip": …}}) or dotted ("source.ip") - into the stored
    native fields using the same alias map the rule/query layer uses, so an
    ECS-shaped document lands fully normalised instead of relying on the
    read-time alias layer.

    Precedence: explicit flat JSON keys > ECS fields > raw-line regex
    heuristics (`weak` holds fields whose value is only a heuristic guess -
    the producer's ECS metadata is authoritative over those). Content-derived
    event classification (event_type/severity/MITRE from signatures) is kept
    unless it's the generic default."""
    from dashboard_api.rule_engine import ECS_ALIASES
    flat = _flatten(obj)
    for ecs, native in ECS_ALIASES.items():
        v = flat.get(ecs)
        if v in (None, "") or native == "raw":  # raw always keeps the original line
            continue
        if native in _INT_FIELDS:
            try:
                v = int(v)
            except (ValueError, TypeError):
                continue
        else:
            v = str(v)
        if native in weak or not ev.get(native) or ev[native] in ("log", "generic"):
            ev[native] = v


def _apply_windows(ev: dict, obj: dict) -> bool:
    """Recognise a Windows Security event (raw EVTX-JSON or winlog/Beats shape)
    and map its fields onto the native event. Returns True if it matched."""
    winlog = obj.get("winlog") if isinstance(obj.get("winlog"), dict) else {}
    data = winlog.get("event_data") if isinstance(winlog.get("event_data"), dict) else {}
    eid = obj.get("EventID") or obj.get("event_id") or winlog.get("event_id")
    try:
        eid = int(eid)
    except (ValueError, TypeError):
        return False
    # Distinguish a real Windows record from arbitrary JSON that happens to carry
    # an "EventID": require a Windows-y companion field.
    src = {**data, **winlog, **obj}
    if not (winlog or any(k in src for k in ("Channel", "Computer", "TargetUserName",
                                             "SubjectUserName", "provider_name"))):
        return False

    def g(*keys):
        for k in keys:
            v = src.get(k)
            if v not in (None, "", "-"):
                return v
        return None

    et, mitre = _WIN_EVENTID.get(eid, (f"windows_{eid}", None))
    ev["event_type"] = et
    ev["category"] = "windows"
    if mitre:
        ev["mitre_tech_id"] = mitre
    user = g("TargetUserName", "SubjectUserName", "user", "AccountName")
    if user:
        ev["username"] = str(user)
    host = g("Computer", "computer_name", "Workstation", "hostname")
    if host:
        ev["hostname"] = str(host)
    ip = g("IpAddress", "ip_address", "SourceNetworkAddress")
    if ip and _is_ip(ip):
        ev["src_ip"] = str(ip)
    proc = g("NewProcessName", "ProcessName", "Image")
    if proc:
        ev["process_name"] = str(proc)
    return True


def _apply_cloudtrail(ev: dict, obj: dict) -> bool:
    """Recognise an AWS CloudTrail record and map it onto the native event.
    Returns True if it matched."""
    name = obj.get("eventName")
    source = str(obj.get("eventSource") or "")
    if not name or not (source.endswith("amazonaws.com") or "eventVersion" in obj):
        return False
    et, mitre = _CT_EVENTNAME.get(name, (None, None))
    if et is None:  # an action we don't special-case → keep the AWS name, mark failures
        et = "cloud_audit"
    # Console-login outcome lives in responseElements; reflect failure explicitly.
    resp = obj.get("responseElements") if isinstance(obj.get("responseElements"), dict) else {}
    if name == "ConsoleLogin":
        et = "failed_login" if str(resp.get("ConsoleLogin")).lower() == "failure" else "login_success"
    ev["event_type"] = et
    ev["category"] = "cloud_audit"
    if mitre:
        ev["mitre_tech_id"] = mitre
    ev["action"] = "deny" if obj.get("errorCode") else "allow"
    ip = obj.get("sourceIPAddress")
    if ip and _is_ip(ip):
        ev["src_ip"] = str(ip)
    ident = obj.get("userIdentity") if isinstance(obj.get("userIdentity"), dict) else {}
    user = ident.get("userName") or ident.get("arn") or ident.get("type")
    if user:
        ev["username"] = str(user).rsplit("/", 1)[-1]  # arn → trailing principal name
    return True


def _parse_json(line: str) -> dict | None:
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    base = _base_event(line)
    ev = dict(base)
    # Map common JSON keys onto the normalised shape (scalars only - nested
    # objects like ECS {"host": {"name": …}} are handled by _apply_ecs below).
    def pick(*keys):
        for k in keys:
            v = obj.get(k)
            if v not in (None, "") and isinstance(v, (str, int, float)):
                return v
        return None
    ev["src_ip"] = pick("src_ip", "source_ip", "srcip", "client_ip", "ip") or ev["src_ip"]
    ev["dest_ip"] = pick("dest_ip", "destination_ip", "dstip") or ev["dest_ip"]
    ev["username"] = pick("user", "username", "user_name", "account") or ev["username"]
    ev["hostname"] = pick("host", "hostname", "computer", "device") or ev["hostname"]
    ev["process_name"] = pick("process", "process_name", "image")
    dp = pick("dest_port", "dst_port", "port")
    if dp is not None:
        try:
            ev["dest_port"] = int(dp)
        except (ValueError, TypeError):
            pass
    bo = pick("bytes_out", "bytes", "bytes_sent")
    if bo is not None:
        try:
            ev["bytes_out"] = int(bo)
        except (ValueError, TypeError):
            pass
    if obj.get("event_type"):
        ev["event_type"] = str(obj["event_type"])
    # Source-specific shapes (Windows Security / AWS CloudTrail) map their
    # distinctive fields authoritatively onto the native vocabulary, so the same
    # detection rules fire on them. Generic JSON/ECS handling fills the rest.
    _apply_windows(ev, obj) or _apply_cloudtrail(ev, obj)
    # ECS documents (nested or dotted keys) normalise at ingest time too.
    # Entity fields still holding only the raw-line regex guess are "weak" -
    # the producer's ECS values are authoritative over them.
    weak = {k for k in ("src_ip", "dest_ip", "username", "hostname")
            if ev.get(k) is not None and ev[k] == base.get(k)}
    _apply_ecs(ev, obj, weak)
    return ev


def _parse_kv(line: str) -> dict:
    ev = _base_event(line)
    for m in re.finditer(r"(\w+)=([^\s]+)", line):
        k, v = m.group(1).lower(), m.group(2).strip('"')
        if k in ("src", "src_ip", "srcip", "client"):
            ev["src_ip"] = v
        elif k in ("dst", "dest_ip", "dstip"):
            ev["dest_ip"] = v
        elif k in ("user", "username", "account"):
            ev["username"] = v
        elif k in ("host", "hostname", "computer"):
            ev["hostname"] = v
        elif k in ("dport", "dest_port", "port"):
            try:
                ev["dest_port"] = int(v)
            except ValueError:
                pass
    return ev


_APACHE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(\S+)\s+\[[^\]]+\]\s+"([^"]*)"\s+(\d{3})')


def _parse_apache(line: str) -> dict | None:
    m = _APACHE.match(line)
    if not m:
        return None
    ev = _base_event(line)
    ev["src_ip"] = m.group(1)
    if m.group(2) not in ("-", ""):
        ev["username"] = m.group(2)
    ev["action"] = m.group(3).split()[0] if m.group(3) else "GET"
    ev["category"], ev["event_type"] = "web", ev["event_type"] if ev["event_type"] != "log" else "web_request"
    return ev


def parse_line(line: str, fmt: str = "auto") -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if fmt in ("json", "auto") and line[:1] in "{[":
        ev = _parse_json(line)
        if ev:
            return ev
    if fmt in ("apache", "nginx", "auto"):
        ev = _parse_apache(line)
        if ev:
            return ev
    if fmt == "kv" or (fmt == "auto" and "=" in line and " " in line):
        return _parse_kv(line)
    return _base_event(line)


def ingest_lines(lines: list[str], fmt: str = "auto", source: str = "collector") -> dict:
    """Parse lines → events → run detection. Returns {ingested, parsed, alerts}."""
    from dashboard_api.engine import run_detection, seed_builtin_rules
    seed_builtin_rules()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    parsed = 0
    with get_conn() as conn:
        for line in lines:
            ev = parse_line(line, fmt)
            if ev is None:
                continue
            conn.execute(
                "INSERT INTO events (id,ts,category,event_type,src_ip,dest_ip,dest_port,username,"
                "hostname,process_name,action,bytes_out,country,severity_hint,mitre_tech_id,raw,processed) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (str(uuid.uuid4()), now, ev.get("category"), ev.get("event_type"),
                 ev.get("src_ip"), ev.get("dest_ip"), ev.get("dest_port"), ev.get("username"),
                 ev.get("hostname"), ev.get("process_name"), ev.get("action"),
                 ev.get("bytes_out", 0), ev.get("country"), ev.get("severity_hint"),
                 ev.get("mitre_tech_id"), ev.get("raw")),
            )
            parsed += 1
        det = run_detection(conn)
        # threat-intel matching over the just-ingested events
        ti = match_threat_intel(conn)
        conn.commit()
    try:  # observability counters (never block ingest)
        from dashboard_api import observability
        observability.inc("ingested_events", parsed)
        observability.inc("ingest_alerts", det["alerts"] + ti)
    except Exception:
        pass
    return {"ingested": len(lines), "parsed": parsed,
            "alerts": det["alerts"] + ti, "tiMatches": ti, "source": source}


def match_threat_intel(conn) -> int:
    """First-class TI detection: any event whose src/dest IP or hostname matches
    a known malicious IOC raises an enriched 'threat intel match' alert."""
    from dashboard_api.detections import alert_from_intel
    rows = conn.execute(
        "SELECT id, src_ip, dest_ip, hostname FROM events WHERE processed IN (0,1) "
        "ORDER BY ts DESC LIMIT 300"
    ).fetchall()
    raised = 0
    seen = set()
    for e in rows:
        for val in (e["src_ip"], e["dest_ip"]):
            if not val or val in seen:
                continue
            ioc = conn.execute(
                "SELECT id, type, value, severity, confidence, threat_type, actor, source "
                "FROM iocs WHERE value=? AND severity IN ('critical','high') AND status='active'", (val,)
            ).fetchone()
            if not ioc:
                continue
            # the event observing this indicator IS a sighting - record it.
            from dashboard_api.ioc_lifecycle import record_sighting
            record_sighting(conn, ioc_id=ioc["id"], source="siem:event",
                            context=f"event {e['id']} matched {val}")
            # avoid duplicate intel alerts for the same value
            if conn.execute("SELECT 1 FROM alerts WHERE src_ip=? AND rule_id='R-TIMATCH'", (val,)).fetchone():
                seen.add(val)
                continue
            aid = alert_from_intel(conn, value=ioc["value"], ioc_type=ioc["type"],
                                   severity=ioc["severity"], confidence=ioc["confidence"] or 70,
                                   threat_type=ioc["threat_type"] or "", actor_name=ioc["actor"] or "",
                                   source=ioc["source"] or "CTI")
            conn.execute("UPDATE alerts SET rule_id='R-TIMATCH' WHERE id=?", (aid,))
            raised += 1
            seen.add(val)
    return raised
