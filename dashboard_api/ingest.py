"""Native log-source ingestion - the collector side of the SIEM.

Accepts raw log lines (syslog, Apache/Nginx, JSON, key=value, or generic),
parses them into normalised `events` rows, and lets the detection rule engine
fire on them. This is how production logs stream into the SIEM (an agent or
syslog forwarder POSTs lines to /siem/ingest), distinct from the deep-analysis
path that hands a whole file to the Log API's ML detectors.

JSON ingest additionally recognises high-value source shapes and maps their
distinctive fields onto the native vocabulary so the same rules fire on them:
**Windows Security events** (EventID → event_type, e.g. 4625 → failed_login),
**Sysmon** operational events (EID 1 → process_start, 3 → network_connect …),
the three major clouds' audit logs — **AWS CloudTrail** (eventName →
event_type), **Microsoft Entra / Azure AD** sign-in + directory audit, and
**GCP Cloud Audit** (methodName → event_type); **endpoint EDR** — **CrowdStrike
Falcon** (event_simpleName / DetectionSummaryEvent) and **SentinelOne** (threat
alerts); **Microsoft 365** — **Defender for Endpoint** Advanced-Hunting
(ActionType) and the **Office 365 / M365 unified audit log** (Operation); and
**firewalls** — **Palo Alto PAN-OS** (TRAFFIC/THREAT) and **Fortinet FortiGate**
(JSON or key=value) — so e.g. a failed cloud/EDR/M365 sign-in lands as
failed_login, a new key as create_access_key, and an AV/IPS hit as
malware_detected / ips_alert across all of them. The two ubiquitous appliance
envelopes — **CEF** (ArcSight) and **LEEF** (IBM QRadar) — are decoded too
(header classification + extension field mapping). TLS syslog (RFC 5425) streams
in through the same pipeline (see `log_listeners.deframe_syslog`).

Every parser returns the same normalised event shape the rule engine reads:
{category, event_type, src_ip, dest_ip, dest_port, username, hostname,
 process_name, action, bytes_out, severity_hint, mitre_tech_id, raw}.
"""
import json
import logging
import re
import uuid
from datetime import datetime, timezone

from dashboard_api.db import get_conn

logger = logging.getLogger("dashboard_api.ingest")

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

# Microsoft Entra / Azure AD sign-in + audit categories.
_AAD_SIGNIN_CATEGORIES = {"signinlogs", "noninteractiveusersigninlogs",
                          "managedidentitysigninlogs", "serviceprincipalsigninlogs"}

# GCP Cloud Audit method (trailing segment) → normalised event_type.
_GCP_METHOD = {
    "CreateServiceAccountKey": ("create_access_key", "T1098.001"),
    "CreateServiceAccount": ("user_created", "T1136"),
    "SetIamPolicy": ("policy_change", "T1098"),
    "DeleteSink": ("log_cleared", "T1562.008"), "UpdateSink": ("log_cleared", "T1562.008"),
    "AccessSecretVersion": ("secret_access", "T1552.005"),
    "SetFirewallPolicy": ("firewall_change", "T1562.007"),
}


# Sysmon (Microsoft-Windows-Sysmon/Operational) EventID → event_type. Sysmon is
# the de-facto endpoint visibility source; its IDs and field names differ from
# the Security log, so it gets its own map.
_SYSMON_EVENTID = {
    1: ("process_start", "T1059"), 3: ("network_connect", None),
    7: ("image_load", "T1574"), 8: ("remote_thread", "T1055"),
    10: ("process_access", "T1003"), 11: ("file_create", None),
    12: ("registry_change", "T1112"), 13: ("registry_change", "T1112"),
    22: ("dns_query", "T1071.004"), 23: ("file_delete", "T1070.004"),
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


# Depth guard for _flatten: ECS/real documents nest a handful of levels; a
# pathologically deep object (crafted, or a buggy producer) must not exhaust the
# Python recursion stack. Beyond this depth we stop descending (the deep subtree
# is ignored for ECS mapping; the whole raw line is still stored via `raw`).
_MAX_FLATTEN_DEPTH = 64


def _flatten(obj: dict, prefix: str = "", _depth: int = 0) -> dict:
    """Flatten nested JSON to dotted keys: {"source": {"ip": x}} → {"source.ip": x}.
    This is how ECS documents arrive (Beats/Logstash emit nested objects)."""
    out: dict = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and _depth < _MAX_FLATTEN_DEPTH:
            out.update(_flatten(v, f"{key}.", _depth + 1))
        elif not isinstance(v, dict):
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


def _win_source(obj: dict) -> tuple[dict, dict]:
    """Merge the field-bearing layers of a Windows/Sysmon record (flat top-level,
    winlog.*, winlog.event_data.*) into one lookup dict; also return winlog."""
    winlog = obj.get("winlog") if isinstance(obj.get("winlog"), dict) else {}
    data = winlog.get("event_data") if isinstance(winlog.get("event_data"), dict) else {}
    return {**data, **winlog, **obj}, winlog


def _apply_sysmon(ev: dict, obj: dict) -> bool:
    """Recognise a Sysmon operational event and map it onto the native event.
    Returns True if it matched."""
    src, winlog = _win_source(obj)
    channel = str(src.get("Channel") or winlog.get("channel")
                  or src.get("provider_name") or winlog.get("provider_name") or "")
    if "sysmon" not in channel.lower():
        return False
    eid = src.get("EventID") or src.get("event_id") or winlog.get("event_id")
    try:
        eid = int(eid)
    except (ValueError, TypeError):
        return False

    def g(*keys):
        for k in keys:
            v = src.get(k)
            if v not in (None, "", "-"):
                return v
        return None

    et, mitre = _SYSMON_EVENTID.get(eid, (f"sysmon_{eid}", None))
    ev["event_type"], ev["category"] = et, "endpoint"
    if mitre:
        ev["mitre_tech_id"] = mitre
    img = g("Image", "SourceImage")
    if img:
        ev["process_name"] = str(img)
    host = g("Computer", "computer_name", "hostname")
    if host:
        ev["hostname"] = str(host)
    user = g("User", "SubjectUserName")
    if user:
        ev["username"] = str(user).split("\\")[-1]   # DOMAIN\\user → user
    sip = g("SourceIp")
    if sip and _is_ip(sip):
        ev["src_ip"] = str(sip)
    dip = g("DestinationIp")
    if dip and _is_ip(dip):
        ev["dest_ip"] = str(dip)
    dport = g("DestinationPort")
    if dport is not None:
        try:
            ev["dest_port"] = int(dport)
        except (ValueError, TypeError):
            pass
    return True


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


def _apply_azure_ad(ev: dict, obj: dict) -> bool:
    """Recognise a Microsoft Entra / Azure AD sign-in or audit record (as exported
    via Event Hub / Log Analytics) and map it. Returns True if it matched."""
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}
    category = str(obj.get("category") or "").lower()
    is_signin = category in _AAD_SIGNIN_CATEGORIES or "userPrincipalName" in props
    if not (is_signin or category == "auditlogs"):
        return False
    ev["category"] = "cloud_audit"
    if category == "auditlogs":
        activity = str(props.get("activityDisplayName") or obj.get("operationName") or "").lower()
        if "member" in activity and ("role" in activity or "group" in activity):
            ev["event_type"], ev["mitre_tech_id"] = "group_change", "T1098"
        else:
            ev["event_type"] = "cloud_audit"
        actor = (props.get("initiatedBy") or {}).get("user") if isinstance(props.get("initiatedBy"), dict) else None
        upn = (actor or {}).get("userPrincipalName") if isinstance(actor, dict) else None
        if upn:
            ev["username"] = str(upn)
        return True
    # sign-in: status.errorCode 0 = success
    status = props.get("status") if isinstance(props.get("status"), dict) else {}
    try:
        err = int(status.get("errorCode", 0))
    except (ValueError, TypeError):
        err = 0
    ev["event_type"] = "login_success" if err == 0 else "failed_login"
    if err != 0:
        ev["mitre_tech_id"] = "T1110"
    if props.get("userPrincipalName"):
        ev["username"] = str(props["userPrincipalName"])
    ip = props.get("ipAddress")
    if ip and _is_ip(ip):
        ev["src_ip"] = str(ip)
    loc = props.get("location") if isinstance(props.get("location"), dict) else {}
    if loc.get("countryOrRegion"):
        ev["country"] = str(loc["countryOrRegion"])
    return True


def _apply_gcp_audit(ev: dict, obj: dict) -> bool:
    """Recognise a GCP Cloud Audit Logging record and map it. Returns True if it
    matched."""
    proto = obj.get("protoPayload") if isinstance(obj.get("protoPayload"), dict) else {}
    log_name = str(obj.get("logName") or "")
    method = str(proto.get("methodName") or "")
    if not (method or "cloudaudit.googleapis.com" in log_name):
        return False
    ev["category"] = "cloud_audit"
    et, mitre = _GCP_METHOD.get(method.rsplit(".", 1)[-1], ("cloud_audit", None))
    ev["event_type"] = et
    if mitre:
        ev["mitre_tech_id"] = mitre
    auth = proto.get("authenticationInfo") if isinstance(proto.get("authenticationInfo"), dict) else {}
    if auth.get("principalEmail"):
        ev["username"] = str(auth["principalEmail"])
    meta = proto.get("requestMetadata") if isinstance(proto.get("requestMetadata"), dict) else {}
    ip = meta.get("callerIp")
    if ip and _is_ip(ip):
        ev["src_ip"] = str(ip)
    status = proto.get("status") if isinstance(proto.get("status"), dict) else {}
    if status.get("code"):  # gRPC status: 0/absent = OK, non-zero = error/denied
        ev["action"] = "deny"
    return True


# ── CrowdStrike Falcon (Streaming API / FDR) ──
# event_simpleName keys most telemetry; DetectionSummaryEvent carries the
# detection verdict. Mapped onto the native endpoint/network/auth vocabulary.
_CS_SEV = {"critical": "critical", "high": "high", "medium": "medium",
           "low": "low", "informational": "info", "info": "info"}
_CROWDSTRIKE_SIMPLENAME = {
    "ProcessRollup2": ("process_start", "endpoint", "medium", "T1059"),
    "SyntheticProcessRollup2": ("process_start", "endpoint", "medium", "T1059"),
    "DnsRequest": ("dns_query", "network", "low", "T1071.004"),
    "NetworkConnectIP4": ("network_connect", "network", "low", None),
    "NetworkReceiveAcceptIP4": ("network_connect", "network", "low", None),
    "UserLogonFailed2": ("failed_login", "auth", "high", "T1110"),
    "UserLogon": ("login_success", "auth", "low", "T1078"),
    "UserLogon2": ("login_success", "auth", "low", "T1078"),
}

# ── Microsoft 365 Defender / Defender for Endpoint (Advanced Hunting) ──
# Every Advanced-Hunting row is keyed by ActionType across the Device* tables.
_DEFENDER_ACTIONTYPE = {
    "LogonFailed": ("failed_login", "auth", "high", "T1110"),
    "LogonSuccess": ("login_success", "auth", "low", "T1078"),
    "ProcessCreated": ("process_start", "endpoint", "medium", "T1059"),
    "CreateProcess": ("process_start", "endpoint", "medium", "T1059"),
    "ProcessCreatedUsingWmiQuery": ("process_start", "endpoint", "high", "T1047"),
    "PowerShellCommand": ("process_start", "endpoint", "high", "T1059.001"),
    "ConnectionSuccess": ("network_connect", "network", "low", None),
    "ConnectionRequest": ("network_connect", "network", "low", None),
    "DnsQueryResponse": ("dns_query", "network", "low", "T1071.004"),
    "AntivirusDetection": ("malware_detected", "endpoint", "critical", "T1204"),
    "AntivirusReport": ("malware_detected", "endpoint", "critical", "T1204"),
    "SmartScreenUrlWarning": ("malware_detected", "endpoint", "high", "T1204"),
    "FileCreated": ("file_create", "endpoint", "low", None),
    "RegistryValueSet": ("registry_change", "endpoint", "low", "T1112"),
}

# ── Microsoft 365 / Office 365 Unified Audit Log (Management Activity API) ──
# Keyed by Operation across Workloads (AzureActiveDirectory, Exchange, …).
_M365_OPERATION = {
    "UserLoggedIn": ("login_success", "auth", "low", "T1078"),
    "UserLoginFailed": ("failed_login", "auth", "high", "T1110"),
    "Add member to role.": ("group_change", "identity", "high", "T1098"),
    "Add member to group.": ("group_change", "identity", "medium", "T1098"),
    "New-InboxRule": ("mailbox_rule", "email", "high", "T1114.003"),
    "Set-InboxRule": ("mailbox_rule", "email", "high", "T1114.003"),
    "UpdateInboxRules": ("mailbox_rule", "email", "high", "T1114.003"),
    "Add-MailboxPermission": ("mailbox_permission", "email", "high", "T1098.002"),
    "FileDownloaded": ("file_download", "cloud", "low", "T1567.002"),
    "FileDeleted": ("file_delete", "cloud", "low", "T1485"),
    "Add service principal.": ("app_registration", "identity", "high", "T1098.001"),
    "Add application.": ("app_registration", "identity", "high", "T1098.001"),
    "Consent to application.": ("app_consent", "identity", "high", "T1528"),
    "Disable Strong Authentication.": ("mfa_disabled", "identity", "high", "T1556.006"),
}

# ── Palo Alto PAN-OS THREAT subtype → native type ──
_PANOS_SUBTYPE = {
    "vulnerability": ("ips_alert", "high", "T1190"),
    "spyware": ("malware_detected", "high", "T1071"),
    "virus": ("malware_detected", "critical", "T1204"),
    "wildfire": ("malware_detected", "critical", "T1204"),
    "wildfire-virus": ("malware_detected", "critical", "T1204"),
    "file": ("ips_alert", "medium", "T1190"),
    "flood": ("ips_alert", "high", "T1498"),
    "scan": ("port_scan", "medium", "T1046"),
}

_FW_DENY = ("deny", "drop", "blocked", "block", "reset", "reset-both",
            "reset-client", "reset-server", "close")


def _apply_crowdstrike(ev: dict, obj: dict) -> bool:
    """CrowdStrike Falcon Streaming-API record: {"metadata": {"eventType": …},
    "event": {…}} - or a flattened event carrying event_simpleName. Maps it onto
    the native vocabulary. Returns True if matched."""
    meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    event = obj.get("event") if isinstance(obj.get("event"), dict) else {}
    etype = str(meta.get("eventType") or "")
    src = {**event, **obj}              # event sub-object, with envelope fallback
    simple = src.get("event_simpleName") or src.get("EventSimpleName")
    if not etype and not simple:
        return False

    def g(*keys):
        for k in keys:
            v = src.get(k)
            if v not in (None, "", "-"):
                return v
        return None

    if etype == "DetectionSummaryEvent" or src.get("DetectName") or src.get("Technique"):
        ev["event_type"], ev["category"], ev["severity_hint"] = "malware_detected", "endpoint", "critical"
        tid = g("TechniqueId")
        ev["mitre_tech_id"] = str(tid) if tid and re.match(r"T\d{4}", str(tid)) else "T1204"
        sev = g("SeverityName", "Severity")
        if sev:
            ev["severity_hint"] = _CS_SEV.get(str(sev).lower(), "high")
    elif simple:
        et, cat, sev, mitre = _CROWDSTRIKE_SIMPLENAME.get(
            str(simple), (f"falcon_{simple}".lower(), "endpoint", "info", None))
        ev["event_type"], ev["category"], ev["severity_hint"] = et, cat, sev
        if mitre:
            ev["mitre_tech_id"] = mitre
    elif etype == "AuthActivityAuditEvent":
        ev["event_type"], ev["category"] = "login_success", "auth"
        if "fail" in str(g("OperationName") or "").lower():
            ev["event_type"], ev["mitre_tech_id"], ev["severity_hint"] = "failed_login", "T1110", "high"
    else:
        ev["event_type"], ev["category"] = (f"falcon_{etype}".lower() if etype else "falcon_event"), "endpoint"

    host = g("ComputerName", "Hostname", "hostname")
    if host:
        ev["hostname"] = str(host)
    user = g("UserName", "UserPrincipal", "AccountName")
    if user:
        ev["username"] = str(user).split("\\")[-1]
    proc = g("FileName", "ImageFileName", "CommandLine")
    if proc:
        ev["process_name"] = str(proc)
    rip = g("RemoteAddressIP4", "RemoteIP", "RemoteAddress")
    if rip and _is_ip(rip):
        ev["dest_ip"] = str(rip)
    lip = g("LocalAddressIP4", "LocalIP")
    if lip and _is_ip(lip):
        ev["src_ip"] = str(lip)
    rport = g("RemotePort")
    if rport is not None:
        try:
            ev["dest_port"] = int(rport)
        except (ValueError, TypeError):
            pass
    return True


def _apply_sentinelone(ev: dict, obj: dict) -> bool:
    """SentinelOne threat / Deep-Visibility alert - distinctive nested objects
    threatInfo / agentRealtimeInfo / agentDetectionInfo. Returns True if matched."""
    ti = obj.get("threatInfo") if isinstance(obj.get("threatInfo"), dict) else {}
    rt = obj.get("agentRealtimeInfo") if isinstance(obj.get("agentRealtimeInfo"), dict) else {}
    di = obj.get("agentDetectionInfo") if isinstance(obj.get("agentDetectionInfo"), dict) else {}
    if not (ti or rt or di):
        return False
    classification = str(ti.get("classification") or "").lower()
    ev["category"] = "endpoint"
    if "ransom" in classification:
        ev["event_type"], ev["severity_hint"], ev["mitre_tech_id"] = "malware_detected", "critical", "T1486"
    elif "malware" in classification or "trojan" in classification or ti.get("threatName"):
        ev["event_type"], ev["severity_hint"], ev["mitre_tech_id"] = "malware_detected", "critical", "T1204"
    else:
        ev["event_type"], ev["severity_hint"] = "edr_alert", "high"
    host = rt.get("agentComputerName") or di.get("agentComputerName") or obj.get("agentComputerName")
    if host:
        ev["hostname"] = str(host)
    user = di.get("agentLastLoggedInUserName") or rt.get("agentLastLoggedInUserName")
    if user:
        ev["username"] = str(user).split("\\")[-1]
    proc = ti.get("processName") or ti.get("threatName") or obj.get("sourceProcessName")
    if proc:
        ev["process_name"] = str(proc)
    ip = di.get("externalIp") or rt.get("externalIp")
    if ip and _is_ip(ip):
        ev["src_ip"] = str(ip)
    return True


def _apply_m365_defender(ev: dict, obj: dict) -> bool:
    """Microsoft 365 Defender / Defender for Endpoint Advanced-Hunting record
    (DeviceLogonEvents, DeviceProcessEvents, DeviceNetworkEvents, …), keyed by
    ActionType. Returns True if matched."""
    action_type = obj.get("ActionType")
    if not action_type:
        return False
    # ActionType alone is generic; require a Defender device/AH companion field.
    if not any(k in obj for k in ("DeviceName", "DeviceId", "ReportId",
                                  "InitiatingProcessFileName", "InitiatingProcessAccountName")):
        return False
    et, cat, sev, mitre = _DEFENDER_ACTIONTYPE.get(
        str(action_type), (f"defender_{action_type}".lower(), "endpoint", "info", None))
    ev["event_type"], ev["category"], ev["severity_hint"] = et, cat, sev
    if mitre:
        ev["mitre_tech_id"] = mitre

    def g(*keys):
        for k in keys:
            v = obj.get(k)
            if v not in (None, "", "-"):
                return v
        return None

    host = g("DeviceName", "DeviceId")
    if host:
        ev["hostname"] = str(host)
    user = g("AccountName", "AccountUpn", "InitiatingProcessAccountName", "InitiatingProcessAccountUpn")
    if user:
        ev["username"] = str(user).split("\\")[-1]
    proc = g("FileName", "InitiatingProcessFileName")
    if proc:
        ev["process_name"] = str(proc)
    rip = g("RemoteIP")
    if et == "network_connect":
        if rip and _is_ip(rip):
            ev["dest_ip"] = str(rip)
        lip = g("LocalIP")
        if lip and _is_ip(lip):
            ev["src_ip"] = str(lip)
        rport = g("RemotePort")
        if rport is not None:
            try:
                ev["dest_port"] = int(rport)
            except (ValueError, TypeError):
                pass
    elif rip and _is_ip(rip):       # logon / process: RemoteIP is the origin
        ev["src_ip"] = str(rip)
    return True


def _apply_m365_audit(ev: dict, obj: dict) -> bool:
    """Microsoft 365 / Office 365 unified-audit-log record (Management Activity
    API), keyed by Operation across Workloads. Returns True if matched."""
    op = obj.get("Operation")
    if not op:
        return False
    if not any(k in obj for k in ("Workload", "RecordType", "OrganizationId", "UserKey", "ResultStatus")):
        return False
    et, cat, sev, mitre = _M365_OPERATION.get(str(op), ("m365_audit", "cloud", "info", None))
    if str(obj.get("ResultStatus") or "").lower() in ("failed", "failure") and et == "login_success":
        et, sev, mitre = "failed_login", "high", "T1110"
    ev["event_type"], ev["category"], ev["severity_hint"] = et, cat, sev
    if mitre:
        ev["mitre_tech_id"] = mitre
    user = obj.get("UserId") or obj.get("UserKey")
    if user:
        ev["username"] = str(user)
    ip = obj.get("ClientIP") or obj.get("ClientIPAddress") or obj.get("ActorIpAddress")
    if ip:
        m = _IPV4.search(str(ip))       # M365 ClientIP often carries :port / brackets
        if m:
            ev["src_ip"] = m.group(0)
    return True


def _fortigate_classify(ev: dict, type_, subtype, action) -> None:
    """Map a FortiGate log's type/subtype/action onto the native vocabulary."""
    t, st, act = (type_ or "").lower(), (subtype or "").lower(), (action or "").lower()
    if "virus" in (t, st):
        ev["event_type"], ev["category"], ev["severity_hint"], ev["mitre_tech_id"] = \
            "malware_detected", "network", "critical", "T1204"
    elif t in ("utm", "attack", "ips", "anomaly"):
        ev["event_type"], ev["category"], ev["severity_hint"], ev["mitre_tech_id"] = \
            "ips_alert", "network", "high", ("T1498" if st == "anomaly" else "T1190")
    elif t in ("traffic", "forward", "local"):
        denied = act in _FW_DENY
        ev["event_type"] = "firewall_deny" if denied else "firewall_allow"
        ev["category"], ev["severity_hint"] = "network", ("low" if denied else "info")
    else:
        ev["event_type"], ev["category"] = "firewall_log", "network"
    if act:
        ev["action"] = "deny" if act in _FW_DENY else "allow"


def _apply_firewall(ev: dict, obj: dict) -> bool:
    """Palo Alto PAN-OS or Fortinet FortiGate firewall log exported as JSON.
    Returns True if matched. (FortiGate key=value syslog is handled in _parse_kv.)"""
    # FortiGate uses srcip/dstip/devname; PAN-OS uses src/dst. Keep them distinct
    # so a PAN-OS TRAFFIC log (which carries "src") is not mis-routed to Fortinet.
    forti = ("devname" in obj or "devid" in obj or "logid" in obj or
             (str(obj.get("type") or "").lower() in
              ("traffic", "utm", "attack", "virus", "anomaly", "forward", "local")
              and "srcip" in obj))
    pa_type = str(obj.get("type") or obj.get("log_type") or "").upper()
    panos = (pa_type in ("TRAFFIC", "THREAT") and
             any(k in obj for k in ("sessionid", "threatid", "serial", "vsys",
                                    "app", "rule", "subtype", "devicename")))
    if not (forti or panos):
        return False

    def g(*keys):
        for k in keys:
            v = obj.get(k)
            if v not in (None, "", "-"):
                return v
        return None

    if panos and not forti:
        subtype = str(g("subtype") or "").lower()
        action = str(g("action") or "").lower()
        if pa_type == "THREAT":
            et, sev, mitre = _PANOS_SUBTYPE.get(subtype, ("ips_alert", "high", "T1190"))
            ev["event_type"], ev["category"], ev["severity_hint"], ev["mitre_tech_id"] = et, "network", sev, mitre
        else:
            denied = action in _FW_DENY
            ev["event_type"] = "firewall_deny" if denied else "firewall_allow"
            ev["category"], ev["severity_hint"] = "network", ("low" if denied else "info")
        if action:
            ev["action"] = "deny" if action in _FW_DENY else "allow"
        sip, dip = g("src", "srcip", "source"), g("dst", "dstip", "destination")
        dport = g("dport", "dstport")
        user = g("srcuser", "source_user", "user")
    else:
        _fortigate_classify(ev, g("type"), g("subtype"), g("action"))
        sip, dip = g("srcip", "src"), g("dstip", "dst")
        dport = g("dstport", "dport")
        user = g("user", "srcuser", "unauthuser")
    if sip and _is_ip(sip):
        ev["src_ip"] = str(sip)
    if dip and _is_ip(dip):
        ev["dest_ip"] = str(dip)
    if dport is not None:
        try:
            ev["dest_port"] = int(dport)
        except (ValueError, TypeError):
            pass
    if user:
        ev["username"] = str(user)
    host = g("devname", "devicename", "dvc")
    if host:
        ev["hostname"] = str(host)
    return True


def _parse_json(line: str) -> dict | None:
    try:
        obj = json.loads(line)
    except (ValueError, TypeError, RecursionError):
        # RecursionError: a deeply-nested JSON line exceeds the decoder's stack.
        # Treat it as unparseable JSON (falls through to a generic log event)
        # rather than letting it escape and abort the whole ingest batch.
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
    # Source-specific shapes map their distinctive fields authoritatively onto
    # the native vocabulary, so the same detection rules fire on them. First
    # match wins; discriminators are tight so generic JSON falls through to the
    # ECS/heuristic handling below. Order: most-specific envelopes first,
    # broad-discriminator firewall logs last.
    (_apply_sysmon(ev, obj) or _apply_windows(ev, obj)
     or _apply_crowdstrike(ev, obj) or _apply_sentinelone(ev, obj)
     or _apply_m365_defender(ev, obj) or _apply_m365_audit(ev, obj)
     or _apply_cloudtrail(ev, obj) or _apply_azure_ad(ev, obj) or _apply_gcp_audit(ev, obj)
     or _apply_firewall(ev, obj))
    # ECS documents (nested or dotted keys) normalise at ingest time too.
    # Entity fields still holding only the raw-line regex guess are "weak" -
    # the producer's ECS values are authoritative over them.
    weak = {k for k in ("src_ip", "dest_ip", "username", "hostname")
            if ev.get(k) is not None and ev[k] == base.get(k)}
    _apply_ecs(ev, obj, weak)
    return ev


def _parse_kv(line: str) -> dict:
    ev = _base_event(line)
    # Collect every key=value pair first (quoted values may contain spaces, as
    # FortiGate's msg="..." does), then map.
    fields = {m.group(1).lower(): m.group(2).strip('"')
              for m in re.finditer(r'(\w+)=("[^"]*"|[^\s]+)', line)}
    for k, v in fields.items():
        if k in ("src", "src_ip", "srcip", "client"):
            ev["src_ip"] = v
        elif k in ("dst", "dest_ip", "dstip"):
            ev["dest_ip"] = v
        elif k in ("user", "username", "account", "srcuser"):
            ev["username"] = v
        elif k in ("host", "hostname", "computer", "devname"):
            ev["hostname"] = v
        elif k in ("dport", "dest_port", "port", "dstport"):
            try:
                ev["dest_port"] = int(v)
            except ValueError:
                pass
        elif k in ("bytes_out", "bytes_sent", "sentbyte"):
            try:
                ev["bytes_out"] = int(v)
            except ValueError:
                pass
    # FortiGate key=value syslog: classify by type/subtype/action so a denied
    # session / IPS / AV hit lands on the native vocabulary the rules read.
    if ("devname" in fields or "devid" in fields or "logid" in fields or
            (fields.get("type") in ("traffic", "utm", "attack", "virus", "anomaly")
             and "srcip" in fields)):
        _fortigate_classify(ev, fields.get("type"), fields.get("subtype"), fields.get("action"))
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


# ── CEF (ArcSight) and LEEF (IBM QRadar) - the two ubiquitous appliance envelopes ──
_CEF_KV = re.compile(r"([A-Za-z][A-Za-z0-9_.]*)=(.*?)(?=(?:\s+[A-Za-z][A-Za-z0-9_.]*=)|$)")
_WORD_SEV = {"low": "low", "medium": "medium", "high": "high",
             "very-high": "critical", "critical": "critical", "unknown": "info"}


def _sev_norm(s) -> str | None:
    """Normalise a numeric (0-10) or word severity onto our scale; None if absent."""
    if s in (None, ""):
        return None
    sl = str(s).strip().lower()
    if sl in _WORD_SEV:
        return _WORD_SEV[sl]
    try:
        v = int(float(sl))
    except (ValueError, TypeError):
        return None
    return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"


def _cef_split(body: str) -> list[str]:
    """Split a CEF body into 7 header fields + the extension (≤8 parts), honouring
    backslash escapes; pipes after the 7th are literal (part of the extension)."""
    out, cur, i, n = [], [], 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            cur.append(body[i + 1]); i += 2; continue
        if c == "|" and len(out) < 7:
            out.append("".join(cur)); cur = []; i += 1; continue
        cur.append(c); i += 1
    out.append("".join(cur))
    return out


def _cef_ext(ext: str) -> dict:
    return {m.group(1): m.group(2).replace("\\=", "=").replace("\\\\", "\\")
            for m in _CEF_KV.finditer(ext)}


def _apply_envelope(ev: dict, name_text: str, sev_raw, f: dict, fallback_type: str,
                    fallback_cat: str, field_map: dict) -> None:
    """Shared CEF/LEEF mapping: classify by the human name via the content
    signatures (so an auth-failure envelope still feeds the brute-force rule),
    apply the device severity, then map the extension fields → native event."""
    et, cat, sev, mitre = _infer(name_text)
    if et == "log":
        ev["event_type"], ev["category"] = fallback_type, fallback_cat
    else:
        ev["event_type"], ev["category"], ev["mitre_tech_id"] = et, cat, mitre
        ev["severity_hint"] = sev
    sv = _sev_norm(sev_raw)
    if sv:
        ev["severity_hint"] = sv

    def g(*keys):
        for k in keys:
            v = f.get(k)
            if v not in (None, ""):
                return v
        return None

    sip = g(*field_map["src"])
    if sip and _is_ip(sip):
        ev["src_ip"] = str(sip)
    dip = g(*field_map["dst"])
    if dip and _is_ip(dip):
        ev["dest_ip"] = str(dip)
    user = g(*field_map["user"])
    if user:
        ev["username"] = str(user)
    host = g(*field_map["host"])
    if host:
        ev["hostname"] = str(host)
    dpt = g(*field_map["dport"])
    if dpt is not None:
        try:
            ev["dest_port"] = int(dpt)
        except (ValueError, TypeError):
            pass
    act = g(*field_map["act"])
    if act:
        ev["action"] = "deny" if str(act).lower() in _FW_DENY else str(act).lower()
    if "proc" in field_map:
        proc = g(*field_map["proc"])
        if proc:
            ev["process_name"] = str(proc)


def _parse_cef(line: str) -> dict | None:
    """ArcSight CEF: ``CEF:Ver|Vendor|Product|Ver|SigID|Name|Severity|extension``."""
    if not line.startswith("CEF:"):
        return None
    parts = _cef_split(line[4:])
    if len(parts) < 7:
        return None
    name, severity = parts[5], parts[6]
    f = _cef_ext(parts[7] if len(parts) > 7 else "")
    ev = _base_event(line)
    _apply_envelope(ev, f"{name} {f.get('msg', '')}", severity, f, "cef_event", "cef", {
        "src": ("src", "sourceAddress"), "dst": ("dst", "destinationAddress"),
        "user": ("suser", "sourceUserName", "duser", "destinationUserName"),
        "host": ("shost", "sourceHostName", "dhost", "destinationHostName", "dvchost"),
        "dport": ("dpt", "destinationPort"), "act": ("act", "deviceAction"),
        "proc": ("fname", "deviceProcessName", "sproc"),
    })
    return ev


def _leef_delim(spec: str) -> str:
    spec = (spec or "").strip()
    if spec.lower().startswith("0x"):
        try:
            return chr(int(spec, 16))
        except ValueError:
            return "\t"
    if spec in ("\\t", "tab", ""):
        return "\t"
    return spec


def _parse_leef(line: str) -> dict | None:
    """IBM QRadar LEEF: ``LEEF:Ver|Vendor|Product|Ver|EventID|[Delim|]extension``.
    1.0 defaults to a tab delimiter; 2.0 declares it in the 6th header field."""
    if not line.startswith("LEEF:"):
        return None
    parts = line.split("|")
    if len(parts) < 6:
        return None
    ver = parts[0][5:].strip()
    if ver.startswith("2") and len(parts) >= 7:
        delim, ext = _leef_delim(parts[5]), "|".join(parts[6:])
    else:
        delim, ext = "\t", "|".join(parts[5:])
    event_id = parts[4]
    chunks = ext.split(delim) if delim in ext else re.split(r"\t|\s{2,}", ext)
    f = {}
    for pair in chunks:
        if "=" in pair:
            k, v = pair.split("=", 1)
            f[k.strip()] = v.strip()
    ev = _base_event(line)
    _apply_envelope(ev, f"{event_id} {f.get('cat', '')} {f.get('msg', '')}",
                    f.get("sev") or f.get("severity"), f, "leef_event",
                    (f.get("cat") or "leef"), {
                        "src": ("src", "srcIP"), "dst": ("dst", "dstIP"),
                        "user": ("usrName", "user", "srcUserName"),
                        "host": ("identHostName", "srcHostName", "dstHostName"),
                        "dport": ("dstPort", "dstport"), "act": ("action", "act"),
                    })
    return ev


def parse_line(line: str, fmt: str = "auto") -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if fmt in ("json", "auto") and line[:1] in "{[":
        ev = _parse_json(line)
        if ev:
            return ev
    # CEF/LEEF envelopes must be tried before the key=value path (they contain
    # "key=value" pairs that would otherwise be mis-parsed as generic kv).
    if fmt in ("cef", "auto") and line.startswith("CEF:"):
        ev = _parse_cef(line)
        if ev:
            return ev
    if fmt in ("leef", "auto") and line.startswith("LEEF:"):
        ev = _parse_leef(line)
        if ev:
            return ev
    if fmt in ("apache", "nginx", "auto"):
        ev = _parse_apache(line)
        if ev:
            return ev
    if fmt == "kv" or (fmt == "auto" and "=" in line and " " in line):
        return _parse_kv(line)
    return _base_event(line)


def ingest_lines(lines: list[str], fmt: str = "auto", source: str = "collector",
                 org_id: str = "org-default") -> dict:
    """Parse lines → events → run detection. Returns {ingested, parsed, alerts}.

    `org_id` stamps the events with the ingesting principal's workspace, so under
    multi-tenancy the alerts they trigger land in that tenant (per-org ingest
    context). The default workspace is used by deployment-level collectors (the
    syslog/file listeners) and single-tenant installs."""
    from dashboard_api import redaction
    from dashboard_api.engine import run_detection, seed_builtin_rules
    seed_builtin_rules()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    parsed = 0
    skipped = 0
    # Parsing stays per-line (one bad/crafted line must never abort the whole
    # batch), but the INSERT itself is collected and issued once via
    # executemany: a Python loop of individual conn.execute() calls is fine on
    # SQLite's in-process file access, but on Postgres every row pays a real
    # client<->server round trip - measured ~6x faster batched this way
    # (dashboard_api/bench.py against DASHBOARD_DB_BACKEND=postgres). No
    # per-row isolation is lost: by this point each row is already
    # known-parseable structured data (the try/except above is what actually
    # guards against malformed input), and executemany fails atomically for
    # the whole statement exactly like the previous per-row loop already did
    # under one transaction (a mid-loop failure previously left a partial
    # insert too - this doesn't change that behaviour, only the round trips).
    rows: list[tuple] = []
    with get_conn() as conn:
        for line in lines:
            try:
                ev = parse_line(line, fmt)
            except Exception:
                # A single malformed/crafted line must never abort the whole
                # batch — that would drop every other forwarded line in the POST
                # and 500 the ingest endpoint. Skip it; the rest still ingest.
                logger.warning("skipping unparseable ingest line", exc_info=True)
                skipped += 1
                continue
            if ev is None:
                continue
            # Opt-in PII/secret redaction of the raw text before it persists
            # (no-op unless DASHBOARD_LOG_REDACT is set; pivots stay intact).
            ev["raw"] = redaction.redact(ev.get("raw"))
            rows.append((str(uuid.uuid4()), now, ev.get("category"), ev.get("event_type"),
                        ev.get("src_ip"), ev.get("dest_ip"), ev.get("dest_port"), ev.get("username"),
                        ev.get("hostname"), ev.get("process_name"), ev.get("action"),
                        ev.get("bytes_out", 0), ev.get("country"), ev.get("severity_hint"),
                        ev.get("mitre_tech_id"), ev.get("raw"), source, org_id))
            parsed += 1
        if rows:
            conn.executemany(
                "INSERT INTO events (id,ts,category,event_type,src_ip,dest_ip,dest_port,username,"
                "hostname,process_name,action,bytes_out,country,severity_hint,mitre_tech_id,raw,"
                "source,processed,org_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
                rows)
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
    return {"ingested": len(lines), "parsed": parsed, "skipped": skipped,
            "alerts": det["alerts"] + ti, "tiMatches": ti, "source": source}


def match_threat_intel(conn) -> int:
    """First-class TI detection: any event whose src/dest IP or hostname matches
    a known malicious IOC raises an enriched 'threat intel match' alert."""
    from dashboard_api.detections import alert_from_intel
    rows = conn.execute(
        "SELECT id, src_ip, dest_ip, hostname, org_id FROM events WHERE processed IN (0,1) "
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
                                   source=ioc["source"] or "CTI",
                                   org_id=e["org_id"] or "org-default")
            conn.execute("UPDATE alerts SET rule_id='R-TIMATCH' WHERE id=?", (aid,))
            raised += 1
            seen.add(val)
    return raised
