"""Source breadth: high-value vendor shapes normalise onto the native event
vocabulary at ingest, so the same detection rules fire on them - Windows
Security, Sysmon, the three clouds (CloudTrail / Entra / GCP), endpoint EDR
(CrowdStrike Falcon, SentinelOne), Microsoft 365 (Defender AH + Office audit),
and firewalls (Palo Alto PAN-OS, Fortinet FortiGate). Plus RFC 5425 (TLS
syslog) stream deframing.
"""
import json
import uuid

from dashboard_api.db import get_conn
from dashboard_api.ingest import parse_line
from dashboard_api.log_listeners import deframe_syslog


def test_windows_security_events_map_to_native_vocab():
    e = parse_line(json.dumps({"EventID": 4625, "Computer": "WIN-01", "TargetUserName": "bob",
                               "IpAddress": "203.0.113.9", "Channel": "Security"}))
    assert e["event_type"] == "failed_login" and e["username"] == "bob"
    assert e["src_ip"] == "203.0.113.9" and e["hostname"] == "WIN-01" and e["mitre_tech_id"] == "T1110"

    # winlogbeat-style nested shape, privileged group membership change
    e = parse_line(json.dumps({"winlog": {"event_id": 4732, "computer_name": "WIN-01",
                                          "event_data": {"TargetUserName": "svc"}}}))
    assert e["event_type"] == "group_change" and e["username"] == "svc"

    # process creation
    e = parse_line(json.dumps({"EventID": 4688, "Computer": "WIN-02",
                               "NewProcessName": r"C:\Windows\System32\cmd.exe", "Channel": "Security"}))
    assert e["event_type"] == "process_start" and e["process_name"].endswith("cmd.exe")

    # arbitrary JSON that merely carries an EventID is NOT hijacked as Windows
    e = parse_line(json.dumps({"EventID": 1, "message": "hello", "src_ip": "10.0.0.1"}))
    assert e["event_type"] != "windows_1" and e["src_ip"] == "10.0.0.1"


def test_sysmon_events_map_to_native_vocab():
    # EID 1 process create (winlog/Beats nesting), DOMAIN\\user is trimmed
    e = parse_line(json.dumps({"winlog": {"channel": "Microsoft-Windows-Sysmon/Operational",
                                          "event_id": 1, "computer_name": "WS-01",
                                          "event_data": {"Image": r"C:\Windows\System32\powershell.exe",
                                                         "User": r"CORP\alice"}}}))
    assert e["event_type"] == "process_start" and e["category"] == "endpoint"
    assert e["process_name"].endswith("powershell.exe") and e["username"] == "alice"
    assert e["hostname"] == "WS-01" and e["mitre_tech_id"] == "T1059"

    # EID 3 network connect (raw shape) - src/dest/port mapped
    e = parse_line(json.dumps({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3,
                               "Computer": "WS-01", "Image": r"C:\evil.exe",
                               "SourceIp": "10.0.0.5", "DestinationIp": "203.0.113.50",
                               "DestinationPort": "4444"}))
    assert e["event_type"] == "network_connect" and e["dest_ip"] == "203.0.113.50"
    assert e["dest_port"] == 4444 and e["src_ip"] == "10.0.0.5"

    # A plain Security record (no Sysmon channel) is NOT captured by the Sysmon path
    e = parse_line(json.dumps({"EventID": 4625, "Computer": "DC-01", "TargetUserName": "bob",
                               "IpAddress": "203.0.113.9", "Channel": "Security"}))
    assert e["event_type"] == "failed_login" and e["category"] == "windows"


def test_cloudtrail_records_map_to_native_vocab():
    e = parse_line(json.dumps({"eventVersion": "1.08", "eventSource": "iam.amazonaws.com",
                               "eventName": "CreateAccessKey", "sourceIPAddress": "198.51.100.7",
                               "userIdentity": {"type": "IAMUser", "userName": "alice",
                                                "arn": "arn:aws:iam::123:user/alice"},
                               "awsRegion": "us-east-1"}))
    assert e["event_type"] == "create_access_key" and e["username"] == "alice"
    assert e["src_ip"] == "198.51.100.7" and e["category"] == "cloud_audit" and e["mitre_tech_id"] == "T1098.001"

    # console-login failure -> failed_login; a service-principal "source IP" is dropped
    e = parse_line(json.dumps({"eventVersion": "1.08", "eventSource": "signin.amazonaws.com",
                               "eventName": "ConsoleLogin", "sourceIPAddress": "cloudtrail.amazonaws.com",
                               "responseElements": {"ConsoleLogin": "Failure"},
                               "userIdentity": {"userName": "eve"}}))
    assert e["event_type"] == "failed_login" and e["username"] == "eve" and e["src_ip"] is None


def test_azure_ad_records_map_to_native_vocab():
    # failed interactive sign-in
    e = parse_line(json.dumps({"category": "SignInLogs",
                               "properties": {"userPrincipalName": "alice@corp.com",
                                              "ipAddress": "203.0.113.5",
                                              "status": {"errorCode": 50126},
                                              "location": {"countryOrRegion": "US"}}}))
    assert e["event_type"] == "failed_login" and e["username"] == "alice@corp.com"
    assert e["src_ip"] == "203.0.113.5" and e["country"] == "US" and e["mitre_tech_id"] == "T1110"

    # successful sign-in (errorCode 0)
    e = parse_line(json.dumps({"category": "SignInLogs",
                               "properties": {"userPrincipalName": "bob@corp.com",
                                              "status": {"errorCode": 0}}}))
    assert e["event_type"] == "login_success"

    # directory audit: add member to a role → group_change
    e = parse_line(json.dumps({"category": "AuditLogs",
                               "properties": {"activityDisplayName": "Add member to role",
                                              "initiatedBy": {"user": {"userPrincipalName": "adm@corp.com"}}}}))
    assert e["event_type"] == "group_change" and e["username"] == "adm@corp.com"

    # generic JSON carrying a 'category' is not hijacked as Azure
    e = parse_line(json.dumps({"category": "web", "message": "hello", "src_ip": "10.0.0.1"}))
    assert e["event_type"] != "failed_login" and e["src_ip"] == "10.0.0.1"


def test_gcp_audit_records_map_to_native_vocab():
    e = parse_line(json.dumps({"protoPayload": {
        "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
        "authenticationInfo": {"principalEmail": "svc@proj.iam"},
        "requestMetadata": {"callerIp": "198.51.100.7"}, "status": {"code": 0}},
        "logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity"}))
    assert e["event_type"] == "create_access_key" and e["username"] == "svc@proj.iam"
    assert e["src_ip"] == "198.51.100.7" and e["category"] == "cloud_audit" and e["mitre_tech_id"] == "T1098.001"

    # denied SetIamPolicy → policy_change + action deny
    e = parse_line(json.dumps({"protoPayload": {
        "methodName": "google.cloud.resourcemanager.v1.SetIamPolicy",
        "authenticationInfo": {"principalEmail": "eve@x"},
        "requestMetadata": {"callerIp": "10.0.0.9"}, "status": {"code": 7}}}))
    assert e["event_type"] == "policy_change" and e["action"] == "deny"


def test_crowdstrike_falcon_records_map_to_native_vocab():
    # Streaming-API envelope: failed user logon (event_simpleName)
    e = parse_line(json.dumps({"metadata": {"eventType": "EpDetectionEvent"},
                               "event": {"event_simpleName": "UserLogonFailed2", "ComputerName": "WS-9",
                                         "UserName": r"CORP\bob"}}))
    assert e["event_type"] == "failed_login" and e["username"] == "bob"
    assert e["hostname"] == "WS-9" and e["category"] == "auth" and e["mitre_tech_id"] == "T1110"

    # DetectionSummaryEvent → malware_detected, technique + severity + IP mapped
    e = parse_line(json.dumps({"metadata": {"eventType": "DetectionSummaryEvent"},
                               "event": {"ComputerName": "WS-1", "UserName": "alice", "FileName": "evil.exe",
                                         "TechniqueId": "T1059", "SeverityName": "Critical",
                                         "LocalAddressIP4": "10.1.1.1"}}))
    assert e["event_type"] == "malware_detected" and e["severity_hint"] == "critical"
    assert e["mitre_tech_id"] == "T1059" and e["process_name"] == "evil.exe" and e["src_ip"] == "10.1.1.1"

    # network connect (flattened, no envelope) → remote ip/port
    e = parse_line(json.dumps({"event_simpleName": "NetworkConnectIP4", "ComputerName": "WS-2",
                               "RemoteAddressIP4": "203.0.113.5", "RemotePort": "443"}))
    assert e["event_type"] == "network_connect" and e["dest_ip"] == "203.0.113.5" and e["dest_port"] == 443

    # arbitrary JSON without CrowdStrike markers is not hijacked
    e = parse_line(json.dumps({"event": {"foo": 1}, "src_ip": "10.0.0.1"}))
    assert e["event_type"] != "falcon_event" and e["src_ip"] == "10.0.0.1"


def test_sentinelone_threat_maps_to_native_vocab():
    e = parse_line(json.dumps({
        "threatInfo": {"classification": "Ransomware", "threatName": "Conti", "processName": "conti.exe"},
        "agentRealtimeInfo": {"agentComputerName": "FIN-7"},
        "agentDetectionInfo": {"agentLastLoggedInUserName": r"CORP\svc", "externalIp": "198.51.100.9"}}))
    assert e["event_type"] == "malware_detected" and e["mitre_tech_id"] == "T1486"
    assert e["hostname"] == "FIN-7" and e["username"] == "svc" and e["src_ip"] == "198.51.100.9"
    assert e["process_name"] == "conti.exe" and e["category"] == "endpoint"

    # generic malware classification → T1204
    e = parse_line(json.dumps({"threatInfo": {"classification": "Malware", "threatName": "x"},
                               "agentRealtimeInfo": {"agentComputerName": "H1"}}))
    assert e["event_type"] == "malware_detected" and e["mitre_tech_id"] == "T1204"

    # plain JSON without S1 nested objects is not hijacked
    e = parse_line(json.dumps({"classification": "Malware", "src_ip": "10.0.0.1"}))
    assert e["event_type"] != "malware_detected" and e["src_ip"] == "10.0.0.1"


def test_m365_defender_advanced_hunting_maps_to_native_vocab():
    # logon failed → failed_login (feeds the brute-force rule)
    e = parse_line(json.dumps({"ActionType": "LogonFailed", "DeviceName": "LT-3",
                               "AccountName": "alice", "RemoteIP": "203.0.113.7"}))
    assert e["event_type"] == "failed_login" and e["username"] == "alice"
    assert e["src_ip"] == "203.0.113.7" and e["hostname"] == "LT-3" and e["mitre_tech_id"] == "T1110"

    # AV detection → malware_detected (critical)
    e = parse_line(json.dumps({"ActionType": "AntivirusDetection", "DeviceName": "LT-4",
                               "FileName": "bad.dll", "InitiatingProcessAccountName": "svc"}))
    assert e["event_type"] == "malware_detected" and e["severity_hint"] == "critical"
    assert e["process_name"] == "bad.dll" and e["mitre_tech_id"] == "T1204" and e["username"] == "svc"

    # network connection → dest ip/port from Remote*, src from LocalIP
    e = parse_line(json.dumps({"ActionType": "ConnectionSuccess", "DeviceId": "abc",
                               "RemoteIP": "8.8.8.8", "RemotePort": 53, "LocalIP": "10.0.0.4"}))
    assert e["event_type"] == "network_connect" and e["dest_ip"] == "8.8.8.8"
    assert e["dest_port"] == 53 and e["src_ip"] == "10.0.0.4"

    # ActionType without a Defender companion field is NOT hijacked
    e = parse_line(json.dumps({"ActionType": "Something", "src_ip": "10.0.0.1"}))
    assert e["event_type"] != "defender_something" and e["src_ip"] == "10.0.0.1"


def test_m365_office_audit_maps_to_native_vocab():
    # failed sign-in; ClientIP carries a :port that must be stripped
    e = parse_line(json.dumps({"Operation": "UserLoginFailed", "Workload": "AzureActiveDirectory",
                               "UserId": "bob@corp.com", "ClientIP": "203.0.113.8:51000"}))
    assert e["event_type"] == "failed_login" and e["username"] == "bob@corp.com"
    assert e["src_ip"] == "203.0.113.8" and e["mitre_tech_id"] == "T1110"

    # inbox-rule creation (Exchange) → mailbox_rule
    e = parse_line(json.dumps({"Operation": "New-InboxRule", "Workload": "Exchange",
                               "UserId": "eve@corp.com", "RecordType": 1}))
    assert e["event_type"] == "mailbox_rule" and e["mitre_tech_id"] == "T1114.003"

    # add-member-to-role → group_change
    e = parse_line(json.dumps({"Operation": "Add member to role.", "Workload": "AzureActiveDirectory",
                               "UserId": "adm@corp.com"}))
    assert e["event_type"] == "group_change" and e["mitre_tech_id"] == "T1098"

    # generic JSON carrying an 'Operation' but no M365 companion is not hijacked
    e = parse_line(json.dumps({"Operation": "noop", "src_ip": "10.0.0.1"}))
    assert e["event_type"] != "m365_audit" and e["src_ip"] == "10.0.0.1"


def test_panos_firewall_maps_to_native_vocab():
    # THREAT / vulnerability → ips_alert, action normalised to deny
    e = parse_line(json.dumps({"type": "THREAT", "subtype": "vulnerability", "src": "45.9.1.2",
                               "dst": "10.0.0.5", "dport": 443, "action": "reset-both",
                               "rule": "inbound-web", "sessionid": 1234, "app": "web-browsing"}))
    assert e["event_type"] == "ips_alert" and e["src_ip"] == "45.9.1.2" and e["dest_ip"] == "10.0.0.5"
    assert e["dest_port"] == 443 and e["action"] == "deny" and e["mitre_tech_id"] == "T1190"

    # TRAFFIC allow (carries "src", a PA-specific field set) → firewall_allow
    e = parse_line(json.dumps({"type": "TRAFFIC", "src": "10.0.0.9", "dst": "8.8.8.8",
                               "dport": 53, "action": "allow", "app": "dns", "rule": "egress"}))
    assert e["event_type"] == "firewall_allow" and e["action"] == "allow"

    # a bare {"type":"TRAFFIC"} with no PA-specific field is not hijacked
    e = parse_line(json.dumps({"type": "TRAFFIC", "message": "x", "src_ip": "10.0.0.1"}))
    assert e["event_type"] != "firewall_allow" and e["src_ip"] == "10.0.0.1"


def test_fortigate_firewall_json_and_kv_map_to_native_vocab():
    # JSON, UTM/IPS → ips_alert
    e = parse_line(json.dumps({"devname": "FGT-1", "type": "utm", "subtype": "ips",
                               "srcip": "45.9.1.2", "dstip": "10.0.0.5", "dstport": 80,
                               "action": "blocked", "user": "bob"}))
    assert e["event_type"] == "ips_alert" and e["src_ip"] == "45.9.1.2" and e["mitre_tech_id"] == "T1190"
    assert e["action"] == "deny" and e["hostname"] == "FGT-1" and e["username"] == "bob"

    # key=value syslog (FortiGate's native format) with a quoted msg, denied traffic
    kv = ('date=2026-06-18 type=traffic subtype=forward devname="FGT-2" '
          'srcip=10.0.0.7 dstip=8.8.8.8 dstport=443 action=deny user="alice" '
          'msg="connection blocked by policy"')
    e = parse_line(kv)
    assert e["event_type"] == "firewall_deny" and e["src_ip"] == "10.0.0.7"
    assert e["dest_ip"] == "8.8.8.8" and e["dest_port"] == 443 and e["username"] == "alice"
    assert e["action"] == "deny" and e["hostname"] == "FGT-2"

    # virus subtype → malware_detected
    e = parse_line(json.dumps({"logid": "0211", "type": "utm", "subtype": "virus",
                               "srcip": "10.0.0.8", "action": "blocked"}))
    assert e["event_type"] == "malware_detected" and e["mitre_tech_id"] == "T1204"


def test_cef_envelope_maps_to_native_vocab():
    # CEF auth-failure → failed_login (feeds the brute-force rule), fields mapped,
    # header severity 7 → high.
    line = ("CEF:0|Fortinet|FortiGate|2.0|0100|authentication failure for bob|7|"
            "src=203.0.113.7 dst=10.0.0.5 dpt=443 suser=bob act=deny shost=fw-1")
    e = parse_line(line)
    assert e["event_type"] == "failed_login" and e["username"] == "bob"
    assert e["src_ip"] == "203.0.113.7" and e["dest_ip"] == "10.0.0.5" and e["dest_port"] == 443
    assert e["action"] == "deny" and e["severity_hint"] == "high"

    # generic CEF (no signature) → cef_event, severity from the header, fields mapped
    e2 = parse_line("CEF:0|Palo Alto|PAN-OS|10|traffic|Traffic allowed|2|"
                    "src=10.0.0.9 dst=8.8.8.8 dpt=53 act=allow")
    assert e2["event_type"] == "cef_event" and e2["category"] == "cef"
    assert e2["src_ip"] == "10.0.0.9" and e2["dest_port"] == 53 and e2["severity_hint"] == "low"
    assert e2["action"] == "allow"

    # malware CEF → classified via the content signature; process + host mapped
    e3 = parse_line("CEF:0|McAfee|EPO|5|0|Virus detected: malware found|9|shost=WS-1 fname=evil.exe")
    assert e3["event_type"] == "process_start" and e3["severity_hint"] == "critical"
    assert e3["process_name"] == "evil.exe" and e3["hostname"] == "WS-1"


def test_leef_envelope_maps_to_native_vocab():
    # LEEF 1.0 (tab-delimited extension), login failed
    line = ("LEEF:1.0|IBM|QRadar|1.0|authFail|src=198.51.100.9\tdst=10.0.0.2\t"
            "dstPort=22\tusrName=alice\tcat=login failed\tsev=8")
    e = parse_line(line)
    assert e["event_type"] == "failed_login" and e["username"] == "alice"
    assert e["src_ip"] == "198.51.100.9" and e["dest_port"] == 22 and e["severity_hint"] == "high"

    # LEEF 2.0 with a caret delimiter declared in the 6th header field
    e2 = parse_line("LEEF:2.0|Cisco|ASA|9|deny|^|src=45.9.1.2^dst=10.0.0.5^dstPort=3389^action=deny^cat=traffic")
    assert e2["src_ip"] == "45.9.1.2" and e2["dest_port"] == 3389 and e2["action"] == "deny"
    assert e2["event_type"] == "leef_event"


def test_ingest_endpoint_accepts_cef(client, auth):
    tag = uuid.uuid4().hex[:8]
    cef = f"CEF:0|Vendor|Prod|1|sig|authentication failure|6|src=203.0.113.4 suser=cef-{tag}"
    r = client.post("/siem/ingest", json={"lines": [cef], "format": "auto"}, headers=auth)
    assert r.status_code == 200 and r.json()["parsed"] == 1
    with get_conn() as conn:
        row = conn.execute("SELECT event_type FROM events WHERE username=?", (f"cef-{tag}",)).fetchone()
    assert row["event_type"] == "failed_login"


def test_deframe_syslog_octet_counting_and_newline():
    # octet-counting framing (RFC 5425): "<len> <msg>"
    msg = "<34>1 2026-06-18T00:00:00Z host app - - - hello"
    msgs, rem = deframe_syslog(f"{len(msg)} {msg}".encode())
    assert msgs == [msg] and rem == b""

    # two octet frames back to back, no remainder
    a, b = "first message", "second"
    msgs, rem = deframe_syslog(f"{len(a)} {a}{len(b)} {b}".encode())
    assert msgs == [a, b] and rem == b""

    # partial octet frame → carried as remainder, nothing emitted yet
    msgs, rem = deframe_syslog(b"20 only-ten")
    assert msgs == [] and rem == b"20 only-ten"

    # non-transparent (newline) framing, trailing partial line preserved
    msgs, rem = deframe_syslog(b"line one\nline two\npartial")
    assert msgs == ["line one", "line two"] and rem == b"partial"


def test_deframe_syslog_rejects_oversized_frames_dos_guard():
    """A malicious octet-count frame or an unterminated giant line must be
    rejected (ValueError), not buffered forever — the TLS listener would
    otherwise exhaust memory. The connection handler drops the peer on this."""
    import pytest
    from dashboard_api.log_listeners import MAX_SYSLOG_MSG

    # An over-long declared octet count → rejected, never buffered.
    with pytest.raises(ValueError, match="declares"):
        deframe_syslog(b"1000000000 x")
    # A boundary-legal frame (exactly the cap) is still accepted…
    ok = "a" * MAX_SYSLOG_MSG
    msgs, rem = deframe_syslog(f"{MAX_SYSLOG_MSG} {ok}".encode())
    assert msgs == [ok] and rem == b""
    # …but one byte over the cap is rejected.
    with pytest.raises(ValueError):
        deframe_syslog(f"{MAX_SYSLOG_MSG + 1} ".encode() + b"b" * (MAX_SYSLOG_MSG + 1))
    # An unterminated newline line past the cap → rejected (no infinite buffer).
    with pytest.raises(ValueError, match="without a newline"):
        deframe_syslog(b"Z" * (MAX_SYSLOG_MSG + 5))
    # A normal partial frame still just waits — not every incomplete read errors.
    msgs, rem = deframe_syslog(b"20 short")
    assert msgs == [] and rem == b"20 short"


def test_ingest_endpoint_stores_edr_and_firewall(client, auth):
    tag = uuid.uuid4().hex[:8]
    cs = json.dumps({"event_simpleName": "UserLogonFailed2", "ComputerName": "WS-9",
                     "UserName": f"cs-{tag}"})
    fw = ('type=traffic subtype=forward devname="FGT-X" '
          f'srcip=10.9.9.9 dstip=8.8.8.8 dstport=53 action=deny user="fw-{tag}"')
    r = client.post("/siem/ingest", json={"lines": [cs, fw], "format": "auto"}, headers=auth)
    assert r.status_code == 200 and r.json()["parsed"] == 2
    with get_conn() as conn:
        a = conn.execute("SELECT event_type FROM events WHERE username=?", (f"cs-{tag}",)).fetchone()
        b = conn.execute("SELECT event_type FROM events WHERE username=?", (f"fw-{tag}",)).fetchone()
    assert a["event_type"] == "failed_login" and b["event_type"] == "firewall_deny"


def test_ingest_endpoint_stores_windows_and_cloudtrail(client, auth):
    tag = uuid.uuid4().hex[:8]
    win = json.dumps({"EventID": 4625, "Computer": "WIN-T", "TargetUserName": f"win-{tag}",
                      "IpAddress": "203.0.113.9", "Channel": "Security"})
    ct = json.dumps({"eventVersion": "1.08", "eventSource": "iam.amazonaws.com",
                     "eventName": "CreateAccessKey", "sourceIPAddress": "198.51.100.7",
                     "userIdentity": {"userName": f"ct-{tag}"}})
    r = client.post("/siem/ingest", json={"lines": [win, ct], "format": "json"}, headers=auth)
    assert r.status_code == 200 and r.json()["parsed"] == 2
    with get_conn() as conn:
        w = conn.execute("SELECT event_type FROM events WHERE username=?", (f"win-{tag}",)).fetchone()
        c = conn.execute("SELECT event_type FROM events WHERE username=?", (f"ct-{tag}",)).fetchone()
    assert w["event_type"] == "failed_login" and c["event_type"] == "create_access_key"


# ── Ingest resilience: one crafted line must not abort the whole batch ─────────

def test_deeply_nested_json_line_does_not_crash_parse():
    """A pathologically deep JSON line (crafted to blow the decoder's recursion
    stack) is handled as a generic log event, not an unhandled RecursionError."""
    deep = '{"a":' * 3000 + '1' + '}' * 3000
    ev = parse_line(deep, "auto")   # must return, never raise RecursionError
    assert ev is not None and ev["event_type"] == "log"


def test_flatten_depth_is_bounded():
    """_flatten stops descending past its depth cap instead of recursing without
    bound on a deeply-nested (but decodable) object."""
    from dashboard_api.ingest import _flatten, _MAX_FLATTEN_DEPTH
    obj = cur = {}
    for _ in range(_MAX_FLATTEN_DEPTH + 50):
        nxt = {}
        cur["child"] = nxt
        cur = nxt
    cur["leaf"] = "x"
    flat = _flatten(obj)   # must return without RecursionError
    assert isinstance(flat, dict)


def test_one_bad_line_does_not_drop_the_whole_batch(client, auth):
    """A batch containing a crafted line that would crash the parser still ingests
    every other line — the bad one is skipped and counted, the POST stays 200."""
    tag = uuid.uuid4().hex[:8]
    good1 = json.dumps({"event_type": "failed_login", "src_ip": "203.0.113.5",
                        "user": f"g1-{tag}", "host": "H1"})
    bad = '{"a":' * 3000 + '1' + '}' * 3000        # deeply-nested → would crash parse
    good2 = json.dumps({"event_type": "login_success", "src_ip": "203.0.113.6",
                        "user": f"g2-{tag}", "host": "H2"})
    r = client.post("/siem/ingest", json={"lines": [good1, bad, good2], "format": "auto"},
                    headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    # Both good lines parsed; the crafted one didn't take the batch down. (It may
    # be skipped, or degrade to a generic event — either way both goods survive.)
    with get_conn() as conn:
        g1 = conn.execute("SELECT 1 FROM events WHERE username=?", (f"g1-{tag}",)).fetchone()
        g2 = conn.execute("SELECT 1 FROM events WHERE username=?", (f"g2-{tag}",)).fetchone()
    assert g1 is not None and g2 is not None, "a single crafted line dropped the whole batch"
    assert body["parsed"] >= 2
