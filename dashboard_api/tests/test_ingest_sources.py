"""Source breadth: Windows Security events and AWS CloudTrail records normalise
onto the native event vocabulary at ingest, so the same detection rules fire on
them (e.g. Windows 4625 -> failed_login, CloudTrail CreateAccessKey ->
create_access_key).
"""
import json
import uuid

from dashboard_api.db import get_conn
from dashboard_api.ingest import parse_line


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
