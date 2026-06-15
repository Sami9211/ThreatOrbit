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
