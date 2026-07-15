"""Vendor-friendly raw ingest (/siem/ingest/raw): the endpoint the certified
Fluent Bit / Vector / Filebeat configs target. It must accept the shapes those
agents emit natively - plain text, NDJSON, JSON string-arrays, JSON object-arrays
- with no {lines:[…]} envelope, authenticated by an API key.
"""
import json


def _write_key(client, auth):
    r = client.post("/config/api-keys", headers=auth, json={"name": "raw-ingest", "scope": "write"})
    assert r.status_code == 201, r.text
    return r.json()["secret"]


def test_raw_plaintext_newline_delimited(client, auth):
    key = _write_key(client, auth)
    body = "203.0.113.5 - - [01/Jan/2020:00:00:00 +0000] \"GET / HTTP/1.1\" 200 12\n" \
           "203.0.113.6 - - [01/Jan/2020:00:00:01 +0000] \"POST /login HTTP/1.1\" 401 0\n"
    r = client.post("/siem/ingest/raw?format=auto&source=fluentbit",
                    headers={"X-API-Key": key, "Content-Type": "text/plain"}, content=body)
    assert r.status_code == 200, r.text
    assert r.json()["parsed"] >= 2


def test_raw_ndjson_objects(client, auth):
    key = _write_key(client, auth)
    ndjson = "\n".join(json.dumps(o) for o in [
        {"msg": "auth failure", "src_ip": "198.51.100.9", "user": "root"},
        {"msg": "auth failure", "src_ip": "198.51.100.9", "user": "admin"},
    ])
    r = client.post("/siem/ingest/raw?format=json&source=vector",
                    headers={"X-API-Key": key, "Content-Type": "application/x-ndjson"}, content=ndjson)
    assert r.status_code == 200, r.text
    assert r.json()["parsed"] >= 2


def test_raw_json_array_of_objects(client, auth):
    key = _write_key(client, auth)
    arr = [{"event": "login", "src_ip": "192.0.2.10"}, {"event": "logout", "src_ip": "192.0.2.10"}]
    r = client.post("/siem/ingest/raw?format=json&source=filebeat",
                    headers={"X-API-Key": key, "Content-Type": "application/json"},
                    content=json.dumps(arr))
    assert r.status_code == 200, r.text
    assert r.json()["parsed"] >= 2


def test_raw_json_string_array(client, auth):
    key = _write_key(client, auth)
    arr = ["raw line one", "raw line two", "   ", "raw line three"]   # blanks dropped
    r = client.post("/siem/ingest/raw?source=custom",
                    headers={"X-API-Key": key, "Content-Type": "application/json"},
                    content=json.dumps(arr))
    assert r.status_code == 200, r.text
    assert r.json()["parsed"] == 3


def test_raw_empty_body_rejected(client, auth):
    key = _write_key(client, auth)
    r = client.post("/siem/ingest/raw", headers={"X-API-Key": key, "Content-Type": "text/plain"}, content="")
    assert r.status_code == 400


def test_raw_requires_auth(client):
    r = client.post("/siem/ingest/raw", headers={"Content-Type": "text/plain"}, content="x\n")
    assert r.status_code == 401
