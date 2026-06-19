"""Agentless S3 log pull: list → fetch → ingest new objects past a checkpoint,
then advance it (restart-safe). SigV4 GET signing is cross-verified against
botocore offline; here the HTTP is stubbed so the poll logic is tested without a
live bucket.
"""
import uuid

from dashboard_api import config, s3_pull
from dashboard_api.db import get_conn


def _cfg(prefix="app/"):
    return {"bucket": "logs", "prefix": prefix, "region": "us-east-1", "endpoint": "",
            "org_id": "org-default", "access_key": "AK", "secret_key": "SK", "session_token": ""}


def test_signed_get_is_wellformed():
    url, headers = s3_pull._signed_get(_cfg(), "/", {"list-type": "2", "prefix": "app/"})
    assert url.startswith("https://logs.s3.us-east-1.amazonaws.com/?")
    assert "list-type=2" in url and "prefix=app%2F" in url       # query is canonically encoded
    auth = headers["authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AK/") and "Signature=" in auth
    assert headers["x-amz-content-sha256"]


def test_poll_ingests_and_checkpoints(monkeypatch):
    tag = uuid.uuid4().hex[:8]
    s3 = _cfg(prefix=f"app-{tag}/")
    list_xml = (f"<ListBucketResult><Contents><Key>app-{tag}/1.log</Key></Contents>"
                f"<Contents><Key>app-{tag}/2.log</Key></Contents></ListBucketResult>")
    bodies = {
        f"app-{tag}/1.log": f'{{"event_type":"failed_login","src_ip":"1.2.3.4","user":"s3a-{tag}"}}\n',
        f"app-{tag}/2.log": f'{{"event_type":"login_success","src_ip":"1.2.3.5","user":"s3b-{tag}"}}\n',
    }

    def fake_get(url, headers):
        if "list-type=2" in url:
            return list_xml
        for key, body in bodies.items():
            if key in url:
                return body
        return ""
    monkeypatch.setattr(s3_pull, "_http_get", fake_get)

    res = s3_pull.poll(s3)
    assert res["objects"] == 2 and res["ingested"] == 2 and res["cursor"] == f"app-{tag}/2.log"
    with get_conn() as conn:
        e = conn.execute("SELECT 1 FROM events WHERE username=?", (f"s3a-{tag}",)).fetchone()
    assert e is not None                              # the object's lines were ingested

    # second poll: the checkpoint is at the last key → nothing new is re-ingested
    res2 = s3_pull.poll(s3)
    assert res2["objects"] == 0 and res2["cursor"] == f"app-{tag}/2.log"


def test_status_reflects_config(monkeypatch):
    monkeypatch.setattr(config, "S3_PULL_BUCKET", "")
    assert s3_pull.status() == {"enabled": False}
    monkeypatch.setattr(config, "S3_PULL_BUCKET", "mybucket")
    monkeypatch.setattr(config, "S3_PULL_PREFIX", "logs/")
    st = s3_pull.status()
    assert st["enabled"] is True and st["bucket"] == "mybucket" and st["prefix"] == "logs/"
