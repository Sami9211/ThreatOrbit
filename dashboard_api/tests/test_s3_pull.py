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


def test_poll_isolates_a_failing_object(monkeypatch):
    """One bad object (network blip, transient 5xx, malformed body) must not
    discard the whole batch or corrupt the checkpoint. Objects that already
    ingested successfully this poll must not be re-ingested on retry, and the
    checkpoint must advance up to (not including) the failing key."""
    tag = uuid.uuid4().hex[:8]
    s3 = _cfg(prefix=f"fail-{tag}/")
    list_xml = (f"<ListBucketResult>"
                f"<Contents><Key>fail-{tag}/1.log</Key></Contents>"
                f"<Contents><Key>fail-{tag}/2.log</Key></Contents>"
                f"<Contents><Key>fail-{tag}/3.log</Key></Contents>"
                f"</ListBucketResult>")
    good = {
        f"fail-{tag}/1.log": f'{{"event_type":"failed_login","src_ip":"9.9.9.1","user":"g1-{tag}"}}\n',
        f"fail-{tag}/3.log": f'{{"event_type":"login_success","src_ip":"9.9.9.3","user":"g3-{tag}"}}\n',
    }

    def flaky_get(url, headers):
        if "list-type=2" in url:
            return list_xml
        if f"fail-{tag}/2.log" in url:
            raise OSError("simulated transient S3 GET failure")
        for key, body in good.items():
            if key in url:
                return body
        return ""

    monkeypatch.setattr(s3_pull, "_http_get", flaky_get)

    res = s3_pull.poll(s3)
    # Object 1 ingested; object 2 failed → stop there, never reaching object 3.
    assert res["objects"] == 1 and res["ingested"] == 1
    assert res["cursor"] == f"fail-{tag}/1.log"
    with get_conn() as conn:
        g1 = conn.execute("SELECT 1 FROM events WHERE username=?", (f"g1-{tag}",)).fetchone()
    assert g1 is not None

    # Retry: object 1 is past the checkpoint (not re-listed, not re-ingested);
    # object 2 still fails, so we again stop before reaching object 3.
    res2 = s3_pull.poll(s3)
    assert res2["objects"] == 0 and res2["ingested"] == 0
    assert res2["cursor"] == f"fail-{tag}/1.log"

    # Once the transient failure clears, the poll resumes from the checkpoint
    # and processes both remaining objects without re-touching object 1.
    recovered = {**good, f"fail-{tag}/2.log":
                f'{{"event_type":"login_success","src_ip":"9.9.9.2","user":"g2-{tag}"}}\n'}
    monkeypatch.setattr(s3_pull, "_http_get",
                        lambda url, headers: (list_xml if "list-type=2" in url
                                              else next((b for k, b in recovered.items() if k in url), "")))
    res3 = s3_pull.poll(s3)
    assert res3["objects"] == 2 and res3["ingested"] == 2
    assert res3["cursor"] == f"fail-{tag}/3.log"
    with get_conn() as conn:
        g3 = conn.execute("SELECT 1 FROM events WHERE username=?", (f"g3-{tag}",)).fetchone()
        g1_again = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE username=?", (f"g1-{tag}",)).fetchone()["n"]
    assert g3 is not None
    assert g1_again == 1   # never duplicated across the retries


def test_status_reflects_config(monkeypatch):
    monkeypatch.setattr(config, "S3_PULL_BUCKET", "")
    assert s3_pull.status() == {"enabled": False}
    monkeypatch.setattr(config, "S3_PULL_BUCKET", "mybucket")
    monkeypatch.setattr(config, "S3_PULL_PREFIX", "logs/")
    st = s3_pull.status()
    assert st["enabled"] is True and st["bucket"] == "mybucket" and st["prefix"] == "logs/"
