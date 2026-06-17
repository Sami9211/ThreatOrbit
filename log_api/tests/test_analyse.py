"""Analysis results + reports are persisted per-job in the DB (not an in-memory
dict / a single shared file), so they survive restarts, are correct across
workers, and concurrent analyses can't overwrite each other. Audit A2 + C6.
"""
from fastapi.testclient import TestClient

from log_api.db import get_conn, init_db
from log_api.main import app

client = TestClient(app)
KEY = {"X-API-Key": "test-user-key"}
APACHE = (
    '127.0.0.1 - - [01/Jun/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "curl/8"\n'
    '10.0.0.5 - - [01/Jun/2026:12:00:01 +0000] "POST /login HTTP/1.1" 401 64 "-" "bot"\n'
    '10.0.0.5 - - [01/Jun/2026:12:00:02 +0000] "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "bot"\n'
)


def _latest_completed_job() -> str:
    init_db()
    with get_conn() as c:
        row = c.execute(
            "SELECT id FROM analysis_jobs WHERE status='completed' ORDER BY updated_at DESC LIMIT 1"
        ).fetchone()
    return row[0] if row else ""


def test_analyse_persists_result_report_and_stix():
    r = client.post("/analyse?log_format=apache",
                    files={"file": ("a.log", APACHE, "text/plain")}, headers=KEY)
    assert r.status_code == 200, r.text

    jid = _latest_completed_job()
    assert jid, "no completed job persisted"

    # the full result is served from the DB (not an in-memory dict)
    res = client.get(f"/results/{jid}", headers=KEY)
    assert res.status_code == 200 and "findings" in res.json()

    # a PER-JOB report is rendered + served (no single shared file)
    rep = client.get(f"/results/{jid}/report", headers=KEY)
    assert rep.status_code == 200 and "<!DOCTYPE html>" in rep.text

    # STIX export reconstructs from the stored result
    stix = client.get(f"/results/{jid}/stix", headers=KEY)
    assert stix.status_code == 200

    # unknown ids 404 (no stale in-memory leakage)
    assert client.get("/results/does-not-exist", headers=KEY).status_code == 404
    assert client.get("/results/does-not-exist/report", headers=KEY).status_code == 404


def test_results_require_api_key():
    assert client.get("/results/anything").status_code in (401, 403)
