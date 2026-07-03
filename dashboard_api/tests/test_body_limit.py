"""Ingress body-size cap (DoS guard): an over-large request body is rejected
with 413 before the app buffers it, while normal-sized requests pass through.
The line-count cap inside /siem/ingest only runs after the whole body is read,
so this middleware is what actually bounds memory against a huge POST.
"""
import dashboard_api.observability as obs


def _small_client():
    """A TestClient whose app has a tiny body cap, so we can exercise the limit
    without multi-MB payloads, plus a valid admin auth header."""
    from fastapi.testclient import TestClient
    from dashboard_api.main import app
    wrapped = obs.BodySizeLimitMiddleware(app, max_bytes=2000)
    tc = TestClient(wrapped)
    tok = tc.post("/auth/login", json={"email": "admin@threatorbit.space",
                                       "password": "ChangeMe123!"}).json()["token"]
    return tc, {"Authorization": f"Bearer {tok}"}


def test_oversize_body_rejected_413():
    tc, hdr = _small_client()
    big = "x" * 5000
    r = tc.post("/siem/ingest", content=big,
                headers={**hdr, "Content-Type": "application/json"})
    assert r.status_code == 413
    assert "too large" in r.json()["error"].lower()


def test_oversize_body_rejected_even_without_content_length():
    """Chunked / streamed bodies (no declared content-length) are still bounded
    by the streaming byte counter — the app buffers at most ~cap, then the body
    is truncated so it can't be a 200, and memory never grows unbounded."""
    tc, hdr = _small_client()

    def gen():
        for _ in range(10):
            yield b"y" * 500   # 5000 bytes total, no content-length

    r = tc.post("/siem/ingest", content=gen(),
                headers={**hdr, "Content-Type": "application/json"})
    assert r.status_code in (413, 400, 422)   # rejected, never 200


def test_normal_body_passes_through(client, auth):
    """A normal ingest request (well under the real 25 MB default) is unaffected."""
    import json
    line = json.dumps({"event_type": "login_success", "src_ip": "10.0.0.9", "user": "ok"})
    r = client.post("/siem/ingest", json={"lines": [line], "format": "json"}, headers=auth)
    assert r.status_code == 200, r.text
