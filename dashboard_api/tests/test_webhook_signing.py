"""Outbound webhook signing: every delivery is HMAC-signed (so a subscriber can
verify it genuinely came from ThreatOrbit) and carries an idempotency id; the
signing secret is shown once at create/rotate and never re-listed.
"""
import http.server
import threading
import uuid

from dashboard_api import webhooks as wh


def test_sign_verify_roundtrip():
    secret = wh.new_webhook_secret()
    body = b'{"event":"x","data":1}'
    sig = wh.sign_payload(secret, body)
    assert wh.verify_signature(secret, body, sig)
    assert not wh.verify_signature(secret, body + b" ", sig)        # tampered body
    assert not wh.verify_signature("whsec_other", body, sig)        # wrong secret
    assert not wh.verify_signature(secret, body, "garbage")         # malformed header
    assert not wh.verify_signature(secret, body, wh.sign_payload(secret, body, ts=1))  # too old


def test_create_returns_secret_list_hides_it(client, auth):
    r = client.post("/config/webhooks", json={"url": "https://example.com/h",
                    "events": ["alert.created"]}, headers=auth)
    assert r.status_code == 201
    secret = r.json()["secret"]
    assert secret.startswith("whsec_")
    mine = next(w for w in client.get("/config/webhooks", headers=auth).json()
                if w["id"] == r.json()["id"])
    assert "secret" not in mine                                     # never exposed again
    client.delete(f"/config/webhooks/{r.json()['id']}", headers=auth)


def _sink():
    received: list = []

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append({"headers": self.headers, "body": self.rfile.read(n)})
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, received


def test_delivery_is_signed_and_idempotent(client, auth, monkeypatch):
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    server, received = _sink()
    port = server.server_address[1]
    try:
        hook = client.post("/config/webhooks", json={
            "url": f"http://127.0.0.1:{port}/sink", "events": ["alert.created"]},
            headers=auth).json()
        secret = hook["secret"]
        client.post(f"/config/webhooks/{hook['id']}/test", headers=auth)
        assert received, "no delivery captured"
        d = received[-1]
        sig = d["headers"].get("X-ThreatOrbit-Signature")
        assert sig and wh.verify_signature(secret, d["body"], sig)      # verifies under the secret
        assert not wh.verify_signature("whsec_wrong", d["body"], sig)
        uuid.UUID(d["headers"].get("X-ThreatOrbit-Delivery"))          # idempotency id is a uuid
        assert d["headers"].get("X-ThreatOrbit-Event") == "webhook.test"
        client.delete(f"/config/webhooks/{hook['id']}", headers=auth)
    finally:
        server.shutdown()


def test_delivery_retries_then_succeeds_with_stable_id(client, auth, monkeypatch):
    """Transient failures are retried (same idempotency id) until one succeeds."""
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    received: list = []
    fail = {"n": 2}   # 500 on the first two attempts, then 200

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            self.rfile.read(n)
            received.append(self.headers.get("X-ThreatOrbit-Delivery"))
            self.send_response(500 if fail["n"] > 0 else 200)
            fail["n"] -= 1
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        hook = client.post("/config/webhooks", json={
            "url": f"http://127.0.0.1:{port}/sink", "events": ["alert.created"]},
            headers=auth).json()
        out = client.post(f"/config/webhooks/{hook['id']}/test", headers=auth).json()
        assert out["ok"] is True                       # eventually delivered
        assert len(received) == 3                       # two failures, then success
        assert len(set(received)) == 1                  # one stable idempotency id across retries
        client.delete(f"/config/webhooks/{hook['id']}", headers=auth)
    finally:
        server.shutdown()


def test_rotate_secret_invalidates_old(client, auth, monkeypatch):
    monkeypatch.setattr(wh, "SYNC_DELIVERY", True)
    server, received = _sink()
    port = server.server_address[1]
    try:
        hook = client.post("/config/webhooks", json={
            "url": f"http://127.0.0.1:{port}/sink", "events": ["alert.created"]},
            headers=auth).json()
        old_secret = hook["secret"]
        new_secret = client.post(f"/config/webhooks/{hook['id']}/rotate-secret",
                                 headers=auth).json()["secret"]
        assert new_secret != old_secret
        client.post(f"/config/webhooks/{hook['id']}/test", headers=auth)
        d = received[-1]
        sig = d["headers"].get("X-ThreatOrbit-Signature")
        assert wh.verify_signature(new_secret, d["body"], sig)         # new secret verifies
        assert not wh.verify_signature(old_secret, d["body"], sig)     # old one no longer
        client.delete(f"/config/webhooks/{hook['id']}", headers=auth)
    finally:
        server.shutdown()
