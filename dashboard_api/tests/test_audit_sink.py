"""External audit sink: audit events are mirrored (optionally HMAC-signed) to an
off-box tamper-evident endpoint. Unset URL is a complete no-op.
"""
import http.server
import json
import threading

from dashboard_api import audit_sink, config, webhooks


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


def test_ship_disabled_is_noop(monkeypatch):
    calls = []
    monkeypatch.setattr(config, "AUDIT_SINK_URL", "")
    monkeypatch.setattr(audit_sink, "_post", lambda e: calls.append(e))
    audit_sink.ship({"action": "x"})
    assert calls == []          # unconfigured → never attempts a post


def test_ship_posts_signed_event(monkeypatch):
    server, received = _sink()
    port = server.server_address[1]
    try:
        monkeypatch.setattr(config, "AUDIT_SINK_URL", f"http://127.0.0.1:{port}/audit")
        monkeypatch.setattr(config, "AUDIT_SINK_SECRET", "auditsecret123")
        monkeypatch.setattr(audit_sink, "SYNC_SHIP", True)
        audit_sink.ship({"ts": "2026-01-01T00:00:00+00:00", "actor": "a@b.c",
                         "action": "test.event", "target": None, "detail": "x"})
        assert received
        d = received[-1]
        sig = d["headers"].get("X-ThreatOrbit-Signature")
        assert sig and webhooks.verify_signature("auditsecret123", d["body"], sig)
        assert json.loads(d["body"])["action"] == "test.event"
    finally:
        server.shutdown()


def test_audit_action_mirrors_to_sink(client, auth, monkeypatch):
    server, received = _sink()
    port = server.server_address[1]
    try:
        monkeypatch.setattr(config, "AUDIT_SINK_URL", f"http://127.0.0.1:{port}/audit")
        monkeypatch.setattr(config, "AUDIT_SINK_SECRET", "s3cr3t")
        monkeypatch.setattr(audit_sink, "SYNC_SHIP", True)
        hook = client.post("/config/webhooks", json={"url": "https://example.com/h",
                           "events": ["alert.created"]}, headers=auth).json()
        evt = next((r for r in received if json.loads(r["body"]).get("action") == "webhook.create"), None)
        assert evt is not None, "audited action not mirrored to the sink"
        assert webhooks.verify_signature("s3cr3t", evt["body"], evt["headers"].get("X-ThreatOrbit-Signature"))
        client.delete(f"/config/webhooks/{hook['id']}", headers=auth)
    finally:
        server.shutdown()
