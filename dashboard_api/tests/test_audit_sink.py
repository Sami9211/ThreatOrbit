"""External audit sink: audit events are mirrored (optionally HMAC-signed) to an
off-box tamper-evident endpoint. Unset URL is a complete no-op. Delivery is an
outbox drain over the committed audit_log with a persisted cursor, so a sink
outage or restart replays the undelivered tail (at-least-once, in order).
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


def _failable_sink():
    """A receiver whose availability the test can toggle (503 while failing)."""
    received: list = []
    state = {"fail": False}

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            if state["fail"]:
                self.send_response(503)
                self.end_headers()
                return
            received.append(json.loads(body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, received, state


def test_outbox_drain_orders_persists_and_replays(monkeypatch):
    """The durable path: committed rows beyond the persisted cursor are
    delivered in id order; a sink outage never loses events - the cursor stays
    put and the next pass (same as a process restart) replays the tail."""
    from dashboard_api.db import audit, get_conn
    server, received, state = _failable_sink()
    port = server.server_address[1]
    try:
        monkeypatch.setattr(config, "AUDIT_SINK_URL", f"http://127.0.0.1:{port}/audit")
        monkeypatch.setattr(config, "AUDIT_SINK_SECRET", "")
        # Drive the drain deterministically: silence the worker nudge and park
        # the cursor at the current head so only this test's rows are in play.
        monkeypatch.setattr(audit_sink, "ship", lambda e: None)
        with get_conn() as conn:
            head = conn.execute("SELECT COALESCE(MAX(id),0) AS m FROM audit_log").fetchone()["m"]
            audit_sink._set_cursor(conn, head)

        with get_conn() as conn:
            audit(conn, "t@x.y", "outbox.one")
            audit(conn, "t@x.y", "outbox.two")
            conn.commit()
        out = audit_sink.drain_once()
        assert out["delivered"] == 2 and out["pending"] == 0 and out["ok"] is True
        assert [e["action"] for e in received[-2:]] == ["outbox.one", "outbox.two"]
        assert all(e["id"] for e in received[-2:])   # consumers can dedupe on id

        # Nothing new → nothing re-delivered (the cursor persisted).
        assert audit_sink.drain_once()["delivered"] == 0

        # Outage: the event is not lost. The cursor holds, replay delivers it.
        state["fail"] = True
        with get_conn() as conn:
            audit(conn, "t@x.y", "outbox.three")
            conn.commit()
        out = audit_sink.drain_once()
        assert out["delivered"] == 0 and out["pending"] == 1 and out["ok"] is False
        state["fail"] = False
        # A fresh pass reads the cursor from the DB - exactly what a restart does.
        out = audit_sink.drain_once()
        assert out["delivered"] == 1 and received[-1]["action"] == "outbox.three"
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
