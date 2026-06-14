"""Stripe self-serve billing: honest degradation + signature-verified webhook.

No Stripe is contacted - the outward calls (checkout/portal) aren't exercised
here because billing is unconfigured by default; the webhook path is fully
testable offline (stdlib HMAC), so that's where the activation logic is proven.
"""
import hashlib
import hmac
import json
import time

from dashboard_api.db import get_conn


def _sig(secret: str, payload: bytes) -> str:
    ts = str(int(time.time()))
    v1 = hmac.new(secret.encode(), f"{ts}.{payload.decode()}".encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={v1}"


def test_billing_status_degrades_without_stripe(client, auth):
    s = client.get("/billing/status", headers=auth).json()
    assert s["configured"] is False
    assert s["plans"] == []                       # no prices configured
    assert isinstance(s["currentPlan"], str) and s["currentPlan"]


def test_billing_checkout_and_portal_not_configured(client, auth):
    assert client.post("/billing/checkout", json={"plan": "pro"}, headers=auth).status_code == 400
    assert client.post("/billing/portal", headers=auth).status_code == 400


def test_billing_webhook_rejects_unsigned(client):
    # No webhook secret configured -> verification fails -> 400 (Stripe retries).
    r = client.post("/billing/webhook", content=b'{"type":"x"}',
                    headers={"Stripe-Signature": "t=1,v1=bad"})
    assert r.status_code == 400


def test_billing_webhook_activates_then_reverts(client, auth, monkeypatch):
    import dashboard_api.billing as b
    monkeypatch.setattr(b, "STRIPE_WEBHOOK_SECRET", "whsec_test")

    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='license_key'").fetchone()
        prev_key = row["value"] if row else None
    try:
        completed = json.dumps({
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {"plan": "pro"},
                                "customer": "cus_test", "subscription": "sub_test"}},
        }).encode()
        ok = client.post("/billing/webhook", content=completed,
                         headers={"Stripe-Signature": _sig("whsec_test", completed)})
        assert ok.status_code == 200, ok.text
        assert ok.json()["applied"] is True
        # the plan is now reflected through the normal licence path
        assert client.get("/config/license", headers=auth).json()["plan"] == "pro"

        # a tampered signature is rejected
        bad = client.post("/billing/webhook", content=completed,
                          headers={"Stripe-Signature": "t=1,v1=deadbeef"})
        assert bad.status_code == 400

        # cancellation reverts the minted licence
        deleted = json.dumps({"type": "customer.subscription.deleted",
                              "data": {"object": {"id": "sub_test"}}}).encode()
        rev = client.post("/billing/webhook", content=deleted,
                          headers={"Stripe-Signature": _sig("whsec_test", deleted)})
        assert rev.status_code == 200 and rev.json()["applied"] is True
    finally:
        with get_conn() as conn:
            conn.execute("DELETE FROM settings WHERE key IN "
                         "('stripe_customer_id','stripe_subscription_id','billing_plan')")
            if prev_key is None:
                conn.execute("DELETE FROM settings WHERE key='license_key'")
            else:
                conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('license_key',?)", (prev_key,))
            conn.commit()
