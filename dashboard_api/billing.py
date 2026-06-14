"""Stripe self-serve billing (optional, opt-in).

Sits on top of the existing signed-licence-key system: a completed Stripe
Checkout *mints the plan's licence key and stores it*, so the seat/connector
limit enforcement in `licensing.py` needs no changes. With no STRIPE_SECRET_KEY
every endpoint degrades honestly to "not configured" and licence keys remain
the only path - the default install and the demo are completely unaffected.

No SDK dependency: Stripe's REST API is called over httpx (the same pattern as
the assistant's model calls), and webhook signatures are verified with stdlib
HMAC. Only test-mode usage is expected here; real keys are set per deployment.
"""
import hashlib
import hmac
import json
import time

import httpx

from dashboard_api.config import (
    BILLING_RETURN_URL, STRIPE_PRICES, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
)
from dashboard_api.licensing import PLANS, generate_key

_API = "https://api.stripe.com/v1"
_TIMEOUT = 20.0


def configured() -> bool:
    """Self-serve billing is live only when a secret key + at least one price
    are set."""
    return bool(STRIPE_SECRET_KEY and STRIPE_PRICES)


def purchasable() -> list[dict]:
    """The plans that can be bought self-serve (those with a configured price)."""
    return [{"plan": p, "label": PLANS[p]["label"],
             "seats": PLANS[p]["seats"], "connectors": PLANS[p]["connectors"]}
            for p in STRIPE_PRICES if p in PLANS]


def _post(path: str, data: dict) -> dict:
    r = httpx.post(f"{_API}/{path}", data=data, timeout=_TIMEOUT,
                   headers={"Authorization": f"Bearer {STRIPE_SECRET_KEY}"})
    if r.status_code >= 400:
        # Surface Stripe's own message without leaking the key.
        try:
            msg = r.json().get("error", {}).get("message", r.text)
        except Exception:
            msg = r.text
        raise RuntimeError(f"Stripe error ({r.status_code}): {msg}")
    return r.json()


def create_checkout(plan: str, *, org_id: str, email: str | None, customer: str | None) -> str:
    """Create a subscription Checkout Session for `plan`; return its URL."""
    price = STRIPE_PRICES.get(plan)
    if not price:
        raise ValueError(f"plan '{plan}' is not available for self-serve purchase")
    data = {
        "mode": "subscription",
        "line_items[0][price]": price,
        "line_items[0][quantity]": "1",
        "success_url": f"{BILLING_RETURN_URL}?billing=success",
        "cancel_url": f"{BILLING_RETURN_URL}?billing=cancel",
        "client_reference_id": org_id,
        "metadata[plan]": plan,
        "metadata[org_id]": org_id,
        "subscription_data[metadata][plan]": plan,
    }
    if customer:
        data["customer"] = customer
    elif email:
        data["customer_email"] = email
    return _post("checkout/sessions", data)["url"]


def create_portal(customer: str) -> str:
    """Create a Billing Portal session (manage / cancel); return its URL."""
    return _post("billing_portal/sessions",
                 {"customer": customer, "return_url": f"{BILLING_RETURN_URL}?billing=portal"})["url"]


def verify_webhook(payload: bytes, sig_header: str, *, tolerance: int = 300) -> dict:
    """Verify a Stripe webhook signature (the `Stripe-Signature` header) and
    return the parsed event. Raises ValueError on any failure."""
    if not STRIPE_WEBHOOK_SECRET:
        raise ValueError("webhook secret not configured")
    if not sig_header:
        raise ValueError("missing signature")
    parts = [p.split("=", 1) for p in sig_header.split(",") if "=" in p]
    ts = next((v for k, v in parts if k == "t"), None)
    sigs = [v for k, v in parts if k == "v1"]
    if not ts or not sigs:
        raise ValueError("malformed signature header")
    if tolerance and abs(time.time() - int(ts)) > tolerance:
        raise ValueError("timestamp outside tolerance")
    expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode(),
                        f"{ts}.{payload.decode()}".encode(), hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, s) for s in sigs):
        raise ValueError("signature mismatch")
    return json.loads(payload)


def _set(conn, key: str, value):
    if value is None:
        conn.execute("DELETE FROM settings WHERE key=?", (key,))
    else:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, str(value)))


def apply_event(conn, event: dict) -> str | None:
    """Reflect a verified Stripe event into the org's plan. Returns a short
    description of what changed (for the audit log), or None if ignored.

    - checkout.session.completed / subscription active -> mint + store the
      plan's licence key, remember the Stripe customer + subscription.
    - subscription deleted -> clear the minted key (revert to the built-in
      default; a hard 'free' downgrade is a follow-up).
    """
    etype = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}

    if etype == "checkout.session.completed" or etype == "customer.subscription.created":
        plan = (obj.get("metadata") or {}).get("plan")
        if not plan or plan not in PLANS:
            return None
        org = conn.execute("SELECT value FROM settings WHERE key='organization'").fetchone()
        org_name = org["value"] if org and org["value"] else "self-serve"
        _set(conn, "license_key", generate_key(plan=plan, org=org_name))
        if obj.get("customer"):
            _set(conn, "stripe_customer_id", obj["customer"])
        sub = obj.get("subscription") or (obj.get("id") if etype.endswith("created") else None)
        if sub:
            _set(conn, "stripe_subscription_id", sub)
        _set(conn, "billing_plan", plan)
        return f"plan={plan} activated via Stripe"

    if etype == "customer.subscription.deleted":
        _set(conn, "license_key", None)
        _set(conn, "stripe_subscription_id", None)
        _set(conn, "billing_plan", None)
        return "subscription cancelled - licence reverted to default"

    return None


def stripe_customer(conn) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key='stripe_customer_id'").fetchone()
    return row["value"] if row and row["value"] else None
