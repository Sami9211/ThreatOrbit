"""Billing endpoints - Stripe self-serve checkout + portal + webhook.

All read/write routes degrade honestly when billing isn't configured. The
webhook is unauthenticated (Stripe calls it) but every event is signature-
verified before it can touch the plan.
"""
from fastapi import APIRouter, Depends, HTTPException, Request

from dashboard_api import billing
from dashboard_api.auth import current_user, require_perm
from dashboard_api.db import audit, get_conn
from dashboard_api.licensing import current_license
from pydantic import BaseModel

router = APIRouter(prefix="/billing", tags=["billing"])


class CheckoutRequest(BaseModel):
    plan: str


@router.get("/status")
def status(user: dict = Depends(current_user)):
    with get_conn() as conn:
        lic = current_license(conn)
        sub = conn.execute("SELECT value FROM settings WHERE key='stripe_subscription_id'").fetchone()
        customer = billing.stripe_customer(conn)
    return {
        "configured": billing.configured(),
        "plans": billing.purchasable(),
        "currentPlan": lic.get("plan"),
        "currentPlanBuiltin": bool(lic.get("builtin")),
        "hasSubscription": bool(sub and sub["value"]),
        "portalAvailable": billing.configured() and bool(customer),
    }


@router.post("/checkout")
def checkout(body: CheckoutRequest, user: dict = Depends(require_perm("license.manage"))):
    if not billing.configured():
        raise HTTPException(status_code=400, detail="Self-serve billing is not configured on this deployment.")
    from dashboard_api import tenancy
    with get_conn() as conn:
        customer = billing.stripe_customer(conn)
    try:
        url = billing.create_checkout(body.plan, org_id=tenancy.org_of(user),
                                      email=user.get("email"), customer=customer)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    with get_conn() as conn:
        audit(conn, user["email"], "billing.checkout", None, f"plan={body.plan}")
        conn.commit()
    return {"url": url}


@router.post("/portal")
def portal(user: dict = Depends(require_perm("license.manage"))):
    if not billing.configured():
        raise HTTPException(status_code=400, detail="Self-serve billing is not configured on this deployment.")
    with get_conn() as conn:
        customer = billing.stripe_customer(conn)
    if not customer:
        raise HTTPException(status_code=400, detail="No Stripe customer yet - start a subscription first.")
    try:
        url = billing.create_portal(customer)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return {"url": url}


@router.post("/webhook")
async def webhook(request: Request):
    """Stripe webhook - verify the signature, then reflect the event into the
    org's plan. Returns 400 on any verification failure so Stripe retries are
    visible, 200 once handled (or safely ignored)."""
    payload = await request.body()
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = billing.verify_webhook(payload, sig)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"webhook verification failed: {e}")
    with get_conn() as conn:
        changed = billing.apply_event(conn, event)
        if changed:
            audit(conn, "stripe", f"billing.{event.get('type', 'event')}", None, changed)
        conn.commit()
    return {"received": True, "applied": bool(changed)}
