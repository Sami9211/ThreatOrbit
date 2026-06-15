"""Compliance control mapping endpoint (read-only).

Serves the SOC 2 / ISO 27001 control self-assessment (dashboard_api/compliance.py)
for an in-product compliance view and for procurement security questionnaires.
"""
from fastapi import APIRouter, Depends

from dashboard_api import compliance
from dashboard_api.auth import current_user

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/controls")
def controls(user: dict = Depends(current_user)):
    """The control matrix + status summary + the self-assessment disclaimer."""
    return compliance.as_dict()
