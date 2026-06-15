"""GDPR data-subject endpoints.

  GET  /privacy/me                 - export your own data (self-service DSAR)
  GET  /privacy/export/{user_id}   - export a subject's data        (users.manage)
  POST /privacy/erase/{user_id}    - right to be forgotten (anonymise) (users.delete)

Erasure anonymises rather than deletes (see dashboard_api/privacy.py).
"""
from fastapi import APIRouter, Depends, HTTPException

from dashboard_api import privacy
from dashboard_api.auth import current_user, require_perm
from dashboard_api.db import audit, get_conn, row_to_dict

router = APIRouter(prefix="/privacy", tags=["privacy"])


def _load(conn, user_id: str) -> dict:
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return row_to_dict(row)


@router.get("/me")
def export_self(user: dict = Depends(current_user)):
    """A data subject exports their own personal data."""
    with get_conn() as conn:
        return privacy.export_user(conn, _load(conn, user["id"]))


@router.get("/export/{user_id}")
def export_subject(user_id: str, actor: dict = Depends(require_perm("users.manage"))):
    with get_conn() as conn:
        data = privacy.export_user(conn, _load(conn, user_id))
        audit(conn, actor["email"], "privacy.export", user_id, f"subject={data['subject']}")
        conn.commit()
    return data


@router.post("/erase/{user_id}")
def erase_subject(user_id: str, actor: dict = Depends(require_perm("users.delete"))):
    """Right to be forgotten (anonymisation). Refuses self-erasure (would lock
    out the operator) - use a separate offboarding flow for your own account."""
    if user_id == actor["id"]:
        raise HTTPException(status_code=400, detail="Refusing to erase your own account.")
    with get_conn() as conn:
        subject = _load(conn, user_id)
        res = privacy.erase_user(conn, subject)
        audit(conn, actor["email"], "privacy.erase", user_id,
              f"anonymized rewritten={sum(res['rewritten'].values())}")
        conn.commit()
    return res
