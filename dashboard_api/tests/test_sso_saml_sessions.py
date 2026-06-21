"""SSO (OIDC) and SAML logins create a listable/revocable per-device session row
(JWT `sid`), like the interactive login - so an admin can see and sign out an
SSO/SAML device, not just rely on the token-epoch.
"""
import uuid

from dashboard_api import oidc, saml
from dashboard_api.auth import decode_token
from dashboard_api.db import get_conn


def _token_from_redirect(resp) -> str:
    assert resp.status_code == 302, resp.text
    loc = resp.headers["location"]
    assert "sso_token=" in loc, loc
    return loc.split("sso_token=")[1].split("&")[0]


def test_sso_callback_creates_listable_session(client, monkeypatch):
    email = f"sso-{uuid.uuid4().hex[:8]}@acme.com"
    monkeypatch.setattr(oidc, "configured", lambda: True)
    monkeypatch.setattr(oidc, "read_state", lambda s: {"n": "nonce", "r": None})
    monkeypatch.setattr(oidc, "exchange_code", lambda code: {"id_token": "fake"})
    monkeypatch.setattr(oidc, "verify_id_token", lambda tok, nonce: {"email": email})
    monkeypatch.setattr(oidc, "claims_to_user",
                        lambda claims: {"email": email, "name": "SSO User", "role": "analyst"})

    token = _token_from_redirect(client.get("/auth/sso/callback?code=abc&state=xyz", follow_redirects=False))
    sid = decode_token(token).get("sid")
    assert sid, "SSO login token has no per-device session id"
    with get_conn() as conn:
        u = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        sess = conn.execute("SELECT user_id FROM sessions WHERE id=?", (sid,)).fetchone()
    assert sess is not None and sess["user_id"] == u["id"]


def test_saml_acs_creates_listable_session(client, monkeypatch):
    email = f"saml-{uuid.uuid4().hex[:8]}@acme.com"
    monkeypatch.setattr(saml, "configured", lambda: True)
    monkeypatch.setattr(saml, "read_relay_state", lambda r: {"r": None})
    monkeypatch.setattr(saml, "parse_response",
                        lambda resp, relay: {"email": email, "name": "SAML User", "role": "analyst"})

    resp = client.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "y"},
                       follow_redirects=False)
    sid = decode_token(_token_from_redirect(resp)).get("sid")
    assert sid, "SAML login token has no per-device session id"
    with get_conn() as conn:
        u = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        sess = conn.execute("SELECT user_id FROM sessions WHERE id=?", (sid,)).fetchone()
    assert sess is not None and sess["user_id"] == u["id"]
