"""SCIM 2.0 provisioning tests.

Covers the degradation-when-unconfigured contract, bearer-token auth, the full
User lifecycle an IdP drives (create / read / list+filter / dedup / PATCH
deactivate-reactivate / PUT replace / DELETE soft-disable / role mapping), and
the pure mapping helpers.
"""
import pytest

from dashboard_api import scim
from dashboard_api.db import get_conn

TOKEN = "scim-test-token-0123456789abcdef"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def scim_on(monkeypatch):
    """Turn SCIM on for a test by patching the token the module + router read."""
    monkeypatch.setattr("dashboard_api.scim.SCIM_TOKEN", TOKEN)
    monkeypatch.setattr("dashboard_api.routers.scim.SCIM_TOKEN", TOKEN)
    return TOKEN


def _make(client, email, **extra):
    body = {"schemas": [scim.USER_SCHEMA], "userName": email,
            "name": {"givenName": "Ada", "familyName": "Lovelace"}, "active": True, **extra}
    return client.post("/scim/v2/Users", headers=AUTH, json=body)


# -- degradation + auth ------------------------------------------------------

def test_unconfigured_returns_404(client):
    # No SCIM_TOKEN set → the whole surface is 404 (feature off).
    assert client.get("/scim/v2/Users", headers=AUTH).status_code == 404


def test_requires_bearer_token(client, scim_on):
    assert client.get("/scim/v2/Users").status_code == 401
    assert client.get("/scim/v2/Users", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/scim/v2/Users", headers=AUTH).status_code == 200


def test_discovery_documents(client, scim_on):
    spc = client.get("/scim/v2/ServiceProviderConfig", headers=AUTH).json()
    assert spc["patch"]["supported"] is True and spc["filter"]["supported"] is True
    rt = client.get("/scim/v2/ResourceTypes", headers=AUTH).json()
    assert rt["Resources"][0]["endpoint"] == "/Users"
    sch = client.get("/scim/v2/Schemas", headers=AUTH).json()
    assert sch["Resources"][0]["id"] == scim.USER_SCHEMA


# -- lifecycle ---------------------------------------------------------------

def test_create_read_filter_and_dedup(client, scim_on):
    email = "scim.ada@threatorbit.space"
    r = _make(client, email)
    assert r.status_code == 201, r.text
    u = r.json()
    assert u["userName"] == email and u["active"] is True and scim.USER_SCHEMA in u["schemas"]
    uid = u["id"]

    assert client.get(f"/scim/v2/Users/{uid}", headers=AUTH).json()["id"] == uid

    lst = client.get("/scim/v2/Users", headers=AUTH,
                     params={"filter": f'userName eq "{email}"'}).json()
    assert lst["totalResults"] == 1 and lst["Resources"][0]["id"] == uid

    # duplicate userName → 409
    assert _make(client, email).status_code == 409
    # unsupported filter → empty result, never the full list
    empty = client.get("/scim/v2/Users", headers=AUTH,
                       params={"filter": 'displayName eq "x"'}).json()
    assert empty["totalResults"] == 0 and empty["Resources"] == []


def test_patch_deactivate_then_reactivate(client, scim_on):
    uid = _make(client, "scim.deact@threatorbit.space").json()["id"]
    deact = {"schemas": [scim.PATCH_SCHEMA],
             "Operations": [{"op": "replace", "path": "active", "value": False}]}
    assert client.patch(f"/scim/v2/Users/{uid}", headers=AUTH, json=deact).json()["active"] is False
    # pathless replace map (Azure AD style)
    react = {"schemas": [scim.PATCH_SCHEMA],
             "Operations": [{"op": "replace", "value": {"active": True}}]}
    assert client.patch(f"/scim/v2/Users/{uid}", headers=AUTH, json=react).json()["active"] is True


def test_put_replace_updates_profile(client, scim_on):
    uid = _make(client, "scim.put@threatorbit.space").json()["id"]
    body = {"schemas": [scim.USER_SCHEMA], "userName": "scim.put@threatorbit.space",
            "name": {"formatted": "Grace Hopper"}, "active": False}
    r = client.put(f"/scim/v2/Users/{uid}", headers=AUTH, json=body).json()
    assert r["displayName"] == "Grace Hopper" and r["active"] is False


def test_delete_soft_disables(client, scim_on):
    uid = _make(client, "scim.del@threatorbit.space").json()["id"]
    assert client.delete(f"/scim/v2/Users/{uid}", headers=AUTH).status_code == 204
    # still present, but deactivated (records owned by the user aren't orphaned)
    assert client.get(f"/scim/v2/Users/{uid}", headers=AUTH).json()["active"] is False


def test_role_mapping_from_scim_roles(client, scim_on, monkeypatch):
    monkeypatch.setattr("dashboard_api.scim.SCIM_ROLE_MAP", {"soc-admins": "admin"})
    email = "scim.admin@threatorbit.space"
    assert _make(client, email, roles=[{"value": "soc-admins"}]).status_code == 201
    with get_conn() as conn:
        role = conn.execute("SELECT role FROM users WHERE email=?", (email,)).fetchone()["role"]
    assert role == "admin"


def test_missing_email_is_400(client, scim_on):
    r = client.post("/scim/v2/Users", headers=AUTH,
                    json={"schemas": [scim.USER_SCHEMA], "name": {"givenName": "x"}})
    assert r.status_code == 400


# -- pure mappers ------------------------------------------------------------

def test_from_scim_pulls_email_from_emails_array():
    out = scim.from_scim({"emails": [{"value": "X@Y.COM", "primary": True}]})
    assert out["email"] == "x@y.com" and out["status"] == "active"


def test_from_scim_requires_email():
    with pytest.raises(ValueError):
        scim.from_scim({"name": {"givenName": "x"}})


def test_apply_patch_active_toggle():
    u = {"name": "A", "status": "active", "email": "a@b.com"}
    assert scim.apply_patch(u, [{"op": "replace", "path": "active", "value": False}])["status"] == "disabled"
    assert scim.apply_patch(u, [{"op": "Replace", "value": {"active": False}}])["status"] == "disabled"
