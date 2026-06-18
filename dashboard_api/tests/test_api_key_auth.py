"""Non-interactive API-key authentication.

Issued keys (collectors, CI, integrations) must authenticate as a service
principal whose scope maps onto the role matrix: read→viewer, write→analyst,
admin→admin. A key works via Authorization: Bearer OR the X-API-Key header,
is rejected once revoked, and a forged key is rejected. This is the credential
the lightweight collector ships with.
"""
import pytest


def _make_key(client, auth, scope):
    r = client.post("/config/api-keys", headers=auth, json={"name": f"k-{scope}", "scope": scope})
    assert r.status_code == 201, r.text
    return r.json()["secret"]


def test_write_key_authenticates_both_headers(client, auth):
    secret = _make_key(client, auth, "write")
    # Authorization: Bearer <key>
    r1 = client.get("/siem/triage", headers={"Authorization": f"Bearer {secret}"})
    assert r1.status_code == 200, r1.text
    # X-API-Key: <key>
    r2 = client.get("/siem/triage", headers={"X-API-Key": secret})
    assert r2.status_code == 200, r2.text
    # write scope → analyst → can ingest logs
    r3 = client.post("/siem/ingest", headers={"X-API-Key": secret},
                     json={"lines": ["127.0.0.1 - - [01/Jan/2020:00:00:00] \"GET / HTTP/1.1\" 200 1"],
                           "format": "auto", "source": "pytest-collector"})
    assert r3.status_code == 200, r3.text


def test_scope_maps_to_role_permissions(client, auth):
    # read scope → viewer → cannot mint keys (config.manage denied)
    read_key = _make_key(client, auth, "read")
    denied = client.post("/config/api-keys", headers={"X-API-Key": read_key},
                         json={"name": "nope", "scope": "read"})
    assert denied.status_code == 403, denied.text
    # but can read
    assert client.get("/siem/kpis", headers={"X-API-Key": read_key}).status_code == 200

    # admin scope → admin → can mint keys
    admin_key = _make_key(client, auth, "admin")
    ok = client.post("/config/api-keys", headers={"X-API-Key": admin_key},
                     json={"name": "by-admin-key", "scope": "read"})
    assert ok.status_code == 201, ok.text


def test_revoked_key_is_rejected(client, auth):
    r = client.post("/config/api-keys", headers=auth, json={"name": "to-revoke", "scope": "write"})
    body = r.json()
    secret, kid = body["secret"], body["id"]
    assert client.get("/siem/triage", headers={"X-API-Key": secret}).status_code == 200
    assert client.delete(f"/config/api-keys/{kid}", headers=auth).status_code == 204
    assert client.get("/siem/triage", headers={"X-API-Key": secret}).status_code == 401


@pytest.mark.parametrize("forged", [
    "to_sk_live_deadbeefdeadbeefdeadbeefdeadbeef",
    "to_ak_live_0000000000000000000000000000",
    "to_rk_live_not_a_real_key",
])
def test_forged_key_rejected(client, forged):
    assert client.get("/siem/triage", headers={"X-API-Key": forged}).status_code == 401


def test_missing_credentials_rejected(client):
    assert client.get("/siem/triage").status_code == 401
