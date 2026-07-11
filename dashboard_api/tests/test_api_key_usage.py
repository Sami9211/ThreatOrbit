"""Per-API-key usage telemetry: every authenticated key request bumps a
day bucket (api_key_usage), which drives the real 'Requests Today' / total
counters on Config → API. These replaced fabricated frontend numbers (a
nonexistent '1M/mo' rate limit and a hardcoded requests column), so the
contract matters: counted on use, zero when fresh, frozen after revoke."""
import uuid


def test_api_key_usage_counted_and_listed(client, auth):
    r = client.post("/config/api-keys",
                    json={"name": f"usage-{uuid.uuid4().hex[:6]}", "scope": "read"},
                    headers=auth)
    assert r.status_code == 201, r.text
    created = r.json()
    kid, secret = created["id"], created["secret"]

    def my_row():
        rows = client.get("/config/api-keys", headers=auth).json()
        return next(k for k in rows if k["id"] == kid)

    # fresh key: honest zeros, not absent fields
    me = my_row()
    assert me["requests_today"] == 0
    assert me["requests_total"] == 0

    kh = {"Authorization": f"Bearer {secret}"}
    for _ in range(3):
        assert client.get("/siem/kpis", headers=kh).status_code == 200

    me = my_row()
    assert me["requests_today"] == 3
    assert me["requests_total"] == 3
    assert me["last_used"], "authenticated use must stamp last_used"

    # revoked key: request is rejected AND the rejection is not counted
    assert client.delete(f"/config/api-keys/{kid}", headers=auth).status_code == 204
    assert client.get("/siem/kpis", headers=kh).status_code == 401
    me = my_row()
    assert me["requests_today"] == 3, "rejected requests must not count as usage"


def test_api_key_usage_is_per_key(client, auth):
    keys = []
    for i in range(2):
        r = client.post("/config/api-keys",
                        json={"name": f"iso-{i}-{uuid.uuid4().hex[:6]}", "scope": "read"},
                        headers=auth)
        assert r.status_code == 201
        keys.append(r.json())

    # use key A twice, key B once — counts must not bleed across keys
    ha = {"Authorization": f"Bearer {keys[0]['secret']}"}
    hb = {"Authorization": f"Bearer {keys[1]['secret']}"}
    assert client.get("/siem/kpis", headers=ha).status_code == 200
    assert client.get("/siem/kpis", headers=ha).status_code == 200
    assert client.get("/siem/kpis", headers=hb).status_code == 200

    rows = client.get("/config/api-keys", headers=auth).json()
    a = next(k for k in rows if k["id"] == keys[0]["id"])
    b = next(k for k in rows if k["id"] == keys[1]["id"])
    assert a["requests_today"] == 2
    assert b["requests_today"] == 1

    for k in keys:   # cleanup: revoke
        client.delete(f"/config/api-keys/{k['id']}", headers=auth)
