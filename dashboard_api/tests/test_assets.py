"""Asset deletion test - delete persists (the bug was: no DELETE endpoint, so a
removed asset reappeared on refresh)."""
import uuid


def test_create_then_delete_asset_persists(client, auth):
    r = client.post("/assets", headers=auth, json={
        "name": f"box-{uuid.uuid4().hex[:6]}", "type": "server",
        "value": "10.0.0.9", "criticality": "high"})
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    # present
    assert client.get(f"/assets/{aid}", headers=auth).status_code == 200
    # delete -> 204
    assert client.delete(f"/assets/{aid}", headers=auth).status_code == 204
    # gone, and stays gone (no resurrection on reload)
    assert client.get(f"/assets/{aid}", headers=auth).status_code == 404
    ids = {a["id"] for a in client.get("/assets", headers=auth).json()["items"]}
    assert aid not in ids
    # deleting again is a clean 404
    assert client.delete(f"/assets/{aid}", headers=auth).status_code == 404
