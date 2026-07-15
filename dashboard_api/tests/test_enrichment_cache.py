"""Enrichment cache-hit contract fence.

The write path stores `json.dumps(data)`; the cache-hit path used to return
the stored column raw — so the SECOND enrich of an indicator within the TTL
handed the API consumer a JSON *string* where the first returned an object.
(Surfaced as a re-run failure against a persistent Postgres DB; it was equally
broken on SQLite for any repeat enrich inside one process's TTL window.)
"""
import uuid


def test_cached_enrichment_data_stays_an_object(client, auth):
    ip = f"203.0.113.{uuid.uuid4().int % 200 + 10}"
    r = client.post("/cti/iocs/import", headers=auth, json={
        "indicators": [{"type": "ip", "value": ip}],
        "source": "cache-test", "severity": "critical",
        "threat_type": "c2", "confidence": 90})
    assert r.status_code in (200, 201), r.text
    iid = client.get(f"/cti/iocs?q={ip}", headers=auth).json()["items"][0]["id"]

    first = client.post(f"/cti/iocs/{iid}/enrich", headers=auth).json()
    p1 = {p["provider"]: p for p in first["providers"]}
    assert isinstance(p1["internal"]["data"], dict)

    second = client.post(f"/cti/iocs/{iid}/enrich", headers=auth).json()
    p2 = {p["provider"]: p for p in second["providers"]}
    assert p2["internal"]["cached"] is True
    # Regression 1: this was a JSON string on the cached path.
    assert isinstance(p2["internal"]["data"], dict)
    assert p2["internal"]["data"] == p1["internal"]["data"]
    assert p2["internal"]["verdict"] == p1["internal"]["verdict"]
    # Regression 2: unavailable results (VirusTotal with no API key) used to be
    # cached and replayed as available=True — fabricated availability on every
    # repeat enrich. Unavailable results are no longer cached at all.
    assert p1["virustotal"]["available"] is False
    assert p2["virustotal"]["available"] is False
