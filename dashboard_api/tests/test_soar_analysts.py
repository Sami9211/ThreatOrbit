"""SOC-metrics analyst leaderboard / throughput is REAL - aggregated from the
cases each analyst owns - not a hardcoded list (audit: dashboard widgets that
render demo data as if live).
"""


def test_analysts_leaderboard_is_aggregated_from_cases(client, auth):
    owner = "leaderboard-test@acme.com"
    r = client.post("/soar/cases", json={"title": "LB-1", "severity": "high", "owner": owner},
                    headers=auth)
    assert r.status_code == 201, r.text
    client.post("/soar/cases", json={"title": "LB-2", "severity": "critical", "owner": owner},
                headers=auth)

    rows = client.get("/soar/analysts", headers=auth)
    assert rows.status_code == 200
    data = rows.json()
    assert isinstance(data, list)
    me = next((a for a in data if a["name"] == owner), None)
    assert me is not None, "the case owner should appear in the analyst leaderboard"
    assert me["handled"] >= 2
    assert me["open"] >= 2                       # freshly-created cases are open
    assert me["handled"] >= me["closed"]
    assert {"closed", "critical", "avgResolveMins"} <= set(me.keys())


def test_analysts_endpoint_requires_auth(client):
    assert client.get("/soar/analysts").status_code in (401, 403)
