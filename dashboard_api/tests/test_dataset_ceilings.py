"""UI dataset ceilings: every list endpoint caps its `limit`, so a client can't
force an unbounded result set (memory/DoS). An over-cap value is rejected (422);
the cap itself is accepted.
"""
import pytest


@pytest.mark.parametrize("path,cap", [
    ("/overview/recent-alerts", 200),
    ("/config/jobs", 500),
    ("/config/audit-log", 2000),
    ("/soar/runs", 500),
    ("/assets/discovered", 1000),
])
def test_list_endpoints_enforce_dataset_ceilings(client, auth, path, cap):
    over = client.get(f"{path}?limit={cap + 1}", headers=auth)
    assert over.status_code == 422, f"{path} accepted limit>{cap}: {over.status_code}"
    at = client.get(f"{path}?limit={cap}", headers=auth)
    assert at.status_code == 200, f"{path} rejected limit={cap}: {at.status_code} {at.text[:120]}"
