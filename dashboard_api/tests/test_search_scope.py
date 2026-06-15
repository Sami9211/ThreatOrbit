"""Global search is tenant-scoped: with isolation ON, the one search box must
not surface another workspace's alerts/IOCs/assets (a cross-tenant leak).
Mirrors the list-endpoint isolation pattern; a no-op when isolation is OFF.
"""
import uuid

from dashboard_api import tenancy
from dashboard_api.db import get_conn


def _seed_two_orgs(marker):
    with get_conn() as conn:
        for org in ("org-default", "org-other"):
            conn.execute(
                "INSERT INTO alerts (id,ts,title,severity,status,disposition,owner,risk_score,"
                "rule_id,rule_name,description,raw_log,event_count,ti_hits,org_id) "
                "VALUES (?,datetime('now'),?,'medium','new','undetermined','',50,'R-T','t',?,'',1,0,?)",
                (str(uuid.uuid4()), f"{marker} {org}", marker, org))
            conn.execute(
                "INSERT INTO iocs (id,type,value,threat_type,confidence,severity,source,actor,"
                "first_seen,last_seen,tags,org_id) VALUES (?,?,?,?,50,'low',?, '',"
                "datetime('now'),datetime('now'),'[]',?)",
                (str(uuid.uuid4()), "domain", f"{marker}-{org}.test", marker, marker, org))
        conn.commit()


def test_global_search_is_tenant_scoped(client, auth, monkeypatch):
    marker = f"SRCH-{uuid.uuid4().hex[:6]}"
    _seed_two_orgs(marker)

    def search():
        return client.get(f"/search?q={marker}&limit=25", headers=auth).json()["results"]

    # default: isolation off → both workspaces' hits are visible
    off = search()
    assert sum(1 for r in off if r["kind"] == "alert") == 2
    assert sum(1 for r in off if r["kind"] == "ioc") == 2

    # isolation on → the admin (org-default) only sees their own workspace
    monkeypatch.setattr(tenancy, "MULTI_TENANT", True)
    on = search()
    assert sum(1 for r in on if r["kind"] == "alert") == 1
    assert sum(1 for r in on if r["kind"] == "ioc") == 1
    # the foreign-workspace rows (…-org-other) are absent
    assert not any("org-other" in (r["sub"] or "") or "org-other" in (r["label"] or "") for r in on)

    monkeypatch.setattr(tenancy, "MULTI_TENANT", False)
    assert sum(1 for r in search() if r["kind"] == "alert") == 2
