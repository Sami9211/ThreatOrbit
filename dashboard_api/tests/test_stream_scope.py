"""SSE broker tenant-scoping: with isolation ON, a tenant event reaches only the
subscribers in that org; system events (no org) still reach everyone; with
isolation OFF the broker broadcasts exactly as before.
"""
from dashboard_api import events_stream as es
from dashboard_api import tenancy


def _drain(*qs):
    for q in qs:
        while not q.empty():
            q.get_nowait()


def test_publish_scopes_to_org_when_enforced(monkeypatch):
    a = es.subscribe("org-default")
    b = es.subscribe("org-other")
    try:
        # isolation OFF: a tenant-tagged event still reaches everyone (unchanged)
        _drain(a, b)
        es.publish("alert.created", {"id": "x"}, org="org-default")
        assert a.qsize() == 1 and b.qsize() == 1

        monkeypatch.setattr(tenancy, "MULTI_TENANT", True)

        # explicit org → only that org's subscriber
        _drain(a, b)
        es.publish("alert.created", {"id": "y"}, org="org-default")
        assert a.qsize() == 1 and b.qsize() == 0

        # org carried in the payload (data['org_id']) scopes the same way
        _drain(a, b)
        es.publish("case.created", {"id": "z", "org_id": "org-other"})
        assert a.qsize() == 0 and b.qsize() == 1

        # a system event with no org still reaches every subscriber
        _drain(a, b)
        es.publish("tick", {"engine": "ok"})
        assert a.qsize() == 1 and b.qsize() == 1
    finally:
        es.unsubscribe(a)
        es.unsubscribe(b)
        monkeypatch.setattr(tenancy, "MULTI_TENANT", False)
