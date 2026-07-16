"""API stability contract.

The ``/v1`` alias must serve the same handlers as the unversioned paths, and
the documented path surface (``docs/api/v1-paths.json``) may not silently shrink
- a route can't disappear without a conscious version decision. See
``docs/API_VERSIONING.md``.
"""
import json
import os

from dashboard_api.main import app
from dashboard_api.api_versioning import stable_paths

_PATHS_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "api", "v1-paths.json")


def test_v1_login_alias_returns_token(client):
    r = client.post("/v1/auth/login",
                    json={"email": "admin@threatorbit.space", "password": "ChangeMe123!"})
    assert r.status_code == 200, r.text
    assert r.json().get("token")
    assert r.headers.get("x-api-version") == "v1"


def test_v1_alias_matches_unversioned(client, auth):
    v1 = client.get("/v1/siem/alerts?limit=5", headers=auth)
    plain = client.get("/siem/alerts?limit=5", headers=auth)
    assert v1.status_code == 200 and plain.status_code == 200
    assert v1.headers.get("x-api-version") == "v1"
    # the unversioned path is the (untagged) legacy alias
    assert plain.headers.get("x-api-version") is None
    assert set(v1.json().keys()) == set(plain.json().keys())


def test_v1_meta_alias(client):
    r = client.get("/v1/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers.get("x-api-version") == "v1"


def test_unknown_v1_path_is_404(client, auth):
    assert client.get("/v1/nope/nothing", headers=auth).status_code == 404


def test_openapi_version_is_set():
    assert app.openapi()["info"]["version"] == "1.0.0"


def test_mark_deprecated_sets_rfc8594_headers():
    from starlette.responses import Response
    from dashboard_api.api_versioning import mark_deprecated
    r = Response()
    mark_deprecated(r, sunset="Wed, 01 Jan 2027 00:00:00 GMT")
    assert r.headers["Deprecation"] == "true"
    assert r.headers["Sunset"].startswith("Wed, 01 Jan 2027")


def test_no_documented_path_removed():
    """The committed stable surface must stay a subset of what the app serves.
    Adding routes is fine; removing one fails here (bump the API version
    instead). Refresh with: python scripts/openapi_snapshot.py"""
    with open(_PATHS_FILE) as fh:
        committed = json.load(fh)["paths"]
    live = set(stable_paths(app))
    missing = [p for p in committed if p not in live]
    assert not missing, f"documented paths removed without a version bump: {missing}"


def test_no_live_path_undocumented():
    """The reverse fence: every route the app serves must be in the committed
    surface, or the API doc silently rots as features land (12 endpoints had
    drifted undocumented when this fence was added). Adding an endpoint?
    Refresh the snapshot in the same change: python scripts/openapi_snapshot.py"""
    with open(_PATHS_FILE) as fh:
        committed = set(json.load(fh)["paths"])
    undocumented = [p for p in stable_paths(app) if p not in committed]
    assert not undocumented, (
        "new endpoints missing from docs/api/v1-paths.json "
        f"(run: python scripts/openapi_snapshot.py): {undocumented}"
    )
