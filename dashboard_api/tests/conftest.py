"""Test fixtures: isolated temp DB, seeded data, authenticated client."""
import os
import tempfile

import pytest

# Point the app at a throwaway database before importing app modules.
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DASHBOARD_DB_PATH"] = _tmp.name
os.environ["DASHBOARD_JWT_SECRET"] = "test-secret"
os.environ["DASHBOARD_ADMIN_EMAIL"] = "admin@threatorbit.space"
os.environ["DASHBOARD_ADMIN_PASSWORD"] = "ChangeMe123!"
# The webhook-delivery tests post to a local sink (127.0.0.1); allow private
# targets here. The SSRF guard's blocking behaviour is covered directly in
# test_net_guard.py (which calls it with allow_private=False).
os.environ["DASHBOARD_ALLOW_PRIVATE_URLS"] = "true"
# Never let the suite depend on external registries: RDAP enrichment reports
# an honest "disabled" instead of making live rdap.org calls. The parser is
# covered in test_scanner_lookup.py with a monkeypatched transport.
os.environ["DASHBOARD_DISABLE_RDAP"] = "true"
# Same reasoning for passive DNS: a suite that resolves real names is slow, is
# non-deterministic, and fails on an air-gapped runner for reasons that have
# nothing to do with the code. The recording, merging and pivot logic is covered
# in test_passive_dns.py against a stubbed resolver.
os.environ["DASHBOARD_DISABLE_DNS"] = "true"

from fastapi.testclient import TestClient  # noqa: E402

from dashboard_api.db import init_db  # noqa: E402
from dashboard_api.main import app  # noqa: E402
from dashboard_api.seed import seed  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _db():
    init_db()
    seed(force=True)
    yield
    try:
        os.unlink(_tmp.name)
    except OSError:
        pass


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def admin_token(client):
    r = client.post("/auth/login", json={"email": "admin@threatorbit.space", "password": "ChangeMe123!"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture()
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
