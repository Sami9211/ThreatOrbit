"""/about - deployment identity + posture.

The card in Config → General and any support conversation lean on this being
(a) authenticated, and (b) real introspection: the version constants shipped
in this build and the effective runtime posture, never invented values.
"""
import re

from dashboard_api import version
from dashboard_api.api_versioning import API_VERSION
from dashboard_api.db import SCHEMA_VERSION


def test_about_requires_auth(client):
    assert client.get("/about").status_code == 401


def test_about_reports_build_and_posture(client, auth):
    r = client.get("/about", headers=auth)
    assert r.status_code == 200
    body = r.json()

    # Build identity comes straight from the shipped constants.
    assert body["product_version"] == version.PRODUCT_VERSION
    assert re.fullmatch(r"\d+\.\d+\.\d+.*", body["product_version"])
    assert body["api_version"] == API_VERSION
    assert body["schema_version"] == SCHEMA_VERSION

    # Effective posture - values must be from the known vocabulary, so a
    # rename in config.py can't silently turn the card into nonsense.
    assert body["db_backend"] in ("sqlite", "postgres")
    assert body["data_mode"] in ("demo", "live")
    assert body["engine"] in ("on", "off")
    assert isinstance(body["multi_tenant"], bool)

    # git_sha is honest: a short hex string when known, null otherwise.
    sha = body["git_sha"]
    assert sha is None or re.fullmatch(r"[0-9a-f]{7,12}", sha)


def test_git_sha_env_override(monkeypatch):
    """Deploy pipelines bake GIT_SHA into the environment; it must win over
    any checkout metadata and be truncated to a readable length."""
    monkeypatch.setenv("GIT_SHA", "0123456789abcdef0123")
    assert version._resolve_git_sha() == "0123456789ab"
