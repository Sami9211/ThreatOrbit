"""OIDC SSO: honest degradation, signed CSRF state, and full ID-token
verification (RS256 signature + claims) against a locally-minted key - no
network or real IdP."""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from dashboard_api import oidc


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _mint(monkeypatch, claims: dict, *, issuer="https://idp.test", client="cid", kid="k1") -> str:
    """Mint a signed RS256 id_token and point oidc at the matching JWKS."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": kid,
           "n": _b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
           "e": _b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}
    monkeypatch.setattr(oidc, "OIDC_ISSUER", issuer)
    monkeypatch.setattr(oidc, "OIDC_CLIENT_ID", client)
    monkeypatch.setattr(oidc, "_jwks", lambda: {"keys": [jwk]})
    h = _b64u(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
    p = _b64u(json.dumps(claims).encode())
    sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64u(sig)}"


def test_sso_status_degrades_without_idp(client):
    s = client.get("/auth/sso/status").json()
    assert s["configured"] is False
    assert client.get("/auth/sso/login", follow_redirects=False).status_code == 404


def test_signed_state_roundtrip():
    state, nonce = oidc.make_state("/dashboard/siem")
    data = oidc.read_state(state)
    assert data["n"] == nonce and data["r"] == "/dashboard/siem"
    assert data.get("cv")                   # a PKCE verifier is bound into the state
    with pytest.raises(ValueError):
        oidc.read_state(state + "x")        # tampered signature
    with pytest.raises(ValueError):
        oidc.read_state("not-a-state")


def test_authorization_url_includes_pkce(monkeypatch):
    """The auth request carries an S256 PKCE challenge derived from the verifier
    that's sealed in the signed state (so the code can't be redeemed elsewhere)."""
    import hashlib
    from urllib.parse import parse_qs, urlparse

    monkeypatch.setattr(oidc, "discovery",
                        lambda: {"authorization_endpoint": "https://idp.test/authorize"})
    monkeypatch.setattr(oidc, "OIDC_CLIENT_ID", "cid")
    monkeypatch.setattr(oidc, "OIDC_REDIRECT_URI", "https://sp.test/cb")
    state, nonce = oidc.make_state("/dashboard")
    q = parse_qs(urlparse(oidc.authorization_url(state, nonce)).query)
    assert q["code_challenge_method"] == ["S256"]
    verifier = oidc.read_state(state)["cv"]
    expected = oidc._code_challenge(verifier)
    assert q["code_challenge"] == [expected]
    # challenge is the base64url SHA-256 of the verifier, never the verifier itself
    assert q["code_challenge"][0] != verifier
    assert oidc._b64u_encode(hashlib.sha256(verifier.encode()).digest()) == expected


def test_id_token_verify_and_role_mapping(monkeypatch):
    claims = {"iss": "https://idp.test", "aud": "cid", "exp": int(time.time()) + 300,
              "nonce": "NONCE", "email": "Jane@Acme.com", "name": "Jane Doe",
              "groups": ["soc-admins"]}
    tok = _mint(monkeypatch, claims)
    verified = oidc.verify_id_token(tok, "NONCE")
    assert verified["email"] == "Jane@Acme.com"

    monkeypatch.setattr(oidc, "OIDC_ROLE_MAP", {"soc-admins": "admin"})
    u = oidc.claims_to_user(verified)
    assert u["email"] == "jane@acme.com" and u["role"] == "admin" and u["name"] == "Jane Doe"

    with pytest.raises(ValueError):                 # nonce mismatch
        oidc.verify_id_token(tok, "WRONG")


def test_id_token_rejects_bad_audience_and_signature(monkeypatch):
    tok = _mint(monkeypatch, {"iss": "https://idp.test", "aud": "someone-else",
                              "exp": int(time.time()) + 300, "nonce": "N"})
    with pytest.raises(ValueError):                 # audience mismatch
        oidc.verify_id_token(tok, "N")

    good = _mint(monkeypatch, {"iss": "https://idp.test", "aud": "cid",
                               "exp": int(time.time()) + 300, "nonce": "N"})
    tampered = good.rsplit(".", 1)[0] + "." + _b64u(b"not-the-real-signature")
    with pytest.raises(ValueError):                 # signature invalid
        oidc.verify_id_token(tampered, "N")


def test_domain_allowlist_and_default_role(monkeypatch):
    monkeypatch.setattr(oidc, "OIDC_ALLOWED_DOMAINS", ["acme.com"])
    monkeypatch.setattr(oidc, "OIDC_ROLE_MAP", {})
    monkeypatch.setattr(oidc, "OIDC_DEFAULT_ROLE", "analyst")
    with pytest.raises(ValueError):
        oidc.claims_to_user({"email": "intruder@evil.com"})
    u = oidc.claims_to_user({"email": "ok@acme.com", "name": "Ok"})
    assert u["role"] == "analyst"          # default when no group maps
