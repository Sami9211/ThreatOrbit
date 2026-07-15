"""OpenID Connect SSO (optional, opt-in).

Authorization-code flow against any OIDC provider. With no OIDC_ISSUER every
entry point degrades to "not configured" and email+password is unaffected.

Security notes:
  * the ID token's RS256 signature is verified against the provider's JWKS
    using `cryptography` (already a dependency via Fernet) - no PyJWT;
  * standard claim checks: issuer, audience (client_id), expiry, and the nonce
    we planted in the login request;
  * CSRF state + nonce are carried in a short-lived value signed with the
    dashboard's JWT secret, so no server-side session store is needed;
  * an optional email-domain allowlist gates which users may be provisioned.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import urlencode

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from dashboard_api.config import (
    JWT_SECRET, OIDC_ALLOWED_DOMAINS, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET,
    OIDC_DEFAULT_ROLE, OIDC_GROUPS_CLAIM, OIDC_ISSUER, OIDC_REDIRECT_URI,
    OIDC_ROLE_MAP, OIDC_SCOPES,
)

_HTTP_TIMEOUT = 15.0
_STATE_TTL = 600          # 10 minutes to complete the round-trip
_VALID_ROLES = {"admin", "manager", "analyst", "viewer"}

# Tiny TTL cache for discovery + JWKS (small docs, but don't hammer the IdP).
_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 300


def configured() -> bool:
    return bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI)


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _cached(key: str, url: str) -> dict:
    now = time.time()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    r = httpx.get(url, timeout=_HTTP_TIMEOUT)
    r.raise_for_status()
    doc = r.json()
    _cache[key] = (now + _CACHE_TTL, doc)
    return doc


def discovery() -> dict:
    """The provider's OIDC configuration document."""
    return _cached("discovery", f"{OIDC_ISSUER}/.well-known/openid-configuration")


def _jwks() -> dict:
    return _cached("jwks", discovery()["jwks_uri"])


# -- CSRF state (stateless, signed with the dashboard JWT secret) --------------

def _sign_state(payload: dict) -> str:
    body = _b64u_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64u_encode(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def make_state(return_to: str | None) -> tuple[str, str]:
    """Return (state, nonce). The nonce and a PKCE code_verifier are bound
    together inside the signed state, so the round-trip needs no server-side
    session store: the IdP echoes `state` back and we recover the verifier from it
    at the token exchange."""
    nonce = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(48)   # PKCE (RFC 7636): 43-128 url-safe chars
    state = _sign_state({"n": nonce, "r": return_to or "", "cv": code_verifier,
                         "exp": int(time.time()) + _STATE_TTL})
    return state, nonce


def _code_challenge(verifier: str) -> str:
    """PKCE S256 challenge: base64url(SHA256(verifier)), no padding."""
    return _b64u_encode(hashlib.sha256(verifier.encode()).digest())


def read_state(state: str) -> dict:
    """Verify a signed state and return its payload. Raises ValueError if bad."""
    try:
        body, _, sig = state.partition(".")
        expected = _b64u_encode(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            raise ValueError("state signature mismatch")
        data = json.loads(_b64u_decode(body))
    except ValueError:
        raise
    except Exception:
        raise ValueError("malformed state")
    if int(data.get("exp", 0)) < int(time.time()):
        raise ValueError("state expired")
    return data


def authorization_url(state: str, nonce: str) -> str:
    params = {
        "response_type": "code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI,
        "scope": OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
    }
    # PKCE: derive the S256 challenge from the verifier carried in the signed
    # state (OAuth 2.1 expects PKCE even for confidential clients; it binds the
    # auth code to this client so a stolen code can't be redeemed elsewhere).
    try:
        verifier = read_state(state).get("cv")
    except ValueError:
        verifier = None
    if verifier:
        params["code_challenge"] = _code_challenge(verifier)
        params["code_challenge_method"] = "S256"
    return f"{discovery()['authorization_endpoint']}?{urlencode(params)}"


def exchange_code(code: str, code_verifier: str | None = None) -> dict:
    """Swap an authorization code for tokens at the token endpoint (TLS, with
    the confidential client's secret). Sends the PKCE `code_verifier` when one
    was planted in the login request."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OIDC_REDIRECT_URI,
        "client_id": OIDC_CLIENT_ID,
        "client_secret": OIDC_CLIENT_SECRET,
    }
    if code_verifier:
        data["code_verifier"] = code_verifier
    r = httpx.post(discovery()["token_endpoint"], timeout=_HTTP_TIMEOUT, data=data)
    if r.status_code >= 400:
        raise ValueError(f"token exchange failed ({r.status_code})")
    return r.json()


def _rsa_key_for(kid: str | None):
    keys = [k for k in _jwks().get("keys", []) if k.get("kty") == "RSA"]
    if kid:
        # Require an exact kid match - do NOT silently fall back to another key,
        # so a token can only be verified with the key its header points to.
        jwk = next((k for k in keys if k.get("kid") == kid), None)
        if not jwk:
            raise ValueError("no JWKS key matches the token's kid")
    else:
        # No kid in the header: only unambiguous when the IdP publishes one RSA key.
        if len(keys) != 1:
            raise ValueError("token has no kid and the JWKS is ambiguous")
        jwk = keys[0]
    e = int.from_bytes(_b64u_decode(jwk["e"]), "big")
    n = int.from_bytes(_b64u_decode(jwk["n"]), "big")
    return RSAPublicNumbers(e, n).public_key()


def verify_id_token(id_token: str, nonce: str) -> dict:
    """Verify the ID token's RS256 signature + standard claims; return claims."""
    try:
        header_b64, payload_b64, sig_b64 = id_token.split(".")
    except ValueError:
        raise ValueError("malformed id_token")
    header = json.loads(_b64u_decode(header_b64))
    if header.get("alg") != "RS256":
        raise ValueError(f"unsupported id_token alg: {header.get('alg')}")
    pub = _rsa_key_for(header.get("kid"))
    try:
        pub.verify(_b64u_decode(sig_b64), f"{header_b64}.{payload_b64}".encode(),
                   padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise ValueError("id_token signature invalid")
    claims = json.loads(_b64u_decode(payload_b64))

    if claims.get("iss", "").rstrip("/") != OIDC_ISSUER:
        raise ValueError("issuer mismatch")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if OIDC_CLIENT_ID not in auds:
        raise ValueError("audience mismatch")
    if int(claims.get("exp", 0)) < int(time.time()):
        raise ValueError("id_token expired")
    if claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch")
    return claims


def map_role(groups: list[str]) -> str:
    for g in groups:
        if g in OIDC_ROLE_MAP and OIDC_ROLE_MAP[g] in _VALID_ROLES:
            return OIDC_ROLE_MAP[g]
    return OIDC_DEFAULT_ROLE if OIDC_DEFAULT_ROLE in _VALID_ROLES else "viewer"


def claims_to_user(claims: dict) -> dict:
    """Map verified ID-token claims to a user record. Raises ValueError when the
    email is missing or its domain isn't allowed."""
    email = (claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("the provider did not return an email")
    if OIDC_ALLOWED_DOMAINS and email.split("@", 1)[1] not in OIDC_ALLOWED_DOMAINS:
        raise ValueError("your email domain is not permitted for SSO")
    raw_groups = claims.get(OIDC_GROUPS_CLAIM) or []
    groups = raw_groups if isinstance(raw_groups, list) else [raw_groups]
    name = claims.get("name") or claims.get("preferred_username") or email.split("@", 1)[0]
    return {"email": email, "name": str(name), "groups": [str(g) for g in groups],
            "role": map_role([str(g) for g in groups])}
