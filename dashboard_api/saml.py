"""SAML 2.0 Service Provider (SP-initiated Web Browser SSO), optional + opt-in.

For IdPs that speak SAML rather than OIDC. With no SAML_IDP_* configured the
endpoints degrade to "not configured" and email+password is unaffected.

Security model (the parts that matter):
  * the assertion's XML signature is verified with **signxml** against the IdP's
    pinned X.509 cert - the cert embedded in the message's KeyInfo is NOT
    trusted on its own;
  * everything we then read is taken ONLY from the element signxml reports as
    signed (`signed_xml`), which defeats XML signature-wrapping (XSW) - an
    injected unsigned assertion is never consulted;
  * we enforce Issuer, Audience, SubjectConfirmation Recipient, the Conditions
    and SubjectConfirmation time windows (with small clock skew), and bind the
    response to our request via InResponseTo;
  * assertion IDs are one-time-use (DB-backed replay cache) within their
    validity window;
  * XML is parsed by signxml's hardened parser (no external entities / DTD), so
    XXE/SSRF via a crafted DOCTYPE is not reachable.

The replay cache is a shared DB table (`saml_replay`), so one-time-use holds
across workers/replicas and survives a restart - not a per-process set. The time
window + InResponseTo binding bound replay even without it.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
import zlib
from datetime import datetime, timezone
from urllib.parse import urlencode

from dashboard_api.config import (
    JWT_SECRET, SAML_ALLOWED_DOMAINS, SAML_DEFAULT_ROLE, SAML_EMAIL_ATTR,
    SAML_GROUPS_ATTR, SAML_IDP_CERT, SAML_IDP_ENTITY_ID, SAML_IDP_SSO_URL,
    SAML_NAME_ATTR, SAML_ROLE_MAP, SAML_SP_ACS_URL, SAML_SP_ENTITY_ID,
)

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}
_VALID_ROLES = {"admin", "manager", "analyst", "viewer"}
_SKEW = 120  # seconds of clock skew tolerance
_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

def _replay_seen(aid: str, now_ts: float) -> bool:
    """True if `aid` is already in the shared replay cache (within its window).
    Prunes expired rows on the way through. DB-backed so it holds across
    workers/replicas, not a per-process set."""
    from dashboard_api.db import get_conn
    with get_conn() as conn:
        conn.execute("DELETE FROM saml_replay WHERE expires_at <= ?", (now_ts,))
        conn.commit()
        return conn.execute(
            "SELECT 1 FROM saml_replay WHERE assertion_id=? AND expires_at > ?",
            (aid, now_ts)).fetchone() is not None


def _replay_record(aid: str, expiry_ts: float) -> None:
    """Mark `aid` one-time-used until `expiry_ts` (committed only after the
    assertion has fully validated, mirroring the prior in-process behaviour)."""
    from dashboard_api.db import get_conn
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO saml_replay (assertion_id, expires_at) VALUES (?,?)",
            (aid, expiry_ts))
        conn.commit()


def configured() -> bool:
    return bool(SAML_IDP_ENTITY_ID and SAML_IDP_SSO_URL and SAML_IDP_CERT)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def cert_pem() -> str:
    """Normalise the configured IdP cert to PEM (accept a bare base64 DER body)."""
    c = SAML_IDP_CERT.strip()
    if "BEGIN CERTIFICATE" in c:
        return c
    body = "".join(c.split())
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


# ── SP-initiated request ──────────────────────────────────────────────────────

def make_authn_request() -> tuple[str, str]:
    """Build an AuthnRequest and the IdP redirect URL (HTTP-Redirect binding).
    Returns (request_id, redirect_url). The caller carries request_id in a signed
    RelayState so the ACS can check InResponseTo."""
    rid = "_" + secrets.token_hex(20)
    issue = _now().strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{rid}" Version="2.0" IssueInstant="{issue}" '
        f'Destination="{_xml_attr(SAML_IDP_SSO_URL)}" '
        f'AssertionConsumerServiceURL="{_xml_attr(SAML_SP_ACS_URL)}" '
        f'ProtocolBinding="{_POST_BINDING}">'
        f'<saml:Issuer>{_xml_text(SAML_SP_ENTITY_ID)}</saml:Issuer>'
        '</samlp:AuthnRequest>'
    )
    # HTTP-Redirect binding: raw DEFLATE + base64 + urlencode.
    deflated = zlib.compress(xml.encode())[2:-4]
    saml_req = base64.b64encode(deflated).decode()
    sep = "&" if "?" in SAML_IDP_SSO_URL else "?"
    return rid, f"{SAML_IDP_SSO_URL}{sep}{urlencode({'SAMLRequest': saml_req})}"


def _xml_attr(s: str) -> str:
    return s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")


def _xml_text(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── Response verification ─────────────────────────────────────────────────────

def _parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _text(el):
    return (el.text or "").strip() if el is not None else ""


def parse_response(saml_response_b64: str, expected_in_response_to: str,
                   now: datetime | None = None) -> dict:
    """Verify a base64 SAMLResponse and return {email, name, groups, role}.

    Raises ValueError on any signature, schema, binding, or policy failure.
    """
    from signxml import XMLVerifier  # imported lazily: only when SAML is used
    from lxml import etree

    now = now or _now()
    try:
        xml_bytes = base64.b64decode(saml_response_b64, validate=True)
    except Exception:
        raise ValueError("malformed SAMLResponse encoding")

    # signxml parses with a hardened (no-XXE) parser and verifies the signature
    # against OUR pinned cert; the embedded KeyInfo cert is not trusted alone.
    try:
        signed = XMLVerifier().verify(xml_bytes, x509_cert=cert_pem()).signed_xml
    except Exception:
        raise ValueError("SAML signature verification failed")
    if signed is None:
        raise ValueError("no signed element in SAMLResponse")

    # Only ever read from the signed subtree (XSW defense). The signed element is
    # either the Assertion itself or a Response that contains it.
    tag = etree.QName(signed).localname
    if tag == "Assertion":
        assertion = signed
    elif tag == "Response":
        assertion = signed.find("saml:Assertion", NS)
    else:
        assertion = None
    if assertion is None:
        raise ValueError("the signature does not cover a SAML assertion")

    # Issuer
    if _text(assertion.find("saml:Issuer", NS)) != SAML_IDP_ENTITY_ID:
        raise ValueError("assertion issuer mismatch")

    # One-time-use (replay) on the assertion ID
    aid = assertion.get("ID") or ""
    if not aid or _replay_seen(aid, now.timestamp()):
        raise ValueError("assertion replay detected")

    # Conditions: validity window + audience
    cond = assertion.find("saml:Conditions", NS)
    nb = _parse_time(cond.get("NotBefore")) if cond is not None else None
    noa = _parse_time(cond.get("NotOnOrAfter")) if cond is not None else None
    if nb and now + _skew() < nb:
        raise ValueError("assertion not yet valid")
    if noa and now - _skew() >= noa:
        raise ValueError("assertion expired")
    audiences = [_text(a) for a in assertion.findall(
        "saml:Conditions/saml:AudienceRestriction/saml:Audience", NS)]
    # Require an AudienceRestriction for SP-initiated SSO: an assertion with no
    # audience at all could have been minted for a *different* SP and replayed at
    # ours, so absence is rejected (not just a wrong value).
    if not audiences:
        raise ValueError("assertion is missing a required audience restriction")
    if SAML_SP_ENTITY_ID not in audiences:
        raise ValueError("audience mismatch")

    # SubjectConfirmation: recipient + InResponseTo + window
    scd = assertion.find(
        "saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", NS)
    if scd is not None:
        if scd.get("Recipient") and scd.get("Recipient") != SAML_SP_ACS_URL:
            raise ValueError("subject recipient mismatch")
        scd_noa = _parse_time(scd.get("NotOnOrAfter"))
        if scd_noa and now - _skew() >= scd_noa:
            raise ValueError("subject confirmation expired")
        in_resp = scd.get("InResponseTo")
        if in_resp and in_resp != expected_in_response_to:
            raise ValueError("InResponseTo mismatch")
    # If the IdP echoes InResponseTo we required it to match above; absence is
    # tolerated (IdP-initiated), but a *wrong* value is always rejected.

    user = _assertion_to_user(assertion)
    # Commit the replay marker only once everything else passed.
    expiry = (noa.timestamp() + _SKEW) if noa else (now.timestamp() + 600)
    _replay_record(aid, expiry)
    return user


def _skew():
    from datetime import timedelta
    return timedelta(seconds=_SKEW)


def _attrs(assertion) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for a in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        key = a.get("Name") or a.get("FriendlyName") or ""
        vals = [_text(v) for v in a.findall("saml:AttributeValue", NS) if _text(v)]
        if key:
            out[key] = vals
            fn = a.get("FriendlyName")
            if fn:
                out.setdefault(fn, vals)
    return out


def _assertion_to_user(assertion) -> dict:
    attrs = _attrs(assertion)

    email = ""
    if SAML_EMAIL_ATTR and attrs.get(SAML_EMAIL_ATTR):
        email = attrs[SAML_EMAIL_ATTR][0]
    if not email:
        nameid = _text(assertion.find("saml:Subject/saml:NameID", NS))
        if "@" in nameid:
            email = nameid
    for k in ("email", "mail", "emailAddress",
              "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"):
        if not email and attrs.get(k):
            email = attrs[k][0]
    email = (email or "").strip().lower()
    if "@" not in email:
        raise ValueError("the IdP assertion did not include an email")
    if SAML_ALLOWED_DOMAINS and email.split("@", 1)[1] not in SAML_ALLOWED_DOMAINS:
        raise ValueError("your email domain is not permitted for SSO")

    name = ""
    for k in ([SAML_NAME_ATTR] if SAML_NAME_ATTR else []) + [
            "displayName", "name", "cn",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]:
        if k and attrs.get(k):
            name = attrs[k][0]
            break
    name = name or email.split("@", 1)[0]

    groups = attrs.get(SAML_GROUPS_ATTR) or attrs.get("groups") or attrs.get("Group") or []
    return {"email": email, "name": str(name), "groups": [str(g) for g in groups],
            "role": map_role([str(g) for g in groups])}


def map_role(groups: list[str]) -> str:
    for g in groups:
        if SAML_ROLE_MAP.get(g) in _VALID_ROLES:
            return SAML_ROLE_MAP[g]
    return SAML_DEFAULT_ROLE if SAML_DEFAULT_ROLE in _VALID_ROLES else "viewer"


# ── Signed RelayState (stateless, HMAC-signed with the dashboard JWT secret) ──
# Carries our AuthnRequest ID (for InResponseTo) + the post-login return path, so
# the ACS needs no server-side session store and the RelayState can't be forged.

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_relay_state(request_id: str, return_to: str | None) -> str:
    body = _b64u(json.dumps({"r": request_id, "u": return_to or "",
                             "exp": int(time.time()) + 600},
                            sort_keys=True, separators=(",", ":")).encode())
    sig = _b64u(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def read_relay_state(state: str) -> dict:
    body, _, sig = (state or "").partition(".")
    expected = _b64u(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    if not body or not hmac.compare_digest(expected, sig):
        raise ValueError("relay state signature mismatch")
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except Exception:
        raise ValueError("malformed relay state")
    if int(data.get("exp", 0)) < int(time.time()):
        raise ValueError("relay state expired")
    return data
