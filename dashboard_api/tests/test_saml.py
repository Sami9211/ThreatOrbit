"""SAML 2.0 SP tests - the security proof.

A locally-minted IdP (RSA key + self-signed cert) signs real assertions with
signxml; the SP must ACCEPT a valid one and REJECT every tampering: no
signature, modified content, wrong signing key, expired, wrong audience /
issuer / recipient / InResponseTo, and replay. Plus the relay-state HMAC and the
router endpoints (status / login redirect / ACS / degradation).
"""
import base64
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

from dashboard_api import saml

IDP_ENTITY = "https://idp.example/entity"
SP_ENTITY = "threatorbit-test-sp"
ACS = "https://sp.example/auth/saml/acs"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _mint_idp():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test IdP")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


_KEY, _CERT = _mint_idp()
_KEY2, _CERT2 = _mint_idp()  # an unrelated key, for the wrong-signer test


def _signed_response(*, key=_KEY, cert=_CERT, email="grace@example.com",
                     issuer=IDP_ENTITY, audience=SP_ENTITY, recipient=ACS,
                     in_response_to="_req123", groups=("soc",),
                     cond_minutes=5, sign=True, name="Grace Hopper",
                     include_audience=True):
    # Build the WHOLE Response first (namespaces on the root), then sign the
    # Assertion in place. Signing a standalone element and moving it afterwards
    # re-serialises and breaks the digest - so the document structure must be
    # final before signing, exactly as a real IdP produces it.
    now = datetime.now(timezone.utc)
    aid = "_" + secrets.token_hex(16)
    noa = _iso(now + timedelta(minutes=cond_minutes))
    grp = "".join(f"<saml:AttributeValue>{g}</saml:AttributeValue>" for g in groups)
    aud_el = (f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
              "</saml:AudienceRestriction>") if include_audience else ""
    full = f"""<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" ID="_r{secrets.token_hex(8)}" Version="2.0" IssueInstant="{_iso(now)}">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{_iso(now)}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID>{email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="{recipient}" NotOnOrAfter="{noa}" InResponseTo="{in_response_to}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{_iso(now - timedelta(minutes=5))}" NotOnOrAfter="{noa}">
      {aud_el}
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue>{name}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups">{grp}</saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
    resp = etree.fromstring(full.encode())
    if sign:
        assertion = resp.find(f"{{{SAML_NS}}}Assertion")
        signed_a = XMLSigner(method=methods.enveloped, signature_algorithm="rsa-sha256",
                             digest_algorithm="sha256").sign(assertion, key=key, cert=cert,
                                                             reference_uri=aid)
        resp.replace(assertion, signed_a)
    return base64.b64encode(etree.tostring(resp)).decode()


@pytest.fixture(autouse=True)
def saml_on(monkeypatch):
    monkeypatch.setattr("dashboard_api.saml.SAML_IDP_ENTITY_ID", IDP_ENTITY)
    monkeypatch.setattr("dashboard_api.saml.SAML_IDP_SSO_URL", "https://idp.example/sso")
    monkeypatch.setattr("dashboard_api.saml.SAML_IDP_CERT", _CERT.decode())
    monkeypatch.setattr("dashboard_api.saml.SAML_SP_ENTITY_ID", SP_ENTITY)
    monkeypatch.setattr("dashboard_api.saml.SAML_SP_ACS_URL", ACS)
    # Fresh replay cache per test (now a shared DB table, not an in-process set).
    from dashboard_api.db import get_conn
    with get_conn() as conn:
        conn.execute("DELETE FROM saml_replay")
        conn.commit()
    return True


# -- happy path ---------------------------------------------------------------

def test_valid_assertion_accepted():
    u = saml.parse_response(_signed_response(), "_req123")
    assert u["email"] == "grace@example.com"
    assert u["name"] == "Grace Hopper"
    assert u["groups"] == ["soc"]


def test_role_mapping(monkeypatch):
    monkeypatch.setattr("dashboard_api.saml.SAML_ROLE_MAP", {"soc": "analyst"})
    assert saml.parse_response(_signed_response(groups=("soc",)), "_req123")["role"] == "analyst"


# -- the rejections (each must raise) -----------------------------------------

def test_rejects_unsigned():
    with pytest.raises(ValueError):
        saml.parse_response(_signed_response(sign=False), "_req123")


def test_rejects_wrong_signing_key():
    # Signed by an unrelated key; SP is pinned to _CERT → must fail.
    with pytest.raises(ValueError, match="signature"):
        saml.parse_response(_signed_response(key=_KEY2, cert=_CERT2), "_req123")


def test_rejects_tampered_content():
    resp_b64 = _signed_response(email="grace@example.com")
    xml = base64.b64decode(resp_b64).replace(b"grace@example.com", b"attacker@evil.com")
    with pytest.raises(ValueError, match="signature"):
        saml.parse_response(base64.b64encode(xml).decode(), "_req123")


def test_rejects_expired():
    with pytest.raises(ValueError, match="expired"):
        saml.parse_response(_signed_response(cond_minutes=-5), "_req123")


def test_rejects_wrong_audience():
    with pytest.raises(ValueError, match="audience"):
        saml.parse_response(_signed_response(audience="some-other-sp"), "_req123")


def test_rejects_missing_audience():
    # An assertion with no AudienceRestriction at all is rejected (it could have
    # been minted for a different SP and replayed at ours).
    with pytest.raises(ValueError, match="audience"):
        saml.parse_response(_signed_response(include_audience=False), "_req123")


def test_rejects_wrong_issuer():
    with pytest.raises(ValueError, match="issuer"):
        saml.parse_response(_signed_response(issuer="https://evil.example/idp"), "_req123")


def test_rejects_wrong_recipient():
    with pytest.raises(ValueError, match="recipient"):
        saml.parse_response(_signed_response(recipient="https://evil.example/acs"), "_req123")


def test_rejects_inresponseto_mismatch():
    with pytest.raises(ValueError, match="InResponseTo"):
        saml.parse_response(_signed_response(in_response_to="_attacker"), "_req123")


def test_rejects_replay():
    resp = _signed_response()
    assert saml.parse_response(resp, "_req123")["email"] == "grace@example.com"
    with pytest.raises(ValueError, match="replay"):
        saml.parse_response(resp, "_req123")


# -- relay state --------------------------------------------------------------

def test_relay_state_roundtrip_and_tamper():
    st = saml.make_relay_state("_req999", "/dashboard")
    data = saml.read_relay_state(st)
    assert data["r"] == "_req999" and data["u"] == "/dashboard"
    with pytest.raises(ValueError):
        saml.read_relay_state(st[:-3] + "xyz")  # broken signature


# -- router endpoints ---------------------------------------------------------

def test_status_and_login_redirect(client):
    assert client.get("/auth/saml/status").json()["configured"] is True
    r = client.get("/auth/saml/login", follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("https://idp.example/sso?") and "SAMLRequest=" in loc and "RelayState=" in loc
    # No SP key configured → the request is sent unsigned (the default).
    assert "SigAlg=" not in loc and "Signature=" not in loc


# -- SP-signed AuthnRequest (HTTP-Redirect detached signature, B9 residual) ---

def _decode_authn_request(loc: str):
    """Pull the deflated AuthnRequest back out of a login redirect URL."""
    import zlib
    from urllib.parse import parse_qs, urlsplit
    q = parse_qs(urlsplit(loc).query)
    xml = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15)
    return etree.fromstring(xml), q


def _verify_redirect_signature(loc: str, private_key_pem: bytes):
    """Verify the detached signature over the EXACT transmitted octets
    (…&SigAlg=… before &Signature=…), the way an IdP does."""
    from urllib.parse import unquote
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    query = loc.split("?", 1)[1]
    signed_part, _, sig_part = query.rpartition("&Signature=")
    assert signed_part and sig_part, "Signature parameter missing"
    sig = base64.b64decode(unquote(sig_part))
    pub = serialization.load_pem_private_key(private_key_pem, password=None).public_key()
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    if isinstance(pub, RSAPublicKey):
        pub.verify(sig, signed_part.encode(), padding.PKCS1v15(), hashes.SHA256())
    else:
        pub.verify(sig, signed_part.encode(), ec.ECDSA(hashes.SHA256()))
    return signed_part


def test_sp_signed_authn_request_rsa(client, monkeypatch):
    sp_key, _ = _mint_idp()  # any RSA key works as the SP key
    monkeypatch.setattr("dashboard_api.saml.SAML_SP_PRIVATE_KEY", sp_key.decode())
    r = client.get("/auth/saml/login", follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    signed_part = _verify_redirect_signature(loc, sp_key)
    # Spec ordering: SAMLRequest, then RelayState, then SigAlg - as transmitted.
    assert signed_part.index("SAMLRequest=") < signed_part.index("RelayState=") \
        < signed_part.index("SigAlg=")
    assert "rsa-sha256" in signed_part
    # The signed RelayState still round-trips and matches the request ID inside
    # the AuthnRequest, so the ACS InResponseTo check keeps working.
    req, q = _decode_authn_request(loc)
    assert saml.read_relay_state(q["RelayState"][0])["r"] == req.get("ID")
    assert req.get("Destination") == "https://idp.example/sso"


def test_sp_signed_authn_request_ec(client, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    monkeypatch.setattr("dashboard_api.saml.SAML_SP_PRIVATE_KEY", pem.decode())
    loc = client.get("/auth/saml/login", follow_redirects=False).headers["location"]
    signed_part = _verify_redirect_signature(loc, pem)
    assert "ecdsa-sha256" in signed_part


def test_sp_signing_tamper_is_detectable(monkeypatch):
    # Flipping anything in the signed octets must fail IdP-side verification -
    # proves the signature actually covers SAMLRequest + RelayState + SigAlg.
    sp_key, _ = _mint_idp()
    monkeypatch.setattr("dashboard_api.saml.SAML_SP_PRIVATE_KEY", sp_key.decode())
    loc = saml.make_login_redirect(None)
    tampered = loc.replace("SAMLRequest=", "SAMLRequest=X", 1)
    with pytest.raises(Exception):
        _verify_redirect_signature(tampered, sp_key)


def test_sp_signing_rejects_unsupported_key(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    monkeypatch.setattr("dashboard_api.saml.SAML_SP_PRIVATE_KEY", pem.decode())
    with pytest.raises(ValueError, match="RSA or EC"):
        saml.make_login_redirect(None)


def test_acs_valid_issues_token(client):
    # Mirror the request id the login step would have generated.
    relay = saml.make_relay_state("_req123", None)
    resp = _signed_response(in_response_to="_req123")
    r = client.post("/auth/saml/acs", data={"SAMLResponse": resp, "RelayState": relay},
                    follow_redirects=False)
    assert r.status_code == 302
    assert "sso_token=" in r.headers["location"]


def test_acs_bad_signature_redirects_with_error(client):
    relay = saml.make_relay_state("_req123", None)
    resp = _signed_response(key=_KEY2, cert=_CERT2, in_response_to="_req123")
    r = client.post("/auth/saml/acs", data={"SAMLResponse": resp, "RelayState": relay},
                    follow_redirects=False)
    assert r.status_code == 302 and "sso_error=" in r.headers["location"]


def test_degrades_when_unconfigured(client, monkeypatch):
    monkeypatch.setattr("dashboard_api.saml.SAML_IDP_ENTITY_ID", "")
    assert client.get("/auth/saml/status").json()["configured"] is False
    assert client.get("/auth/saml/login", follow_redirects=False).status_code == 404
