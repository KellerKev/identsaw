import base64
import zlib
from urllib.parse import parse_qs, urlparse

import pytest

from identsaw import SAMLProvider


def test_authn_request_redirect():
    p = SAMLProvider("saml", idp_sso_url="https://idp/sso", sp_entity_id="sp",
                     acs_url="https://sp/acs")
    url = p.login_url("relay1")
    q = parse_qs(urlparse(url).query)
    assert q["RelayState"] == ["relay1"] and "SAMLRequest" in q
    xml = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -zlib.MAX_WBITS).decode()
    assert "AuthnRequest" in xml and "https://sp/acs" in xml and "<saml:Issuer>sp</saml:Issuer>" in xml


def test_parse_response_extracts_nameid_and_attributes():
    resp = ('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion>'
            '<saml:Subject><saml:NameID>a@x.io</saml:NameID></saml:Subject>'
            '<saml:AttributeStatement>'
            '<saml:Attribute Name="firstName"><saml:AttributeValue>Ada</saml:AttributeValue></saml:Attribute>'
            '</saml:AttributeStatement></saml:Assertion></samlp:Response>')
    p = SAMLProvider("saml", idp_sso_url="x", sp_entity_id="sp", acs_url="acs")
    prof = p.parse_response(base64.b64encode(resp.encode()).decode())
    assert prof["provider_uid"] == "a@x.io" and prof["email"] == "a@x.io"
    assert prof["first_name"] == "Ada" and prof["attributes"]["firstName"] == "Ada"


def test_parse_response_verify_hook_can_reject():
    p = SAMLProvider("saml", idp_sso_url="x", sp_entity_id="sp", acs_url="acs",
                     verify=lambda xml: False)
    with pytest.raises(ValueError):
        p.parse_response(base64.b64encode(b"<x/>").decode())
