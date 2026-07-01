"""Pluggable OAuth2 / OIDC login providers (py4web ``register_plugin`` spirit).

A ``Provider`` turns an authorization-code login into a normalized profile:
``authorize_url`` (redirect the user) → ``exchange_code`` (code → tokens) →
``map_profile`` (tokens/userinfo → ``{provider_uid, email, ...}``). Built-ins:
``GoogleOAuth2``, ``GitHubOAuth2``, and ``OIDCProvider`` (any IdP via .well-known
discovery + JWKS id_token verification). HTTP uses ``httpx`` and id_token
verification uses ``pyjwt[crypto]`` — both lazy (the ``oidc`` extra).
"""
from __future__ import annotations

from urllib.parse import urlencode


class Provider:
    name = ""

    def authorize_url(self, state, redirect_uri) -> str:
        raise NotImplementedError

    def exchange_code(self, code, redirect_uri) -> dict:
        raise NotImplementedError

    def map_profile(self, tokens) -> dict:
        raise NotImplementedError


class OAuth2Provider(Provider):
    def __init__(self, name, client_id, client_secret, *, authorize_endpoint,
                 token_endpoint, userinfo_endpoint=None, scope="openid email profile",
                 profile_map=None):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_endpoint = authorize_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.scope = scope
        self.profile_map = profile_map

    def authorize_url(self, state, redirect_uri) -> str:
        q = urlencode({"client_id": self.client_id, "redirect_uri": redirect_uri,
                       "response_type": "code", "scope": self.scope, "state": state})
        return "%s?%s" % (self.authorize_endpoint, q)

    def exchange_code(self, code, redirect_uri) -> dict:
        import httpx
        r = httpx.post(self.token_endpoint, headers={"Accept": "application/json"},
                       data={"grant_type": "authorization_code", "code": code,
                             "client_id": self.client_id, "client_secret": self.client_secret,
                             "redirect_uri": redirect_uri})
        r.raise_for_status()
        return r.json()

    def userinfo(self, tokens) -> dict:
        import httpx
        r = httpx.get(self.userinfo_endpoint,
                      headers={"Authorization": "Bearer " + tokens["access_token"],
                               "Accept": "application/json"})
        r.raise_for_status()
        return r.json()

    def _default_map(self, info) -> dict:
        return {
            "provider_uid": str(info.get("sub") or info.get("id") or ""),
            "email": info.get("email"),
            "first_name": info.get("given_name") or info.get("name"),
            "last_name": info.get("family_name"),
            "username": info.get("preferred_username") or info.get("login"),
        }

    def map_profile(self, tokens) -> dict:
        info = self.userinfo(tokens) if self.userinfo_endpoint else {}
        return (self.profile_map or self._default_map)(info)


def GoogleOAuth2(client_id, client_secret, **kw):
    return OAuth2Provider(
        "google", client_id, client_secret,
        authorize_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo", **kw)


def GitHubOAuth2(client_id, client_secret, **kw):
    return OAuth2Provider(
        "github", client_id, client_secret,
        authorize_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        userinfo_endpoint="https://api.github.com/user",
        scope="read:user user:email",
        profile_map=lambda i: {"provider_uid": str(i.get("id")), "email": i.get("email"),
                               "username": i.get("login"), "first_name": i.get("name")}, **kw)


class OIDCProvider(OAuth2Provider):
    """Any OpenID-Connect IdP (Auth0/Keycloak/Okta/Azure AD/Google) via the
    ``.well-known/openid-configuration`` discovery document."""

    def __init__(self, name, client_id, client_secret, discovery_url, *,
                 scope="openid email profile"):
        import httpx
        conf = httpx.get(discovery_url).json()
        super().__init__(name, client_id, client_secret,
                         authorize_endpoint=conf["authorization_endpoint"],
                         token_endpoint=conf["token_endpoint"],
                         userinfo_endpoint=conf.get("userinfo_endpoint"), scope=scope)
        self.jwks_uri = conf.get("jwks_uri")
        self.issuer = conf.get("issuer")

    def map_profile(self, tokens) -> dict:
        idt = tokens.get("id_token")
        if idt and self.jwks_uri:
            import jwt
            from jwt import PyJWKClient
            key = PyJWKClient(self.jwks_uri).get_signing_key_from_jwt(idt).key
            claims = jwt.decode(idt, key, algorithms=["RS256"],
                                audience=self.client_id, issuer=self.issuer)
            return self._default_map(claims)
        return super().map_profile(tokens)


class SAMLProvider(Provider):
    """SAML 2.0 SP (service provider), SP-initiated Redirect binding.

    ``login_url(relay_state)`` builds an ``AuthnRequest`` and returns the IdP SSO
    redirect; the IdP POSTs a ``SAMLResponse`` to your ACS, which you pass to
    ``parse_response`` to get a normalized profile.

    NOTE: this extracts the assertion's NameID + attributes but does **not**
    validate the XML signature — wire a ``verify`` callback (e.g. backed by
    ``signxml``/``xmlsec``) before trusting a response in production.
    """

    name = "saml"
    _NS = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion",
           "samlp": "urn:oasis:names:tc:SAML:2.0:protocol"}

    def __init__(self, name, *, idp_sso_url, sp_entity_id, acs_url, verify=None,
                 attribute_map=None):
        self.name = name
        self.idp_sso_url = idp_sso_url
        self.sp_entity_id = sp_entity_id
        self.acs_url = acs_url
        self.verify = verify
        self.attribute_map = attribute_map or {}

    def login_url(self, relay_state="", *, request_id="_idsaw") -> str:
        import base64
        import zlib
        from urllib.parse import urlencode
        req = (
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" '
            'IssueInstant="1970-01-01T00:00:00Z" AssertionConsumerServiceURL="%s" '
            'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            '<saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>'
            % (request_id, self.acs_url, self.sp_entity_id))
        # HTTP-Redirect binding: raw-deflate + base64 + urlencode
        co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        comp = co.compress(req.encode()) + co.flush()
        q = urlencode({"SAMLRequest": base64.b64encode(comp).decode(), "RelayState": relay_state})
        sep = "&" if "?" in self.idp_sso_url else "?"
        return "%s%s%s" % (self.idp_sso_url, sep, q)

    def parse_response(self, saml_response_b64) -> dict:
        import base64
        from xml.etree import ElementTree as ET
        xml = base64.b64decode(saml_response_b64)
        if self.verify is not None and not self.verify(xml):
            raise ValueError("SAML signature verification failed")
        root = ET.fromstring(xml)
        nameid_el = root.find(".//saml:Subject/saml:NameID", self._NS)
        attrs = {}
        for a in root.findall(".//saml:Attribute", self._NS):
            name = a.get("Name")
            vals = [v.text for v in a.findall("saml:AttributeValue", self._NS)]
            attrs[name] = vals[0] if len(vals) == 1 else vals
        nameid = nameid_el.text if nameid_el is not None else None
        m = self.attribute_map
        return {
            "provider_uid": nameid,
            "email": attrs.get(m.get("email", "email")) or nameid,
            "first_name": attrs.get(m.get("first_name", "firstName")),
            "last_name": attrs.get(m.get("last_name", "lastName")),
            "username": attrs.get(m.get("username", "username")),
            "attributes": attrs,
        }


__all__ = ["Provider", "OAuth2Provider", "GoogleOAuth2", "GitHubOAuth2", "OIDCProvider",
           "SAMLProvider"]
