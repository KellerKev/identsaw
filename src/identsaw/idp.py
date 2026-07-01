"""A centralized OpenID-Connect Identity Provider (the IdP side).

Turns one identsaw-backed app into an OIDC provider so *other* apps log in through
it — real cross-app / cross-domain SSO (the server counterpart to
:class:`identsaw.providers.OIDCProvider`, the client). Implements the
authorization-code flow with RS256 id_tokens and a JWKS endpoint.

    idp = OpenIDProvider(issuer="https://id.example/oauth", auth=auth)
    idp.register_client("webapp", "s3cret", ["https://app.example/callback"])
    mount_idp(ombott_app, idp, current_user=current_user)   # exposes /authorize, /token, ...

Authorization codes are held in-process (fine for a single worker / demo); back
them with a shared store for multi-worker deployments. Needs the ``oidc`` extra
(``pyjwt[crypto]`` + ``cryptography``).
"""
from __future__ import annotations

import base64
import secrets
import time


class OIDCError(Exception):
    def __init__(self, error, description=""):
        super().__init__(description or error)
        self.error = error
        self.description = description


def _b64u_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class OpenIDProvider:
    def __init__(self, *, issuer, auth, private_key_pem=None, kid="idp-key", code_ttl=300,
                 token_ttl=3600):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.issuer = issuer.rstrip("/")
        self.auth = auth
        self.kid = kid
        self.code_ttl = code_ttl
        self.token_ttl = token_ttl
        if private_key_pem:
            self._key = serialization.load_pem_private_key(private_key_pem, password=None)
        else:
            self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.clients = {}
        self._codes = {}

    # --- key material -------------------------------------------------------
    def private_key_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

    def _sign(self, claims: dict) -> str:
        import jwt
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid})

    def _decode(self, token: str) -> dict:
        import jwt
        return jwt.decode(token, self._key.public_key(), algorithms=["RS256"],
                          options={"verify_aud": False})

    def jwks(self) -> dict:
        pub = self._key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                          "n": _b64u_uint(pub.n), "e": _b64u_uint(pub.e)}]}

    def discovery(self) -> dict:
        i = self.issuer
        return {
            "issuer": i,
            "authorization_endpoint": i + "/authorize",
            "token_endpoint": i + "/token",
            "userinfo_endpoint": i + "/userinfo",
            "jwks_uri": i + "/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "email", "profile"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
        }

    # --- clients ------------------------------------------------------------
    def register_client(self, client_id, client_secret, redirect_uris):
        self.clients[client_id] = {"secret": client_secret, "redirect_uris": list(redirect_uris)}

    def check_redirect(self, client_id, redirect_uri) -> bool:
        c = self.clients.get(client_id)
        return bool(c) and redirect_uri in c["redirect_uris"]

    # --- authorization-code flow -------------------------------------------
    def create_code(self, *, client_id, uid, redirect_uri, scope="openid", nonce=None) -> str:
        if not self.check_redirect(client_id, redirect_uri):
            raise OIDCError("invalid_request", "unknown client or redirect_uri")
        code = secrets.token_urlsafe(24)
        self._codes[code] = {"client_id": client_id, "uid": uid, "redirect_uri": redirect_uri,
                             "scope": scope, "nonce": nonce, "exp": time.time() + self.code_ttl}
        return code

    def _claims_for(self, uid, scope):
        user = self.auth.user(uid) or {}
        out = {}
        if "email" in scope or "openid" in scope:
            out["email"] = user.get("email")
        if "profile" in scope or "openid" in scope:
            name = " ".join(x for x in (user.get("first_name"), user.get("last_name")) if x)
            out["name"] = name or user.get("username")
        return out

    def exchange_code(self, *, code, client_id, client_secret, redirect_uri) -> dict:
        data = self._codes.pop(code, None)
        if not data:
            raise OIDCError("invalid_grant", "unknown or used code")
        if time.time() > data["exp"]:
            raise OIDCError("invalid_grant", "code expired")
        if data["client_id"] != client_id or data["redirect_uri"] != redirect_uri:
            raise OIDCError("invalid_grant", "client/redirect mismatch")
        c = self.clients.get(client_id)
        if not c or c["secret"] != client_secret:
            raise OIDCError("invalid_client", "bad client credentials")

        iat = int(time.time())
        base = {"iss": self.issuer, "sub": str(data["uid"]), "iat": iat, "exp": iat + self.token_ttl}
        id_claims = dict(base, aud=client_id, **self._claims_for(data["uid"], data["scope"]))
        if data.get("nonce"):
            id_claims["nonce"] = data["nonce"]
        access = dict(base, scope=data["scope"], token_use="access")
        return {"access_token": self._sign(access), "id_token": self._sign(id_claims),
                "token_type": "Bearer", "expires_in": self.token_ttl, "scope": data["scope"]}

    def userinfo(self, access_token) -> dict:
        claims = self._decode(access_token)
        if claims.get("token_use") != "access":
            raise OIDCError("invalid_token", "not an access token")
        uid = int(claims["sub"])
        return dict(sub=claims["sub"], **self._claims_for(uid, claims.get("scope", "")))


def mount_idp(app, idp, *, current_user, base=None, login_path="/login"):
    """Expose ``idp`` as OIDC HTTP endpoints on an ombott ``app``. ``current_user``
    maps a request to a logged-in user dict (or None -> bounce to ``login_path``)."""
    import json

    import ombott_ng

    path = base if base is not None else "/" + idp.issuer.split("://", 1)[-1].split("/", 1)[-1]
    path = "/" + path.strip("/") if path.strip("/") else ""

    def _json(data):
        ombott_ng.response.content_type = "application/json"
        return json.dumps(data)

    @app.get(path + "/.well-known/openid-configuration")
    def _disco():
        return _json(idp.discovery())

    @app.get(path + "/jwks")
    def _jwks():
        return _json(idp.jwks())

    @app.get(path + "/authorize")
    def _authorize():
        q = ombott_ng.request.query
        user = current_user(ombott_ng.request)
        if not user:
            from urllib.parse import quote
            env = ombott_ng.request.environ
            nxt = env.get("PATH_INFO", "")
            if env.get("QUERY_STRING"):
                nxt += "?" + env["QUERY_STRING"]
            ombott_ng.redirect("%s?next=%s" % (login_path, quote(nxt)))
            return
        client_id = q.get("client_id")
        redirect_uri = q.get("redirect_uri")
        if not idp.check_redirect(client_id, redirect_uri):
            ombott_ng.response.status = 400
            return "invalid client_id or redirect_uri"
        code = idp.create_code(client_id=client_id, uid=user["id"], redirect_uri=redirect_uri,
                               scope=q.get("scope") or "openid", nonce=q.get("nonce"))
        sep = "&" if "?" in redirect_uri else "?"
        state = q.get("state")
        ombott_ng.redirect("%s%scode=%s%s" % (redirect_uri, sep, code,
                                           ("&state=%s" % state) if state else ""))

    @app.route(path + "/token", method="POST")
    def _token():
        f = ombott_ng.request.forms
        try:
            return _json(idp.exchange_code(code=f.get("code"), client_id=f.get("client_id"),
                                           client_secret=f.get("client_secret"),
                                           redirect_uri=f.get("redirect_uri")))
        except OIDCError as e:
            ombott_ng.response.status = 400
            return _json({"error": e.error, "error_description": e.description})

    @app.get(path + "/userinfo")
    def _userinfo():
        h = ombott_ng.request.headers.get("Authorization", "") or ""
        if not h.startswith("Bearer "):
            ombott_ng.response.status = 401
            return _json({"error": "invalid_token"})
        try:
            return _json(idp.userinfo(h[7:]))
        except OIDCError as e:
            ombott_ng.response.status = 401
            return _json({"error": e.error})

    return app


__all__ = ["OpenIDProvider", "OIDCError", "mount_idp"]
