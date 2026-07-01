"""Magic-link (passwordless email) login — a signed, time-limited, single-use token.

    ml = MagicLink(secret, store=user_store)
    token = ml.create(uid=user_id, email="a@x.io")     # embed in an emailed URL
    claims = ml.consume(token)                          # {sub, email} once, then invalid

Single-use is enforced by recording the token's ``jti`` in the user store's token
table and revoking it on first consume (omit ``store`` for stateless, replayable
links). Delivery (email/SMS) is the caller's job — pass an ``on_link`` sender.
"""
from __future__ import annotations

import datetime
import secrets

from ._util import now
from .jwt import jwt_decode, jwt_encode
from .methods import AuthMethod


class MagicLink:
    def __init__(self, secret, *, store=None, ttl=900):
        self.secret = secret
        self.store = store
        self.ttl = ttl

    def create(self, *, uid=None, email=None, ttl=None, purpose="login") -> str:
        ttl = ttl or self.ttl
        jti = secrets.token_urlsafe(9)
        payload = {"purpose": purpose, "jti": jti}
        if uid is not None:
            payload["sub"] = uid
        if email:
            payload["email"] = email
        if self.store is not None:
            self.store.save_token(jti, uid or 0, name="magic-link", scopes=purpose,
                                  expires_on=now() + datetime.timedelta(seconds=ttl))
        return jwt_encode(payload, self.secret, exp=ttl)

    def consume(self, token, *, purpose="login"):
        """Validate + single-use-consume a link; returns ``{sub, email}`` or None."""
        try:
            payload = jwt_decode(token, self.secret)
        except ValueError:
            return None
        if payload.get("purpose") != purpose:
            return None
        jti = payload.get("jti")
        if self.store is not None and jti is not None:
            row = self.store.token_row(jti)
            if row is None or row.revoked:
                return None
            self.store.revoke_token(jti)                       # burn it
        return {"sub": payload.get("sub"), "email": payload.get("email")}


class MagicLinkMethod(AuthMethod):
    """``auth.authenticate("magiclink", token=...)`` -> session user or None."""
    name = "magiclink"

    def __init__(self, magic: MagicLink):
        self.magic = magic

    def authenticate(self, auth, *, token, **_):
        claims = self.magic.consume(token)
        if not claims:
            return None
        if claims.get("sub") is not None:
            return auth.user(claims["sub"])
        u = auth.store.by_email(claims.get("email")) if claims.get("email") else None
        return auth.store.to_session(u) if u else None


__all__ = ["MagicLink", "MagicLinkMethod"]
