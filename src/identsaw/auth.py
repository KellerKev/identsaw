"""Auth — local accounts, JWT sessions/API tokens, and OAuth2/OIDC login over an
abstract :class:`~identsaw.stores.UserStore`. No database is baked in: pass any
store (the default :class:`~identsaw.stores.SqladalUserStore`, or your own).

    from identsaw import Auth, SqladalUserStore, install_identity_models
    install_identity_models(db)
    auth = Auth(SqladalUserStore(db), secret=SECRET)
    auth.register("a@x.io", "pw"); user = auth.login("a@x.io", "pw")

An optional ``events`` callback ``(event, user_id, detail)`` receives login /
register / token / oauth events — guardsaw wires it to its audit log.
"""
from __future__ import annotations

import datetime
import secrets

from ._util import now
from .jwt import jwt_decode, jwt_encode
from .methods import PasswordMethod
from .providers import (GitHubOAuth2, GoogleOAuth2, OAuth2Provider, OIDCProvider,  # noqa: F401
                        Provider)


class Auth:
    def __init__(self, store, *, secret="identsaw-change-me", events=None):
        self.store = store
        self.secret = secret
        self.providers = {}
        self.methods = {}
        self._events = events
        self.register_method(PasswordMethod())

    @staticmethod
    def _uid(user):
        if user is None:
            return None
        if isinstance(user, dict):
            return user.get("id")
        return getattr(user, "id", user)

    def emit(self, event, user_id=None, detail=None):
        if self._events:
            self._events(event, user_id, detail)

    # --- local accounts -----------------------------------------------------
    def register(self, email, password, **kw):
        if self.store.by_email(email):
            return None, "email already registered"
        uid = self.store.create(email, password=password, **kw)
        self.emit("register", uid, {"email": email})
        return uid, None

    def login(self, email, password):
        u = self.store.by_email(email)
        if not u or not self.store.is_active(u) or not self.store.verify_password(u, password):
            self.emit("login.fail", self._uid(u), {"email": email})
            return None
        self.store.touch_login(u.id)
        self.emit("login.success", u.id)
        return self.store.to_session(u)

    def session_user(self, u) -> dict:
        return self.store.to_session(u)

    def user(self, user_id):
        u = self.store.by_id(user_id)
        return self.store.to_session(u) if u else None

    # --- pluggable auth methods (password now; otp/passkey/magic-link later) -
    def register_method(self, method):
        self.methods[method.name] = method
        return method

    def authenticate(self, method, **kw):
        return self.methods[method].authenticate(self, **kw)

    # --- JWT sessions / API tokens ------------------------------------------
    def issue_token(self, user, *, scopes=None, exp=3600, persist=False, name=None):
        """A signed HS256 token. ``persist=True`` records it (with a ``jti``) so it
        can be **revoked**; otherwise the token is stateless."""
        uid = self._uid(user)
        scope = (scopes if isinstance(scopes, str) else " ".join(scopes)) if scopes else ""
        payload = {"sub": uid}
        if scope:
            payload["scope"] = scope
        if persist:
            jti = secrets.token_urlsafe(12)
            payload["jti"] = jti
            self.store.save_token(jti, uid, name=name or "api token", scopes=scope,
                                  expires_on=now() + datetime.timedelta(seconds=exp))
            self.emit("token.issue", uid, {"name": name, "scopes": scope})
        return jwt_encode(payload, self.secret, exp=exp)

    def verify_token(self, token):
        try:
            payload = jwt_decode(token, self.secret)
        except ValueError:
            return None
        jti = payload.get("jti")                       # persisted token -> check revocation
        if jti is not None:
            row = self.store.token_row(jti)
            if row is None or row.revoked:
                return None
        return payload

    def revoke_token(self, jti) -> int:
        self.emit("token.revoke", None, {"jti": jti})
        return self.store.revoke_token(jti)

    def active_tokens(self, user=None):
        return self.store.active_tokens(self._uid(user) if user is not None else None)

    def token_user(self, token):
        """Resolve a Bearer token to ``(session_user_dict, scopes_set)`` or None."""
        payload = self.verify_token(token)
        if not payload:
            return None
        u = self.store.by_id(payload.get("sub"))
        if not u:
            return None
        scope = payload.get("scope", "")
        scopes = set(scope.split()) if isinstance(scope, str) else set(scope)
        return self.store.to_session(u), scopes

    def bearer_resolver(self):
        """A ``resolve(request)`` reading ``Authorization: Bearer <jwt>`` →
        ``(user, scopes)`` (for guardsaw's ``guard_authorizer``)."""
        def resolve(request):
            h = request.headers.get("Authorization", "") or ""
            return self.token_user(h[7:]) if h.startswith("Bearer ") else None
        return resolve

    # --- OAuth2 / OIDC ------------------------------------------------------
    def register_provider(self, provider: Provider):
        self.providers[provider.name] = provider
        return provider

    def oauth_login_url(self, provider_name, state, redirect_uri):
        return self.providers[provider_name].authorize_url(state, redirect_uri)

    def oauth_callback(self, provider_name, code, redirect_uri):
        p = self.providers[provider_name]
        tokens = p.exchange_code(code, redirect_uri)
        return self.upsert_oauth_user(provider_name, p.map_profile(tokens))

    def upsert_oauth_user(self, provider_name, profile) -> dict:
        uid = str(profile["provider_uid"])
        email = profile.get("email")
        u = self.store.oauth_link(provider_name, uid)
        if u:
            return self.store.to_session(u)
        u = self.store.by_email(email) if email else None
        if not u:
            new_id = self.store.create(
                email or "%s-%s@oauth.local" % (provider_name, uid),
                username=profile.get("username"),
                first_name=profile.get("first_name"),
                last_name=profile.get("last_name"))
            u = self.store.by_id(new_id)
        self.store.link_oauth(provider_name, uid, u.id)
        self.emit("oauth.login", u.id, {"provider": provider_name})
        return self.store.to_session(u)


__all__ = ["Auth"]
