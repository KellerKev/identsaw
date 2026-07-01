"""The user store — the seam that frees Auth from any particular database.

:class:`UserStore` is the contract Auth needs (look up / create users, verify
passwords, link OAuth identities, persist & revoke tokens). :class:`SqladalUserStore`
is the default implementation over sqladal/pydal tables; ``install_identity_models``
defines a minimal compatible schema for standalone use. guardsaw points the same
store at its richer ``gs_*`` tables (``prefix="gs_"``).
"""
from __future__ import annotations

from .._util import now


class UserStore:
    """The identity persistence contract Auth depends on. A ``user`` is any object
    with at least an ``id`` and the attributes ``to_session`` exposes."""

    def by_email(self, email):
        raise NotImplementedError

    def by_id(self, uid):
        raise NotImplementedError

    def create(self, email, password=None, **fields):
        """Create a user (hashing ``password`` if given); return the new id."""
        raise NotImplementedError

    def verify_password(self, user, password) -> bool:
        raise NotImplementedError

    def is_active(self, user) -> bool:
        return True

    def touch_login(self, uid):
        pass

    def to_session(self, user) -> dict:
        raise NotImplementedError

    # --- OAuth identity links ----------------------------------------------
    def oauth_link(self, provider, provider_uid):
        """The user previously linked to ``(provider, provider_uid)``, or None."""
        raise NotImplementedError

    def link_oauth(self, provider, provider_uid, uid):
        raise NotImplementedError

    # --- persisted (revocable) tokens --------------------------------------
    def save_token(self, jti, uid, *, name, scopes, expires_on):
        raise NotImplementedError

    def token_row(self, jti):
        """The token row for ``jti`` (with a ``revoked`` flag), or None."""
        raise NotImplementedError

    def revoke_token(self, jti) -> int:
        raise NotImplementedError

    def active_tokens(self, uid=None):
        raise NotImplementedError


class SqladalUserStore(UserStore):
    """A :class:`UserStore` over sqladal/pydal tables ``{prefix}user`` /
    ``{prefix}oauth`` / ``{prefix}token``. Works with guardsaw's ``gs_*`` tables
    (``prefix='gs_'``) or :func:`install_identity_models` (``prefix='id_'``)."""

    def __init__(self, db, *, prefix="id_", session_fields=None):
        self.db = db
        self.prefix = prefix
        # fields surfaced in the session dict (skipped if absent on the row)
        self._session_fields = session_fields or (
            "email", "username", "first_name", "last_name", "tenant")

    @property
    def users(self):
        return self.db[self.prefix + "user"]

    @property
    def oauth(self):
        return self.db[self.prefix + "oauth"]

    @property
    def tokens(self):
        return self.db[self.prefix + "token"]

    def by_email(self, email):
        return self.db(self.users.email == email).select().first()

    def by_id(self, uid):
        return self.users(uid) if uid is not None else None

    def create(self, email, password=None, **fields):
        vals = dict(email=email, **fields)
        if password is not None:
            vals["password"] = password
        res = self.users.validate_and_insert(**vals)     # CRYPT hashes the password
        return res.get("id")

    def verify_password(self, user, password) -> bool:
        from sqladal.validators import CRYPT
        if not user or not user.password:
            return False
        return CRYPT()(password)[0] == user.password     # LazyCrypt.__eq__ verifies

    def is_active(self, user) -> bool:
        return getattr(user, "status", "active") != "banned"

    def touch_login(self, uid):
        self.db(self.users.id == uid).update(last_login=now())

    def to_session(self, user) -> dict:
        out = {"id": user.id}
        for f in self._session_fields:
            if f in self.users.fields:
                out[f] = getattr(user, f, None)
        return out

    def oauth_link(self, provider, provider_uid):
        oa = self.oauth
        link = self.db((oa.provider == provider)
                       & (oa.provider_uid == str(provider_uid))).select().first()
        return self.by_id(link.user) if link else None

    def link_oauth(self, provider, provider_uid, uid):
        return self.oauth.insert(provider=provider, provider_uid=str(provider_uid), user=uid)

    def save_token(self, jti, uid, *, name, scopes, expires_on):
        return self.tokens.insert(name=name, key_hash=jti, user=uid, scopes=scopes,
                                  revoked=False, expires_on=expires_on)

    def token_row(self, jti):
        return self.db(self.tokens.key_hash == jti).select().first()

    def revoke_token(self, jti) -> int:
        return self.db(self.tokens.key_hash == jti).update(revoked=True)

    def active_tokens(self, uid=None):
        q = (self.tokens.revoked == False)               # noqa: E712 (pydal needs ==)
        if uid is not None:
            q = q & (self.tokens.user == uid)
        return self.db(q).select(orderby=~self.tokens.created_on)


def install_identity_models(db, *, prefix="id_", tenancy=False):
    """Define a minimal identity schema (``user``/``oauth``/``token``) for
    standalone use. guardsaw supplies its own richer ``gs_*`` tables instead."""
    from sqladal import Field
    from sqladal.validators import CRYPT, IS_EMAIL
    p = prefix

    if p + "user" not in db.tables:
        db.define_table(
            p + "user",
            Field("email", requires=IS_EMAIL()),
            Field("username"),
            Field("password", "password", requires=CRYPT()),
            Field("first_name"),
            Field("last_name"),
            Field("status", default="active"),
            Field("last_login", "datetime", writable=False),
            Field("created_on", "datetime", default=now, writable=False),
            *([Field("tenant", "integer")] if tenancy else []),
            format="%(email)s",
        )
    if p + "oauth" not in db.tables:
        db.define_table(
            p + "oauth",
            Field("provider"),
            Field("provider_uid"),
            Field("user", "reference %suser" % p),
            Field("created_on", "datetime", default=now, writable=False),
        )
    if p + "token" not in db.tables:
        db.define_table(
            p + "token",
            Field("name"),
            Field("key_hash", writable=False, readable=False),
            Field("user", "reference %suser" % p),
            Field("scopes", default=""),
            Field("expires_on", "datetime"),
            Field("revoked", "boolean", default=False),
            Field("created_on", "datetime", default=now, writable=False),
        )
    return db


__all__ = ["UserStore", "SqladalUserStore", "install_identity_models"]
