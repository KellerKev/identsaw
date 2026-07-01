"""TOTP (RFC 6238) — time-based one-time passwords for MFA, stdlib-only.

    from identsaw.otp import generate_secret, verify, provisioning_uri
    secret = generate_secret()                       # store per user (base32)
    uri = provisioning_uri(secret, "a@x.io")         # -> QR for an authenticator app
    verify(secret, code_from_app)                    # True/False (with ±1 step drift)

:class:`TOTPStore` persists a per-user secret in a sqladal table, and
:class:`TOTPMethod` plugs TOTP into ``auth.authenticate("totp", ...)``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

from ._util import now
from .methods import AuthMethod


def _b32pad(s: str) -> str:
    s = s.upper().replace(" ", "")
    return s + "=" * (-len(s) % 8)


def generate_secret(length=20) -> str:
    """A fresh base32 secret (no padding), ready for an authenticator app."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int, *, digits=6, algo="sha1") -> str:
    key = base64.b32decode(_b32pad(secret))
    dig = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    off = dig[-1] & 0x0F
    code = (struct.unpack(">I", dig[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret: str, t=None, *, step=30, digits=6, algo="sha1") -> str:
    t = time.time() if t is None else t
    return _hotp(secret, int(t // step), digits=digits, algo=algo)


def verify(secret, code, t=None, *, step=30, digits=6, window=1, algo="sha1") -> bool:
    """True if ``code`` matches within ±``window`` time steps (clock drift)."""
    if not secret or code is None:
        return False
    t = time.time() if t is None else t
    counter = int(t // step)
    code = str(code).zfill(digits)
    return any(hmac.compare_digest(_hotp(secret, counter + w, digits=digits, algo=algo), code)
               for w in range(-window, window + 1))


def provisioning_uri(secret, account_name, *, issuer="websaw_ng") -> str:
    label = urllib.parse.quote("%s:%s" % (issuer, account_name))
    q = urllib.parse.urlencode({"secret": secret, "issuer": issuer})
    return "otpauth://totp/%s?%s" % (label, q)


class TOTPStore:
    """Per-user TOTP secrets in a sqladal table ``{prefix}totp``."""

    def __init__(self, db, *, prefix="id_"):
        self.db = db
        self.prefix = prefix
        from sqladal import Field
        t = prefix + "totp"
        if t not in db.tables:
            db.define_table(
                t,
                Field("user", "reference %suser" % prefix),
                Field("secret"),
                Field("confirmed", "boolean", default=False),
                Field("created_on", "datetime", default=now, writable=False),
            )

    @property
    def table(self):
        return self.db[self.prefix + "totp"]

    def enroll(self, uid) -> str:
        secret = generate_secret()
        self.db(self.table.user == uid).delete()
        self.table.insert(user=uid, secret=secret, confirmed=False)
        return secret

    def _row(self, uid):
        return self.db(self.table.user == uid).select().first()

    def secret_for(self, uid):
        row = self._row(uid)
        return row.secret if row else None

    def confirm(self, uid, code) -> bool:
        row = self._row(uid)
        if not row or not verify(row.secret, code):
            return False
        self.db(self.table.id == row.id).update(confirmed=True)
        return True

    def is_enabled(self, uid) -> bool:
        row = self._row(uid)
        return bool(row and row.confirmed)

    def check(self, uid, code) -> bool:
        row = self._row(uid)
        return bool(row and row.confirmed and verify(row.secret, code))


class TOTPMethod(AuthMethod):
    """Second factor: ``auth.authenticate("totp", uid=..., code=...)``."""
    name = "totp"

    def __init__(self, store: TOTPStore):
        self.store = store

    def authenticate(self, auth, *, uid, code, **_):
        return auth.user(uid) if self.store.check(uid, code) else None


__all__ = ["generate_secret", "totp", "verify", "provisioning_uri", "TOTPStore", "TOTPMethod"]
