"""WebAuthn / passkeys — passwordless, phishing-resistant login.

A thin wrapper over `py_webauthn <https://pypi.org/project/webauthn/>`_ (the
``passkey`` extra) plus a :class:`CredentialStore`. The ceremony is: the server
issues *options* (with a challenge) → the browser's authenticator signs them → the
server verifies and stores/looks-up the credential. Full verification needs a real
authenticator (a browser/security key), so end-to-end can't be unit-tested here;
option generation and credential storage can.

    pk = PasskeyManager(rp_id="example.com", rp_name="Example", origin="https://example.com",
                        store=CredentialStore(db))
    opts, challenge = pk.begin_registration(user)      # -> send opts to the browser; stash challenge
    pk.complete_registration(user, response_json, challenge)   # verify + store the credential
"""
from __future__ import annotations

from ._util import now


class CredentialStore:
    """Stored passkeys in a sqladal table ``{prefix}credential``."""

    def __init__(self, db, *, prefix="id_"):
        self.db = db
        self.prefix = prefix
        from sqladal import Field
        t = prefix + "credential"
        if t not in db.tables:
            db.define_table(
                t,
                Field("user", "reference %suser" % prefix),
                Field("credential_id"),           # base64url
                Field("public_key", "text"),      # base64url COSE key
                Field("sign_count", "integer", default=0),
                Field("label"),
                Field("created_on", "datetime", default=now, writable=False),
            )

    @property
    def table(self):
        return self.db[self.prefix + "credential"]

    def add(self, uid, credential_id, public_key, *, sign_count=0, label="passkey"):
        return self.table.insert(user=uid, credential_id=credential_id, public_key=public_key,
                                 sign_count=sign_count, label=label)

    def for_user(self, uid):
        return self.db(self.table.user == uid).select()

    def by_credential_id(self, credential_id):
        return self.db(self.table.credential_id == credential_id).select().first()

    def bump_sign_count(self, credential_id, sign_count):
        return self.db(self.table.credential_id == credential_id).update(sign_count=sign_count)


class PasskeyManager:
    def __init__(self, *, rp_id, rp_name, origin, store: CredentialStore):
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self.store = store

    def begin_registration(self, user):
        """Return (options_json, challenge_bytes). Send options to the browser."""
        import webauthn
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor

        exclude = [PublicKeyCredentialDescriptor(id=_b64u_dec(c.credential_id))
                   for c in self.store.for_user(user["id"])]
        opts = webauthn.generate_registration_options(
            rp_id=self.rp_id, rp_name=self.rp_name,
            user_id=str(user["id"]).encode(), user_name=user.get("email", str(user["id"])),
            exclude_credentials=exclude)
        return webauthn.options_to_json(opts), opts.challenge

    def complete_registration(self, user, response_json, challenge, *, label="passkey"):
        import webauthn
        v = webauthn.verify_registration_response(
            credential=response_json, expected_challenge=challenge,
            expected_rp_id=self.rp_id, expected_origin=self.origin)
        self.store.add(user["id"], _b64u(v.credential_id), _b64u(v.credential_public_key),
                       sign_count=v.sign_count, label=label)
        return True

    def begin_authentication(self, user=None):
        import webauthn
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor

        allow = None
        if user is not None:
            allow = [PublicKeyCredentialDescriptor(id=_b64u_dec(c.credential_id))
                     for c in self.store.for_user(user["id"])]
        opts = webauthn.generate_authentication_options(rp_id=self.rp_id, allow_credentials=allow)
        return webauthn.options_to_json(opts), opts.challenge

    def complete_authentication(self, response_json, challenge):
        """Verify an assertion; return the owning uid or None."""
        import json

        import webauthn
        cred_id = json.loads(response_json)["id"] if isinstance(response_json, str) else response_json["id"]
        row = self.store.by_credential_id(cred_id)
        if not row:
            return None
        webauthn.verify_authentication_response(
            credential=response_json, expected_challenge=challenge,
            expected_rp_id=self.rp_id, expected_origin=self.origin,
            credential_public_key=_b64u_dec(row.public_key), credential_current_sign_count=row.sign_count)
        return row.user


def _b64u(b) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s) -> bytes:
    import base64
    if isinstance(s, bytes):
        return s
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


__all__ = ["CredentialStore", "PasskeyManager"]
