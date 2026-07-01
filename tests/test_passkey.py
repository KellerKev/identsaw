import json

import pytest

pytest.importorskip("webauthn")

from sqladal import DAL                                        # noqa: E402

from identsaw import install_identity_models                  # noqa: E402
from identsaw.passkey import CredentialStore, PasskeyManager   # noqa: E402


def _db():
    db = DAL("sqlite://:memory:")
    install_identity_models(db)
    return db


def test_credential_store_crud():
    db = _db()
    uid = db["id_user"].insert(email="a@x.io")
    cs = CredentialStore(db)
    cs.add(uid, "credid", "pubkey", sign_count=1, label="yubikey")
    assert len(cs.for_user(uid)) == 1
    row = cs.by_credential_id("credid")
    assert row.public_key == "pubkey" and row.label == "yubikey"
    cs.bump_sign_count("credid", 5)
    assert cs.by_credential_id("credid").sign_count == 5
    db.close()


def test_begin_registration_and_authentication_options():
    db = _db()
    uid = db["id_user"].insert(email="a@x.io")
    pk = PasskeyManager(rp_id="example.com", rp_name="Example",
                        origin="https://example.com", store=CredentialStore(db))

    opts_json, challenge = pk.begin_registration({"id": uid, "email": "a@x.io"})
    opts = json.loads(opts_json)
    assert opts["rp"]["id"] == "example.com" and opts["challenge"] and challenge

    auth_json, auth_challenge = pk.begin_authentication()
    assert json.loads(auth_json)["challenge"] and auth_challenge
    db.close()
