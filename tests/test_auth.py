"""identsaw standalone — local accounts, JWT tokens, OAuth upsert, method registry
and the events hook, over the default sqladal user store."""
from sqladal import DAL

from identsaw import Auth, SqladalUserStore, install_identity_models
from identsaw.providers import Provider


def _setup(events=None):
    db = DAL("sqlite://:memory:")
    install_identity_models(db)
    return db, Auth(SqladalUserStore(db), secret="s3cr3t", events=events)


class _MockProvider(Provider):
    name = "mock"

    def authorize_url(self, state, redirect_uri):
        return "https://idp.example/auth?state=%s" % state

    def exchange_code(self, code, redirect_uri):
        return {"access_token": "tok", "_code": code}

    def map_profile(self, tokens):
        return {"provider_uid": "u123", "email": "sso@x.io",
                "first_name": "Single", "username": "sso"}


def test_local_register_login():
    db, auth = _setup()
    uid, err = auth.register("a@x.io", "pw1", username="a")
    assert uid and err is None
    assert auth.register("a@x.io", "pw2")[1]                  # duplicate -> error
    u = auth.login("a@x.io", "pw1")
    assert u and u["email"] == "a@x.io" and u["username"] == "a"
    assert auth.login("a@x.io", "wrong") is None
    assert auth.login("nobody@x.io", "pw") is None
    db.close()


def test_method_registry():
    db, auth = _setup()
    auth.register("a@x.io", "pw")
    assert "password" in auth.methods
    u = auth.authenticate("password", email="a@x.io", password="pw")
    assert u and u["email"] == "a@x.io"
    assert auth.authenticate("password", email="a@x.io", password="nope") is None
    db.close()


def test_jwt_token_roundtrip_and_revocation():
    db, auth = _setup()
    uid, _ = auth.register("a@x.io", "pw")
    tok = auth.issue_token(uid, scopes=["read:doc"])
    su, scopes = auth.token_user(tok)
    assert su["id"] == uid and "read:doc" in scopes
    assert auth.token_user("garbage") is None

    class _Req:
        headers = {"Authorization": "Bearer " + tok}
    user, sc = auth.bearer_resolver()(_Req())
    assert user["id"] == uid and "read:doc" in sc

    # persisted token can be revoked
    ptok = auth.issue_token(uid, persist=True, name="cli")
    import identsaw.jwt as J
    jti = J.jwt_decode(ptok, "s3cr3t")["jti"]
    assert auth.verify_token(ptok) is not None
    auth.revoke_token(jti)
    assert auth.verify_token(ptok) is None
    db.close()


def test_oauth_upsert_then_link_existing():
    db, auth = _setup()
    auth.register_provider(_MockProvider())
    u1 = auth.oauth_callback("mock", "code", "https://app/cb")
    assert u1["email"] == "sso@x.io"
    u2 = auth.oauth_callback("mock", "code2", "https://app/cb")   # same provider uid
    assert u2["id"] == u1["id"]
    # a second store query: no duplicate user / link
    store = auth.store
    assert db(store.users.email == "sso@x.io").count() == 1
    assert db(store.oauth.provider_uid == "u123").count() == 1

    # links to a pre-existing local email instead of recreating
    uid, _ = auth.register("local@x.io", "pw")

    class _P(_MockProvider):
        def map_profile(self, tokens):
            return {"provider_uid": "other", "email": "local@x.io"}
    auth.register_provider(_P())
    auth.providers["mock"] = _P()
    assert auth.oauth_callback("mock", "c", "cb")["id"] == uid
    db.close()


def test_events_hook():
    seen = []
    db, auth = _setup(events=lambda e, uid, d: seen.append((e, uid)))
    auth.register("a@x.io", "pw")
    auth.login("a@x.io", "pw")
    auth.login("a@x.io", "bad")
    kinds = [e for e, _ in seen]
    assert "register" in kinds and "login.success" in kinds and "login.fail" in kinds
    db.close()
