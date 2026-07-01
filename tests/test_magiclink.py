from sqladal import DAL

from identsaw import Auth, MagicLink, MagicLinkMethod, SqladalUserStore, install_identity_models


def _store():
    db = DAL("sqlite://:memory:")
    install_identity_models(db)
    return db, SqladalUserStore(db)


def test_create_consume_single_use():
    db, store = _store()
    uid = store.create("a@x.io")
    ml = MagicLink("secret", store=store)
    tok = ml.create(uid=uid, email="a@x.io")
    claims = ml.consume(tok)
    assert claims["sub"] == uid and claims["email"] == "a@x.io"
    assert ml.consume(tok) is None                     # single-use: burned
    db.close()


def test_stateless_replayable_and_bad_tokens():
    ml = MagicLink("secret")                            # no store -> stateless
    tok = ml.create(email="a@x.io")
    assert ml.consume(tok)["email"] == "a@x.io"
    assert ml.consume(tok)["email"] == "a@x.io"         # replayable without a store
    assert ml.consume("garbage") is None
    assert ml.consume(ml.create(email="x", purpose="reset")) is None   # purpose mismatch
    assert MagicLink("other-secret").consume(tok) is None              # wrong signature


def test_magiclink_auth_method():
    db, store = _store()
    store.create("a@x.io")
    auth = Auth(store)
    ml = MagicLink("s", store=store)
    auth.register_method(MagicLinkMethod(ml))
    u = auth.authenticate("magiclink", token=ml.create(email="a@x.io"))
    assert u["email"] == "a@x.io"
    db.close()
