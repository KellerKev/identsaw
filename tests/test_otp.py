from sqladal import DAL

from identsaw import Auth, SqladalUserStore, TOTPMethod, TOTPStore, install_identity_models
from identsaw.otp import generate_secret, provisioning_uri, totp, verify


def test_totp_roundtrip_and_drift():
    s = generate_secret()
    t = 1_000_000
    code = totp(s, t)
    assert len(code) == 6 and code.isdigit()
    assert verify(s, code, t)
    assert verify(s, code, t + 29)              # same 30s step
    assert verify(s, totp(s, t - 30), t)         # ±1 step drift accepted
    wrong = "111111" if code != "111111" else "222222"
    assert not verify(s, wrong, t)
    assert not verify(s, code, t + 120)          # far outside the window


def test_provisioning_uri():
    uri = provisioning_uri("ABC", "a@x.io", issuer="acme")
    assert uri.startswith("otpauth://totp/") and "secret=ABC" in uri and "issuer=acme" in uri


def test_store_enroll_confirm_check_and_method():
    db = DAL("sqlite://:memory:")
    install_identity_models(db)
    store = SqladalUserStore(db)
    auth = Auth(store)
    uid, _ = auth.register("a@x.io", "pw")

    totp_store = TOTPStore(db)
    auth.register_method(TOTPMethod(totp_store))
    secret = totp_store.enroll(uid)
    assert not totp_store.is_enabled(uid)                    # unconfirmed
    assert auth.authenticate("totp", uid=uid, code=totp(secret)) is None   # not enabled yet

    assert totp_store.confirm(uid, totp(secret)) and totp_store.is_enabled(uid)
    assert auth.authenticate("totp", uid=uid, code=totp(secret))["email"] == "a@x.io"
    cur = totp(secret)
    bad = "111111" if cur != "111111" else "222222"
    assert auth.authenticate("totp", uid=uid, code=bad) is None
    db.close()
