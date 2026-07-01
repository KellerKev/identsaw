import io
import json

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt                                           # noqa: E402
from jwt.algorithms import RSAAlgorithm             # noqa: E402
from sqladal import DAL                              # noqa: E402

from identsaw import Auth, SqladalUserStore, install_identity_models   # noqa: E402
from identsaw.idp import OIDCError, OpenIDProvider, mount_idp          # noqa: E402


def _setup():
    db = DAL("sqlite://:memory:")
    install_identity_models(db)
    auth = Auth(SqladalUserStore(db))
    uid, _ = auth.register("a@x.io", "pw", first_name="Ada")
    idp = OpenIDProvider(issuer="https://id.test/oauth", auth=auth)
    idp.register_client("webapp", "s3cret", ["https://app/cb"])
    return db, auth, idp, uid


def test_discovery_and_jwks():
    db, auth, idp, uid = _setup()
    d = idp.discovery()
    assert d["issuer"] == "https://id.test/oauth"
    assert d["authorization_endpoint"].endswith("/authorize") and d["jwks_uri"].endswith("/jwks")
    k = idp.jwks()["keys"][0]
    assert k["kty"] == "RSA" and k["alg"] == "RS256" and k["kid"] and k["n"] and k["e"]
    db.close()


def test_full_code_flow_verified_via_jwks():
    db, auth, idp, uid = _setup()
    code = idp.create_code(client_id="webapp", uid=uid, redirect_uri="https://app/cb",
                           scope="openid email profile", nonce="n1")
    tok = idp.exchange_code(code=code, client_id="webapp", client_secret="s3cret",
                            redirect_uri="https://app/cb")
    assert tok["token_type"] == "Bearer" and tok["id_token"] and tok["access_token"]

    # a client verifies the id_token using the published JWKS
    key = RSAAlgorithm.from_jwk(json.dumps(idp.jwks()["keys"][0]))
    claims = jwt.decode(tok["id_token"], key, algorithms=["RS256"], audience="webapp")
    assert claims["iss"] == "https://id.test/oauth" and claims["sub"] == str(uid)
    assert claims["email"] == "a@x.io" and claims["name"] == "Ada" and claims["nonce"] == "n1"

    info = idp.userinfo(tok["access_token"])
    assert info["sub"] == str(uid) and info["email"] == "a@x.io"
    db.close()


def test_code_single_use_bad_client_and_redirect():
    db, auth, idp, uid = _setup()
    code = idp.create_code(client_id="webapp", uid=uid, redirect_uri="https://app/cb")
    idp.exchange_code(code=code, client_id="webapp", client_secret="s3cret", redirect_uri="https://app/cb")
    with pytest.raises(OIDCError):                                    # reused code
        idp.exchange_code(code=code, client_id="webapp", client_secret="s3cret", redirect_uri="https://app/cb")

    code2 = idp.create_code(client_id="webapp", uid=uid, redirect_uri="https://app/cb")
    with pytest.raises(OIDCError):                                    # wrong secret
        idp.exchange_code(code=code2, client_id="webapp", client_secret="WRONG", redirect_uri="https://app/cb")

    with pytest.raises(OIDCError):                                    # unregistered redirect
        idp.create_code(client_id="webapp", uid=uid, redirect_uri="https://evil/cb")
    db.close()


def _wsgi(app, path, method="GET", form=None, headers=None):
    env = {"REQUEST_METHOD": method, "PATH_INFO": path, "SERVER_NAME": "t", "SERVER_PORT": "80",
           "wsgi.input": io.BytesIO((form or "").encode()), "wsgi.errors": io.StringIO(),
           "wsgi.url_scheme": "http", "QUERY_STRING": ""}
    if form is not None:
        env["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
        env["CONTENT_LENGTH"] = str(len(form))
    for k, v in (headers or {}).items():
        env["HTTP_" + k.upper().replace("-", "_")] = v
    box = {}

    def start(status, hdrs, exc_info=None):
        box["status"] = status
        box["headers"] = dict(hdrs)
    body = b"".join(app.wsgi(env, start)).decode()
    return box["status"], box.get("headers", {}), body


def test_mount_endpoints():
    import ombott_ng
    db, auth, idp, uid = _setup()
    app = ombott_ng.Ombott()
    mount_idp(app, idp, current_user=lambda req: {"id": uid}, base="/oauth")

    _, _, disco = _wsgi(app, "/oauth/.well-known/openid-configuration")
    assert json.loads(disco)["token_endpoint"].endswith("/token")
    _, _, jwks = _wsgi(app, "/oauth/jwks")
    assert json.loads(jwks)["keys"][0]["kty"] == "RSA"

    code = idp.create_code(client_id="webapp", uid=uid, redirect_uri="https://app/cb", scope="openid email")
    form = "code=%s&client_id=webapp&client_secret=s3cret&redirect_uri=https://app/cb" % code
    _, _, tok = _wsgi(app, "/oauth/token", method="POST", form=form)
    payload = json.loads(tok)
    assert payload["id_token"] and payload["access_token"] and payload["token_type"] == "Bearer"
    db.close()
