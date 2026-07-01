"""identsaw OIDC IdP demo — one process plays both the identity provider AND a
client app, proving real OpenID-Connect SSO end to end.

    cd identsaw && pixi run python examples/idp_demo/serve.py
    open http://127.0.0.1:8070/            (ada@demo.io / secret)

Flow: /app (the client) → /oauth/authorize (the IdP) → /login → back to the client
/callback, which exchanges the code at the token endpoint and verifies the id_token
against the IdP's published JWKS. /mfa shows TOTP enrollment; /magic a magic-link.
"""
import json
import os
from urllib.parse import urlencode

import jwt
import ombott_ng
from jwt.algorithms import RSAAlgorithm
from sqladal import DAL

from identsaw import Auth, MagicLink, SqladalUserStore, TOTPStore, install_identity_models
from identsaw.idp import OpenIDProvider, mount_idp
from identsaw.otp import provisioning_uri, totp

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 8070
ROOT = "http://127.0.0.1:%d" % PORT
ISSUER = ROOT + "/oauth"
CLIENT_ID, CLIENT_SECRET = "demoapp", "client-secret"
CALLBACK = ROOT + "/callback"

db = DAL("sqlite://idp.db", folder=HERE)
install_identity_models(db)
store = SqladalUserStore(db)
auth = Auth(store)
totp_store = TOTPStore(db)
magic = MagicLink("magic-secret", store=store)

if not store.by_email("ada@demo.io"):
    auth.register("ada@demo.io", "secret", first_name="Ada")

idp = OpenIDProvider(issuer=ISSUER, auth=auth)
idp.register_client(CLIENT_ID, CLIENT_SECRET, [CALLBACK])

app = ombott_ng.Ombott()


def _page(body):
    return ('<!doctype html><html data-theme="dark"><meta charset="utf-8">'
            '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@1.0.2/css/bulma.min.css">'
            '<section class="section"><div class="container">%s</div></section></html>' % body)


def current_user(request):
    tok = request.get_cookie("idp_session")
    r = auth.token_user(tok) if tok else None
    return r[0] if r else None


@app.get("/")
def _home():
    u = current_user(ombott_ng.request)
    who = ("signed in as <b>%s</b> &middot; <a href='/logout'>logout</a>" % u["email"]) if u \
        else "not signed in"
    return _page(
        "<h1 class='title'>identsaw IdP demo</h1><p>%s</p>"
        "<div class='buttons' style='margin-top:1rem'>"
        "<a class='button is-primary' href='/app'>Log in to demoapp via SSO</a>"
        "<a class='button' href='/login'>IdP login</a>"
        "<a class='button' href='/mfa'>TOTP (MFA)</a>"
        "<a class='button' href='/magic'>Magic link</a></div>" % who)


@app.get("/login")
def _login_form():
    nxt = ombott_ng.request.query.get("next") or "/"
    return _page(
        "<h1 class='title'>IdP login</h1><form method='post' action='/login'>"
        "<input type='hidden' name='next' value='%s'>"
        "<div class='field'><input class='input' name='email' value='ada@demo.io'></div>"
        "<div class='field'><input class='input' type='password' name='password' value='secret'></div>"
        "<button class='button is-primary'>Sign in</button></form>" % nxt)


@app.post("/login")
def _login():
    f = ombott_ng.request.forms
    u = auth.login(f.get("email"), f.get("password"))
    if not u:
        ombott_ng.response.status = 401
        return _page("<p class='notification is-danger'>bad credentials</p><a href='/login'>back</a>")
    ombott_ng.response.set_cookie("idp_session", auth.issue_token(u, exp=86400), path="/")
    ombott_ng.redirect(f.get("next") or "/")


@app.get("/logout")
def _logout():
    ombott_ng.response.set_cookie("idp_session", "", path="/", max_age=0)
    ombott_ng.redirect("/")


# --- the CLIENT app (delegates identity to the IdP over OIDC) --------------
@app.get("/app")
def _app_start():
    params = urlencode({"client_id": CLIENT_ID, "redirect_uri": CALLBACK,
                        "response_type": "code", "scope": "openid email profile",
                        "state": "xyz", "nonce": "n-123"})
    ombott_ng.redirect(ISSUER + "/authorize?" + params)


@app.get("/callback")
def _callback():
    code = ombott_ng.request.query.get("code")
    if not code:
        return _page("<p class='notification is-danger'>no code</p>")
    # back-channel token exchange (in-process here — same process plays both roles;
    # a separate client would POST to ISSUER + "/token" over HTTP)
    tokens = idp.exchange_code(code=code, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
                               redirect_uri=CALLBACK)
    # verify the id_token against the IdP's published JWKS (as any OIDC client does)
    key = RSAAlgorithm.from_jwk(json.dumps(idp.jwks()["keys"][0]))
    claims = jwt.decode(tokens["id_token"], key, algorithms=["RS256"], audience=CLIENT_ID)
    rows = "".join("<tr><td>%s</td><td>%s</td></tr>" % (k, v) for k, v in claims.items())
    return _page(
        "<h1 class='title'>SSO success</h1>"
        "<p class='subtitle is-6'>demoapp verified this id_token via the IdP's JWKS</p>"
        "<table class='table is-striped'>%s</table><a class='button' href='/'>home</a>" % rows)


# --- MFA + magic-link showcases -------------------------------------------
@app.get("/mfa")
def _mfa():
    u = current_user(ombott_ng.request)
    if not u:
        ombott_ng.redirect("/login?next=/mfa")
        return
    secret = totp_store.secret_for(u["id"]) or totp_store.enroll(u["id"])
    uri = provisioning_uri(secret, u["email"], issuer="identsaw-demo")
    return _page(
        "<h1 class='title'>TOTP enrollment</h1>"
        "<p>Add this secret to an authenticator app (or scan the otpauth URI):</p>"
        "<p class='notification'><code>%s</code></p>"
        "<p>otpauth URI: <code>%s</code></p>"
        "<p>current 6-digit code (demo only): <b>%s</b></p><a class='button' href='/'>home</a>"
        % (secret, uri, totp(secret)))


@app.get("/magic")
def _magic():
    u = store.by_email("ada@demo.io")
    link = ROOT + "/magic/consume?token=" + magic.create(uid=u.id, email=u.email)
    return _page("<h1 class='title'>Magic link</h1><p>Emailed link (single-use):</p>"
                 "<p><a href='%s'>%s</a></p>" % (link, link))


@app.get("/magic/consume")
def _magic_consume():
    claims = magic.consume(ombott_ng.request.query.get("token"))
    if not claims:
        return _page("<p class='notification is-danger'>invalid or already-used link</p>")
    u = auth.user(claims["sub"])
    ombott_ng.response.set_cookie("idp_session", auth.issue_token(u, exp=86400), path="/")
    return _page("<p class='notification is-success'>logged in as %s via magic link</p>"
                 "<a class='button' href='/'>home</a>" % u["email"])


mount_idp(app, idp, current_user=current_user, base="/oauth", login_path="/login")


def main():
    print("\n  identsaw IdP demo:  %s/   (ada@demo.io / secret)\n"
          "    /app  -> full OIDC SSO loop   /mfa -> TOTP   /magic -> magic link\n" % ROOT)
    ombott_ng.run(app, server="uvicorn", host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    main()
