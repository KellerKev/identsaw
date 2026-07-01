```
    __
   /o \___________________    the Keymaster
   \__/  i d e n t s a w  ]==  one door -- every key (password/OIDC/passkey/OTP)
         `----------------'
```

# identsaw

A reusable identity module: **local accounts + JWT sessions/API tokens + pluggable
OAuth2/OIDC login**, behind an abstract **user store** so it isn't tied to any one
database or web framework. Use it standalone, or as the auth layer under
[guardsaw](../guardsaw).

```python
from sqladal import DAL
from identsaw import Auth, SqladalUserStore, install_identity_models

db = DAL("sqlite://app.db")
install_identity_models(db)                 # id_user / id_oauth / id_token

auth = Auth(SqladalUserStore(db), secret="change-me")
uid, _ = auth.register("a@x.io", "pw")
user   = auth.login("a@x.io", "pw")         # -> session dict, or None
token  = auth.issue_token(uid, scopes=["read:doc"])   # signed HS256 JWT
```

## What's here

- **`Auth`** — register / login, JWT `issue_token` / `verify_token` / `revoke_token`,
  `bearer_resolver`, and OAuth `oauth_login_url` / `oauth_callback`.
- **`UserStore`** — the persistence contract Auth depends on. **`SqladalUserStore`**
  is the default (over sqladal/pydal tables); point it at any compatible schema
  (`prefix="gs_"` for guardsaw's `gs_*` tables, `prefix="id_"` for the bundled one).
- **Method registry** — `password` is built in; OTP / magic-link / passkey register
  the same way (`auth.register_method`, `auth.authenticate(name, ...)`).
- **Providers** — `GoogleOAuth2`, `GitHubOAuth2`, and `OIDCProvider` (any IdP via
  `.well-known` discovery + JWKS). SAML is planned.
- **`events`** callback `(event, user_id, detail)` — login / register / token / oauth
  events for audit logging (guardsaw wires this to its audit trail).

Core is **stdlib-only** (HS256 JWT included). Extras: `sqladal` (the store),
`oidc` (`httpx` + `pyjwt[crypto]` for OAuth2/OIDC).

## Roadmap

WebAuthn/passkeys, magic-link, OTP/TOTP, and a SAML provider — plus a centralized
OIDC IdP — land in later phases.

---

*Part of the **[websaw-ng](https://github.com/KellerKev/websaw-ng)** platform &middot; forging your dreams &middot; install: `pixi add identsaw` from the `websaw-ng` conda channel.*
