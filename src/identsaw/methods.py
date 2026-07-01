"""Authentication-method registry.

A *method* is one way to prove identity. Password is built in; future methods
(TOTP/OTP, magic-link, WebAuthn/passkey) register the same way and are reachable
through ``auth.authenticate(name, **kwargs)``. Providers (OAuth2/OIDC/SAML) are a
separate registry (see :mod:`identsaw.providers`) because they federate identity
rather than verify a local credential.
"""
from __future__ import annotations


class AuthMethod:
    name = ""

    def authenticate(self, auth, **kw):
        """Return a session-user dict on success, or ``None``."""
        raise NotImplementedError


class PasswordMethod(AuthMethod):
    name = "password"

    def authenticate(self, auth, *, email, password, **_):
        return auth.login(email, password)


__all__ = ["AuthMethod", "PasswordMethod"]
