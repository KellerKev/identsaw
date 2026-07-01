"""identsaw — a reusable identity module.

Local accounts + JWT sessions/API tokens + pluggable OAuth2/OIDC login, behind an
abstract :class:`UserStore` so it isn't tied to any one database or framework. Use
it standalone, or as the auth layer under guardsaw.

    from identsaw import Auth, SqladalUserStore, install_identity_models
    install_identity_models(db)
    auth = Auth(SqladalUserStore(db), secret="change-me")
"""
from __future__ import annotations

from .auth import Auth
from .jwt import jwt_decode, jwt_encode
from .magiclink import MagicLink, MagicLinkMethod
from .methods import AuthMethod, PasswordMethod
from .otp import TOTPMethod, TOTPStore
from .providers import (GitHubOAuth2, GoogleOAuth2, OAuth2Provider, OIDCProvider,
                        Provider, SAMLProvider)
from .stores import SqladalUserStore, UserStore, install_identity_models

__all__ = [
    "Auth", "UserStore", "SqladalUserStore", "install_identity_models",
    "AuthMethod", "PasswordMethod",
    "Provider", "OAuth2Provider", "GoogleOAuth2", "GitHubOAuth2", "OIDCProvider", "SAMLProvider",
    "TOTPStore", "TOTPMethod", "MagicLink", "MagicLinkMethod",
    "jwt_encode", "jwt_decode",
]

__version__ = "0.1.0"
