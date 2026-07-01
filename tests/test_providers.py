"""Provider URL building + profile mapping (no network)."""
from identsaw import GitHubOAuth2, GoogleOAuth2, OAuth2Provider


def test_google_authorize_url():
    g = GoogleOAuth2("cid", "secret")
    url = g.authorize_url("xyz", "https://app/cb")
    assert "accounts.google.com" in url and "state=xyz" in url and "client_id=cid" in url
    assert "redirect_uri=https%3A%2F%2Fapp%2Fcb" in url


def test_github_profile_map():
    gh = GitHubOAuth2("c", "s")
    prof = gh.profile_map({"id": 42, "login": "octocat", "email": "o@gh.io", "name": "Octo"})
    assert prof["provider_uid"] == "42" and prof["username"] == "octocat" and prof["email"] == "o@gh.io"


def test_default_profile_map():
    p = OAuth2Provider("x", "c", "s", authorize_endpoint="https://a", token_endpoint="https://t")
    info = {"sub": "9", "email": "e@x.io", "given_name": "Gn", "family_name": "Fn",
            "preferred_username": "u"}
    m = p._default_map(info)
    assert m == {"provider_uid": "9", "email": "e@x.io", "first_name": "Gn",
                 "last_name": "Fn", "username": "u"}
