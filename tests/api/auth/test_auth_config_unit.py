"""P2.2 -- `api/auth/config.py`: redirect-URI allowlisting, open-redirect
rejection for the post-login path, and production-only cookie rules. No
network, no database."""

from __future__ import annotations

import pytest
from api.auth.config import AuthConfigurationError, AuthHttpConfig, get_auth_http_config


@pytest.fixture(autouse=True)
def _clear_cache():
    get_auth_http_config.cache_clear()
    yield
    get_auth_http_config.cache_clear()


def test_valid_https_configuration() -> None:
    config = AuthHttpConfig(redirect_uri="https://app.example.com/auth/callback")
    assert config.cookie_name == "saas_os_session"
    assert config.cookie_secure is True
    assert config.post_login_path == "/"
    assert config.login_transaction_cookie_name == "saas_os_session_login"


@pytest.mark.parametrize("bad", ["", "not-a-url", "/auth/callback", "ftp://x/cb", "https:///cb"])
def test_redirect_uri_must_be_an_absolute_http_url(bad: str) -> None:
    with pytest.raises(AuthConfigurationError):
        AuthHttpConfig(redirect_uri=bad)


def test_http_redirect_uri_is_refused_in_production() -> None:
    with pytest.raises(AuthConfigurationError):
        AuthHttpConfig(
            redirect_uri="http://app.example.com/auth/callback", environment="production"
        )


def test_http_redirect_uri_is_allowed_outside_production() -> None:
    config = AuthHttpConfig(redirect_uri="http://localhost:8000/auth/callback", environment="test")
    assert config.redirect_uri.startswith("http://")


def test_insecure_cookie_is_refused_in_production() -> None:
    with pytest.raises(AuthConfigurationError):
        AuthHttpConfig(
            redirect_uri="https://app.example.com/auth/callback",
            cookie_secure=False,
            environment="production",
        )


def test_insecure_cookie_is_allowed_only_as_an_explicit_development_setting() -> None:
    config = AuthHttpConfig(
        redirect_uri="http://localhost:8000/auth/callback",
        cookie_secure=False,
        environment="development",
    )
    assert config.cookie_secure is False


@pytest.mark.parametrize(
    "bad_path",
    [
        "https://attacker.example",
        "//attacker.example",
        "/\\attacker.example",
        "javascript:alert(1)",
        "app",
        "",
    ],
)
def test_post_login_path_rejects_open_redirect_shapes(bad_path: str) -> None:
    with pytest.raises(AuthConfigurationError):
        AuthHttpConfig(
            redirect_uri="https://app.example.com/auth/callback", post_login_path=bad_path
        )


def test_post_login_path_accepts_a_same_origin_absolute_path() -> None:
    config = AuthHttpConfig(
        redirect_uri="https://app.example.com/auth/callback", post_login_path="/app/home?tab=1"
    )
    assert config.post_login_path == "/app/home?tab=1"


@pytest.mark.parametrize("bad_name", ["", "with space", "semi;colon", "a=b"])
def test_cookie_name_must_be_identifier_like(bad_name: str) -> None:
    with pytest.raises(AuthConfigurationError):
        AuthHttpConfig(redirect_uri="https://app.example.com/auth/callback", cookie_name=bad_name)


def test_env_missing_redirect_uri_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OIDC_REDIRECT_URI", raising=False)
    with pytest.raises(AuthConfigurationError):
        get_auth_http_config()


def test_env_parses_every_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://app.example.com/auth/callback")
    monkeypatch.setenv("AUTH_COOKIE_NAME", "custom_session")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    monkeypatch.setenv("AUTH_POST_LOGIN_PATH", "/dashboard")
    monkeypatch.setenv("ENVIRONMENT", "production")
    config = get_auth_http_config()
    assert config.cookie_name == "custom_session"
    assert config.cookie_secure is True
    assert config.post_login_path == "/dashboard"
    assert config.environment == "production"


def test_env_invalid_boolean_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://app.example.com/auth/callback")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "maybe")
    with pytest.raises(AuthConfigurationError):
        get_auth_http_config()
