"""P2.2 -- `saas_os/api/auth/config.py`: redirect-URI allowlisting, open-redirect
rejection for the post-login path, and production-only cookie rules. No
network, no database."""

from __future__ import annotations

import pytest

from saas_os.api.auth.config import AuthConfigurationError, AuthHttpConfig, get_auth_http_config


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


# --- ADR-0064: OIDC_POST_LOGOUT_REDIRECT_URI ----------------------------------------

_APP_CALLBACK = "https://app.example.com/auth/callback"


def test_post_logout_uri_is_optional_and_off_by_default() -> None:
    config = AuthHttpConfig(redirect_uri=_APP_CALLBACK)
    assert config.post_logout_redirect_uri is None
    assert config.post_logout_local_path == "/"


@pytest.mark.parametrize(
    ("uri", "local_path"),
    [
        ("https://app.example.com/", "/"),
        ("https://app.example.com", "/"),
        ("https://app.example.com/signed-out", "/signed-out"),
        ("https://APP.example.com:443/bye?lang=nl", "/bye?lang=nl"),
    ],
)
def test_post_logout_uri_on_the_application_origin_is_accepted(uri: str, local_path: str) -> None:
    config = AuthHttpConfig(redirect_uri=_APP_CALLBACK, post_logout_redirect_uri=uri)
    assert config.post_logout_redirect_uri == uri
    assert config.post_logout_local_path == local_path


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.example.com/",  # another host
        "https://example.com/",  # the parent domain
        "https://sub.app.example.com/",  # a sibling/child subdomain
        "https://app.example.com:8443/",  # another port
        "http://app.example.com/",  # another scheme
        "//app.example.com/",  # scheme-relative
        "/signed-out",  # relative
        "javascript:alert(1)",
        "https://user:pw@app.example.com/",  # credentials  # pragma: allowlist secret
        "https://app.example.com/#frag",  # fragment
        "https://app.example.com/a b",  # whitespace
        r"https://app.example.com/\evil.example.com",  # backslash
        "https://app.example.com:notaport/",
        "",
    ],
)
def test_post_logout_uri_off_the_application_origin_is_refused(uri: str) -> None:
    with pytest.raises(AuthConfigurationError, match="OIDC_POST_LOGOUT_REDIRECT_URI"):
        AuthHttpConfig(redirect_uri=_APP_CALLBACK, post_logout_redirect_uri=uri)


def test_post_logout_uri_follows_public_app_origin_when_declared() -> None:
    config = AuthHttpConfig(
        redirect_uri="https://shop.example.com/auth/callback",
        public_app_origin="https://shop.example.com",
        post_logout_redirect_uri="https://shop.example.com/",
    )
    assert config.post_logout_local_path == "/"
    with pytest.raises(AuthConfigurationError, match="OIDC_POST_LOGOUT_REDIRECT_URI"):
        AuthHttpConfig(
            redirect_uri="https://shop.example.com/auth/callback",
            public_app_origin="https://shop.example.com",
            post_logout_redirect_uri="https://api.example.com/",
        )


def test_post_logout_uri_must_use_https_in_production() -> None:
    with pytest.raises(AuthConfigurationError, match="https in production"):
        AuthHttpConfig(
            redirect_uri="https://app.example.com/auth/callback",
            environment="production",
            post_logout_redirect_uri="http://app.example.com/",
        )
    config = AuthHttpConfig(
        redirect_uri="http://localhost:8000/auth/callback",
        environment="test",
        post_logout_redirect_uri="http://localhost:8000/",
    )
    assert config.post_logout_local_path == "/"


def test_env_reads_post_logout_uri_and_treats_empty_as_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDC_REDIRECT_URI", _APP_CALLBACK)
    monkeypatch.setenv("OIDC_POST_LOGOUT_REDIRECT_URI", "https://app.example.com/bye")
    assert get_auth_http_config().post_logout_redirect_uri == "https://app.example.com/bye"
    get_auth_http_config.cache_clear()
    monkeypatch.setenv("OIDC_POST_LOGOUT_REDIRECT_URI", "")
    assert get_auth_http_config().post_logout_redirect_uri is None
    get_auth_http_config.cache_clear()
    monkeypatch.setenv("OIDC_POST_LOGOUT_REDIRECT_URI", "https://evil.example.com/")
    with pytest.raises(AuthConfigurationError):
        get_auth_http_config()
