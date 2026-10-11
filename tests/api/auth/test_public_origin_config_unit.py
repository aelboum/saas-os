"""ADR-0024 -- `saas_os/api/auth/config.py`'s single-origin behavior: the OIDC
callback derives from `PUBLIC_APP_ORIGIN`, the pre-existing
`OIDC_REDIRECT_URI`-only configuration is unchanged, and a disagreement
between the two fails closed. No network, no database."""

from __future__ import annotations

import pytest

from saas_os.api.auth.config import AuthConfigurationError, AuthHttpConfig, get_auth_http_config


@pytest.fixture(autouse=True)
def _clear_cache():
    get_auth_http_config.cache_clear()
    yield
    get_auth_http_config.cache_clear()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for name in ("PUBLIC_APP_ORIGIN", "OIDC_REDIRECT_URI", "ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)


def test_public_app_origin_alone_derives_the_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUBLIC_APP_ORIGIN", "http://localhost:8080")
    config = get_auth_http_config()
    assert config.redirect_uri == "http://localhost:8080/auth/callback"
    assert config.normalized_public_app_origin == "http://localhost:8080"


def test_redirect_uri_alone_is_unchanged_from_before(monkeypatch: pytest.MonkeyPatch) -> None:
    """Backward compatibility: an existing two-origin local `.env` that
    never heard of PUBLIC_APP_ORIGIN keeps working exactly as it did."""
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://localhost:8000/auth/callback")
    config = get_auth_http_config()
    assert config.redirect_uri == "http://localhost:8000/auth/callback"
    assert config.public_app_origin is None
    assert config.normalized_public_app_origin is None


def test_both_agreeing_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUBLIC_APP_ORIGIN", "https://app.example.com")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://app.example.com/auth/callback")
    assert get_auth_http_config().redirect_uri == "https://app.example.com/auth/callback"


def test_both_disagreeing_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUBLIC_APP_ORIGIN", "https://app.example.com")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://elsewhere.example.com/auth/callback")
    with pytest.raises(AuthConfigurationError):
        get_auth_http_config()


def test_neither_setting_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AuthConfigurationError):
        get_auth_http_config()


def test_a_plaintext_public_origin_is_refused_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("PUBLIC_APP_ORIGIN", "http://app.example.com")
    with pytest.raises(AuthConfigurationError):
        get_auth_http_config()


@pytest.mark.parametrize(
    "bad",
    ["https://app.example.com/app", "not-an-origin", "https://app.example.com?next=/x"],
)
def test_a_malformed_public_origin_is_rejected(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv("PUBLIC_APP_ORIGIN", bad)
    with pytest.raises(AuthConfigurationError):
        get_auth_http_config()


def test_a_directly_constructed_config_cannot_bypass_the_consistency_check() -> None:
    """A consuming project composing `AuthHttpConfig` itself gets the same
    fail-closed check the environment path gets."""
    with pytest.raises(AuthConfigurationError):
        AuthHttpConfig(
            redirect_uri="https://elsewhere.example.com/auth/callback",
            public_app_origin="https://app.example.com",
        )


def test_the_post_login_destination_stays_a_fixed_same_origin_path() -> None:
    """The SaaS-OS/product boundary: SaaS-OS sends the browser to a fixed,
    same-origin path and never to a product route it invented, and no
    browser-supplied destination exists to override it."""
    config = AuthHttpConfig(
        redirect_uri="https://app.example.com/auth/callback",
        public_app_origin="https://app.example.com",
    )
    assert config.post_login_path == "/"
    assert not config.post_login_path.startswith("http")
