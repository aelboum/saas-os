"""ADR-0024 -- `infra/edge/origin.py`: what a browser-visible origin is
allowed to be, and the one derivation of the OIDC callback from it. No
network, no database, no environment reads."""

from __future__ import annotations

import pytest

from infra.edge import (
    AUTH_CALLBACK_PATH,
    PublicAppOriginError,
    callback_url_for,
    normalize_public_app_origin,
    resolve_callback_url,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://app.example.com", "https://app.example.com"),
        ("https://app.example.com/", "https://app.example.com"),
        ("http://localhost:8080", "http://localhost:8080"),
        ("HTTPS://App.Example.COM", "https://app.example.com"),
        ("https://app.example.com:8443", "https://app.example.com:8443"),
        ("  http://localhost:8080  ", "http://localhost:8080"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        # An IPv6 literal keeps its brackets -- `urlsplit(...).hostname`
        # strips them, and reassembling unbracketed yields `http://::1:8080`.
        ("http://[::1]:8080", "http://[::1]:8080"),
        ("http://[::1]", "http://[::1]"),
        ("https://[2001:DB8::1]:8443/", "https://[2001:db8::1]:8443"),
    ],
)
def test_valid_origins_are_canonicalized(raw: str, expected: str) -> None:
    assert normalize_public_app_origin(raw) == expected


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "   ",
        "localhost:8080",  # no scheme
        "app.example.com",
        "ftp://app.example.com",
        "https://",  # no host
        "//app.example.com",
    ],
)
def test_an_origin_must_be_an_absolute_http_origin(bad: str | None) -> None:
    with pytest.raises(PublicAppOriginError):
        normalize_public_app_origin(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "https://app.example.com/app",
        "https://app.example.com/auth/callback",
        "https://app.example.com?next=/x",
        "https://app.example.com#fragment",
        "http://localhost:8080/t/1/dashboard",
    ],
)
def test_an_origin_may_not_carry_a_path_query_or_fragment(bad: str) -> None:
    """The product's own routes never belong in SaaS-OS configuration --
    a dashboard path smuggled in here would make SaaS-OS own it."""
    with pytest.raises(PublicAppOriginError):
        normalize_public_app_origin(bad)


def test_an_origin_may_not_embed_credentials() -> None:
    with pytest.raises(PublicAppOriginError):
        normalize_public_app_origin("https://user:pass@app.example.com")  # pragma: allowlist secret


def test_an_ipv6_origin_derives_a_structurally_valid_callback() -> None:
    assert callback_url_for("http://[::1]:8080") == "http://[::1]:8080/auth/callback"
    assert (
        resolve_callback_url(
            public_app_origin="http://[::1]:8080",
            redirect_uri="http://[::1]:8080/auth/callback",
        )
        == "http://[::1]:8080/auth/callback"
    )


def test_an_invalid_port_is_rejected_rather_than_silently_dropped() -> None:
    with pytest.raises(PublicAppOriginError):
        normalize_public_app_origin("http://localhost:not-a-port")


@pytest.mark.parametrize(
    "malformed",
    [
        "https://app.example.com:notaport/auth/callback",
        "https://app.example.com:99999/auth/callback",
    ],
)
def test_a_malformed_redirect_uri_port_raises_the_module_error(malformed: str) -> None:
    """A non-numeric/out-of-range port in `OIDC_REDIRECT_URI` must surface as
    this module's own configuration error, not leak a bare `ValueError` from
    `urlsplit` out of the comparison path."""
    with pytest.raises(PublicAppOriginError):
        resolve_callback_url(public_app_origin="https://app.example.com", redirect_uri=malformed)


def test_plaintext_origin_is_refused_in_production() -> None:
    with pytest.raises(PublicAppOriginError):
        normalize_public_app_origin("http://app.example.com", environment="production")


def test_plaintext_origin_is_allowed_outside_production() -> None:
    assert normalize_public_app_origin("http://localhost:8080", environment="development")


def test_callback_is_derived_from_the_origin_and_is_not_configurable() -> None:
    assert callback_url_for("https://app.example.com") == "https://app.example.com/auth/callback"
    assert AUTH_CALLBACK_PATH == "/auth/callback"


def test_only_a_redirect_uri_keeps_pre_adr_0024_behavior_exactly() -> None:
    assert (
        resolve_callback_url(
            public_app_origin=None, redirect_uri="http://localhost:8000/auth/callback"
        )
        == "http://localhost:8000/auth/callback"
    )


def test_only_an_origin_derives_the_callback() -> None:
    assert (
        resolve_callback_url(public_app_origin="http://localhost:8080", redirect_uri=None)
        == "http://localhost:8080/auth/callback"
    )


def test_neither_setting_resolves_to_none_for_the_caller_to_report() -> None:
    assert resolve_callback_url(public_app_origin=None, redirect_uri=None) is None
    assert resolve_callback_url(public_app_origin="", redirect_uri="  ") is None


def test_both_settings_agreeing_is_accepted() -> None:
    assert (
        resolve_callback_url(
            public_app_origin="https://app.example.com",
            redirect_uri="https://app.example.com/auth/callback",
        )
        == "https://app.example.com/auth/callback"
    )


@pytest.mark.parametrize(
    "conflicting",
    [
        "https://evil.example.com/auth/callback",
        "https://app.example.com:9443/auth/callback",
        "http://app.example.com/auth/callback",
        "https://app.example.com/other/callback",
    ],
)
def test_both_settings_disagreeing_fails_closed(conflicting: str) -> None:
    """Never silent precedence either way -- a callback on a different
    origin than the application is exactly the split-origin defect this
    phase exists to prevent."""
    with pytest.raises(PublicAppOriginError):
        resolve_callback_url(public_app_origin="https://app.example.com", redirect_uri=conflicting)
