"""P2.3 -- `api/auth/routes.py::_resolve_client_address`: the forwarded-
header trust model the pre-login rate limiter depends on. No network, no
proxy -- these tests prove the *decision logic* in isolation; the real
end-to-end proof (a genuine spoofed header through a real Caddy) is
`scripts/check-docker-prod.sh`'s job.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from api.auth.config import AuthHttpConfig
from api.auth.routes import _resolve_client_address

_UNTRUSTED = AuthHttpConfig(redirect_uri="https://app.example.com/auth/callback")
_TRUSTED = AuthHttpConfig(
    redirect_uri="https://app.example.com/auth/callback", trust_proxy_headers=True
)


def _request(*, client_host: str | None, forwarded_for: str | None = None) -> MagicMock:
    request = MagicMock()
    request.client = MagicMock(host=client_host) if client_host is not None else None
    request.headers = {"X-Forwarded-For": forwarded_for} if forwarded_for is not None else {}
    return request


# --- Untrusted (default): header is never read -----------------------------


def test_untrusted_uses_the_direct_peer_even_with_a_forwarded_header_present() -> None:
    request = _request(client_host="203.0.113.9", forwarded_for="9.9.9.9")
    assert _resolve_client_address(request, _UNTRUSTED) == "203.0.113.9"


def test_untrusted_falls_back_to_unknown_when_no_client_info_exists() -> None:
    request = _request(client_host=None)
    assert _resolve_client_address(request, _UNTRUSTED) == "unknown"


# --- Trusted: only the last hop is ever read --------------------------------


def test_trusted_with_no_header_uses_the_direct_peer() -> None:
    request = _request(client_host="10.0.0.5")  # the proxy's own container IP
    assert _resolve_client_address(request, _TRUSTED) == "10.0.0.5"


def test_trusted_single_hop_header_is_used() -> None:
    request = _request(client_host="10.0.0.5", forwarded_for="198.51.100.7")
    assert _resolve_client_address(request, _TRUSTED) == "198.51.100.7"


def test_trusted_multi_hop_header_uses_only_the_last_entry() -> None:
    """The core anti-spoofing property: every entry except the last is
    attacker-controlled (the client can send whatever chain it wants);
    only the rightmost entry -- appended by the trusted proxy itself -- is
    ever trusted."""
    request = _request(client_host="10.0.0.5", forwarded_for="1.2.3.4, 5.6.7.8, 198.51.100.7")
    assert _resolve_client_address(request, _TRUSTED) == "198.51.100.7"


def test_an_attacker_cannot_change_the_resolved_identity_by_prepending_fake_hops() -> None:
    """Same real (trusted) last hop, two different attacker-supplied
    prefixes -- the resolved identity must be identical both times, proving
    the prefix has zero influence."""
    first = _request(
        client_host="10.0.0.5",
        forwarded_for="1.1.1.1",
    )
    second = _request(client_host="10.0.0.5", forwarded_for="9.9.9.9, 8.8.8.8")
    # Both attacker prefixes precede the SAME real last hop appended by the trusted proxy.
    first.headers["X-Forwarded-For"] = "1.1.1.1, 198.51.100.7"
    second.headers["X-Forwarded-For"] = "9.9.9.9, 8.8.8.8, 198.51.100.7"
    assert (
        _resolve_client_address(first, _TRUSTED)
        == _resolve_client_address(second, _TRUSTED)
        == "198.51.100.7"
    )


def test_trusted_header_with_extra_whitespace_is_trimmed() -> None:
    request = _request(client_host="10.0.0.5", forwarded_for="1.2.3.4 ,  198.51.100.7  ")
    assert _resolve_client_address(request, _TRUSTED) == "198.51.100.7"


def test_trusted_empty_header_falls_back_to_the_direct_peer() -> None:
    request = _request(client_host="10.0.0.5", forwarded_for="")
    assert _resolve_client_address(request, _TRUSTED) == "10.0.0.5"


def test_trust_proxy_headers_defaults_to_false() -> None:
    assert (
        AuthHttpConfig(redirect_uri="https://app.example.com/auth/callback").trust_proxy_headers
        is False
    )


# --- Config parsing ----------------------------------------------------------


def test_trust_proxy_headers_env_var_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    from api.auth.config import get_auth_http_config

    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://app.example.com/auth/callback")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    get_auth_http_config.cache_clear()
    try:
        assert get_auth_http_config().trust_proxy_headers is True
    finally:
        get_auth_http_config.cache_clear()


def test_trust_proxy_headers_env_var_defaults_false_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from api.auth.config import get_auth_http_config

    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://app.example.com/auth/callback")
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
    get_auth_http_config.cache_clear()
    try:
        assert get_auth_http_config().trust_proxy_headers is False
    finally:
        get_auth_http_config.cache_clear()
