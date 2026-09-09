"""OIDC provider configuration tests (docs/IMPLEMENTATION-ROADMAP.md Phase
3.2 section 8). Pure unit tests -- `_discover_jwks_uri` is monkeypatched so
no real network call is ever made; `get_secrets_provider` is monkeypatched
to a fake in-memory provider so no real `.env`/environment is touched.
"""

from __future__ import annotations

from collections.abc import Iterator

import core.identity.provider as provider_module
import pytest
from core.identity.provider import (
    OIDCConfigurationError,
    OIDCProviderConfig,
    get_oidc_provider_config,
)


class _FakeSecretsProvider:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)

    def get_required(self, name: str) -> str:
        value = self.get(name)
        if not value:
            raise LookupError(name)
        return value


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    get_oidc_provider_config.cache_clear()
    yield
    get_oidc_provider_config.cache_clear()


def test_get_oidc_provider_config_resolves_issuer_client_id_and_jwks_uri(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_module,
        "get_secrets_provider",
        lambda: _FakeSecretsProvider(
            {"ZITADEL_ISSUER_URL": "https://idp.example.test", "ZITADEL_CLIENT_ID": "my-client"}
        ),
    )
    monkeypatch.setattr(
        provider_module, "_discover_jwks_uri", lambda issuer: f"{issuer}/discovered/jwks"
    )

    config = get_oidc_provider_config()

    assert config == OIDCProviderConfig(
        issuer="https://idp.example.test",
        client_id="my-client",
        audience="my-client",
        jwks_uri="https://idp.example.test/discovered/jwks",
    )


def test_trailing_slash_on_issuer_is_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provider_module,
        "get_secrets_provider",
        lambda: _FakeSecretsProvider(
            {"ZITADEL_ISSUER_URL": "https://idp.example.test/", "ZITADEL_CLIENT_ID": "my-client"}
        ),
    )
    seen_issuers: list[str] = []

    def _fake_discover(issuer: str) -> str:
        seen_issuers.append(issuer)
        return f"{issuer}/jwks"

    monkeypatch.setattr(provider_module, "_discover_jwks_uri", _fake_discover)

    config = get_oidc_provider_config()

    assert config.issuer == "https://idp.example.test"
    assert seen_issuers == ["https://idp.example.test"]


def test_missing_issuer_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provider_module,
        "get_secrets_provider",
        lambda: _FakeSecretsProvider({"ZITADEL_CLIENT_ID": "my-client"}),
    )

    with pytest.raises(LookupError):
        get_oidc_provider_config()


def test_missing_client_id_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provider_module,
        "get_secrets_provider",
        lambda: _FakeSecretsProvider({"ZITADEL_ISSUER_URL": "https://idp.example.test"}),
    )

    with pytest.raises(LookupError):
        get_oidc_provider_config()


def test_config_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def _fake_discover(issuer: str) -> str:
        calls["n"] += 1
        return f"{issuer}/jwks"

    monkeypatch.setattr(
        provider_module,
        "get_secrets_provider",
        lambda: _FakeSecretsProvider(
            {"ZITADEL_ISSUER_URL": "https://idp.example.test", "ZITADEL_CLIENT_ID": "my-client"}
        ),
    )
    monkeypatch.setattr(provider_module, "_discover_jwks_uri", _fake_discover)

    get_oidc_provider_config()
    get_oidc_provider_config()

    assert calls["n"] == 1


# --- _discover_jwks_uri itself (still no real network) --------------------


class _FakeHTTPResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def test_discover_jwks_uri_rejects_non_http_scheme() -> None:
    with pytest.raises(OIDCConfigurationError):
        provider_module._discover_jwks_uri("file:///etc/passwd")


def test_discover_jwks_uri_parses_the_discovery_document(monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    def _fake_urlopen(url: str, timeout: int) -> _FakeHTTPResponse:
        assert url == "https://idp.example.test/.well-known/openid-configuration"
        return _FakeHTTPResponse(json.dumps({"jwks_uri": "https://idp.example.test/keys"}).encode())

    monkeypatch.setattr(provider_module.urllib.request, "urlopen", _fake_urlopen)

    jwks_uri = provider_module._discover_jwks_uri("https://idp.example.test")
    assert jwks_uri == "https://idp.example.test/keys"


def test_discover_jwks_uri_raises_when_document_has_no_jwks_uri(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    monkeypatch.setattr(
        provider_module.urllib.request,
        "urlopen",
        lambda url, timeout: _FakeHTTPResponse(
            json.dumps({"issuer": "https://idp.example.test"}).encode()
        ),
    )

    with pytest.raises(OIDCConfigurationError):
        provider_module._discover_jwks_uri("https://idp.example.test")


def test_discover_jwks_uri_raises_on_unreachable_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from urllib.error import URLError

    def _raise(url: str, timeout: int) -> None:
        raise URLError("connection refused")

    monkeypatch.setattr(provider_module.urllib.request, "urlopen", _raise)

    with pytest.raises(OIDCConfigurationError):
        provider_module._discover_jwks_uri("https://idp.example.test")


def test_discover_jwks_uri_raises_on_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provider_module.urllib.request,
        "urlopen",
        lambda url, timeout: _FakeHTTPResponse(b"not json"),
    )

    with pytest.raises(OIDCConfigurationError):
        provider_module._discover_jwks_uri("https://idp.example.test")
