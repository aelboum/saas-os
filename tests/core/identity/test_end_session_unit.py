"""ADR-0064 -- OpenID Connect RP-initiated logout, the provider side: the
optional `end_session_endpoint` in discovery and the pure construction of
the end-session URL. No network, no database."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest

import saas_os.core.identity.provider as provider_module
from saas_os.core.identity.oidc import OIDCIdentityProvider, build_end_session_url
from saas_os.core.identity.provider import (
    IdentityProvider,
    OIDCConfigurationError,
    OIDCFlowEndpoints,
    OIDCProviderConfig,
)

_ISSUER = "https://idp.example.test"
_CONFIG = OIDCProviderConfig(
    issuer=_ISSUER, client_id="client-1", audience="client-1", jwks_uri=f"{_ISSUER}/keys"
)
_END_SESSION = f"{_ISSUER}/oidc/v1/end_session"
_ENDPOINTS = OIDCFlowEndpoints(
    authorization_endpoint=f"{_ISSUER}/oauth/v2/authorize",
    token_endpoint=f"{_ISSUER}/oauth/v2/token",
    end_session_endpoint=_END_SESSION,
)
_POST_LOGOUT = "https://app.example.test/signed-out"


class _FakeHTTPResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _patch_discovery(monkeypatch: pytest.MonkeyPatch, document: dict[str, object]) -> None:
    monkeypatch.setattr(
        provider_module,
        "open_provider_url",
        lambda url, timeout: _FakeHTTPResponse(json.dumps(document).encode()),
    )


def _document(issuer: str = _ISSUER, **extra: object) -> dict[str, object]:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/v2/authorize",
        "token_endpoint": f"{issuer}/oauth/v2/token",
        "jwks_uri": f"{issuer}/keys",
        **extra,
    }


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query, keep_blank_values=True)


# --- Discovery -----------------------------------------------------------------


def test_end_session_endpoint_is_read_from_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_discovery(monkeypatch, _document(end_session_endpoint=_END_SESSION))
    assert provider_module._discover_flow_endpoints(_ISSUER) == _ENDPOINTS


@pytest.mark.parametrize("explicit_null", [True, False])
def test_a_provider_without_end_session_endpoint_is_still_usable(
    monkeypatch: pytest.MonkeyPatch, explicit_null: bool
) -> None:
    document = _document()
    if explicit_null:
        document["end_session_endpoint"] = None
    _patch_discovery(monkeypatch, document)
    endpoints = provider_module._discover_flow_endpoints(_ISSUER)
    assert endpoints.end_session_endpoint is None
    assert endpoints.token_endpoint == f"{_ISSUER}/oauth/v2/token"


@pytest.mark.parametrize(
    "value",
    [
        "http://idp.example.test/oidc/v1/end_session",  # plain HTTP for an HTTPS issuer
        "javascript:alert(1)",
        "/oidc/v1/end_session",  # relative
        "",
        42,
        ["https://idp.example.test/end"],
    ],
)
def test_an_unusable_end_session_endpoint_fails_closed(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    _patch_discovery(monkeypatch, _document(end_session_endpoint=value))
    with pytest.raises(OIDCConfigurationError, match="end_session_endpoint"):
        provider_module._discover_flow_endpoints(_ISSUER)


def test_http_end_session_endpoint_is_allowed_only_for_an_http_development_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = "http://localhost:8080"
    _patch_discovery(
        monkeypatch, _document(issuer, end_session_endpoint=f"{issuer}/oidc/v1/end_session")
    )
    endpoints = provider_module._discover_flow_endpoints(issuer)
    assert endpoints.end_session_endpoint == f"{issuer}/oidc/v1/end_session"


def test_discovery_for_another_issuer_is_refused_before_any_endpoint_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_discovery(
        monkeypatch,
        _document("https://evil.example.test", end_session_endpoint="https://evil.example.test/x"),
    )
    with pytest.raises(OIDCConfigurationError, match="does not name the configured issuer"):
        provider_module._discover_flow_endpoints(_ISSUER)


# --- The end-session URL ----------------------------------------------------------


def test_url_carries_client_id_post_logout_uri_and_hint() -> None:
    url = build_end_session_url(
        _CONFIG, _ENDPOINTS, post_logout_redirect_uri=_POST_LOGOUT, id_token_hint="a.b.c"
    )
    assert url is not None
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == _END_SESSION
    assert _query(url) == {
        "client_id": ["client-1"],
        "post_logout_redirect_uri": [_POST_LOGOUT],
        "id_token_hint": ["a.b.c"],
    }


@pytest.mark.parametrize("hint", [None, ""])
def test_without_a_hint_the_url_still_identifies_the_client(hint: str | None) -> None:
    url = build_end_session_url(
        _CONFIG, _ENDPOINTS, post_logout_redirect_uri=_POST_LOGOUT, id_token_hint=hint
    )
    assert url is not None
    assert _query(url) == {"client_id": ["client-1"], "post_logout_redirect_uri": [_POST_LOGOUT]}


def test_no_end_session_endpoint_means_no_url() -> None:
    endpoints = OIDCFlowEndpoints(
        authorization_endpoint=_ENDPOINTS.authorization_endpoint,
        token_endpoint=_ENDPOINTS.token_endpoint,
    )
    assert endpoints.end_session_endpoint is None
    assert (
        build_end_session_url(
            _CONFIG, endpoints, post_logout_redirect_uri=_POST_LOGOUT, id_token_hint="a.b.c"
        )
        is None
    )


def test_an_endpoint_with_its_own_query_keeps_it() -> None:
    endpoints = OIDCFlowEndpoints(
        authorization_endpoint=_ENDPOINTS.authorization_endpoint,
        token_endpoint=_ENDPOINTS.token_endpoint,
        end_session_endpoint=f"{_ISSUER}/logout?p=tenant-a",
    )
    url = build_end_session_url(
        _CONFIG, endpoints, post_logout_redirect_uri=_POST_LOGOUT, id_token_hint=None
    )
    assert url is not None and url.count("?") == 1
    assert _query(url)["p"] == ["tenant-a"]
    assert _query(url)["client_id"] == ["client-1"]


def test_parameter_values_are_encoded_not_spliced() -> None:
    url = build_end_session_url(
        _CONFIG,
        _ENDPOINTS,
        post_logout_redirect_uri="https://app.example.test/out?x=1&y=2",
        id_token_hint="h&client_id=evil",
    )
    assert url is not None
    query = _query(url)
    assert query["client_id"] == ["client-1"]
    assert query["post_logout_redirect_uri"] == ["https://app.example.test/out?x=1&y=2"]
    assert query["id_token_hint"] == ["h&client_id=evil"]
    assert "state" not in query


def test_the_adapter_delegates_and_satisfies_the_protocol() -> None:
    adapter = OIDCIdentityProvider(_CONFIG, _ENDPOINTS)
    assert isinstance(adapter, IdentityProvider)
    assert adapter.build_end_session_url(
        post_logout_redirect_uri=_POST_LOGOUT, id_token_hint="a.b.c"
    ) == build_end_session_url(
        _CONFIG, _ENDPOINTS, post_logout_redirect_uri=_POST_LOGOUT, id_token_hint="a.b.c"
    )
