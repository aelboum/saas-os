"""`WEBHOOK_ALLOWED_PORTS` (ADR-0035 amendment of 2026-10-19).

Unset, any port is allowed, as ADR-0035 has always said. Set, a webhook URL
must use one of the listed ports -- explicit, or 443 for `https` and 80 for
`http` -- when it is subscribed and again before every delivery. A value
that is not a list of ports is a configuration error, never "allow
everything".
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import httpx
import pytest

from saas_os.core.webhooks import service as webhooks_service
from saas_os.core.webhooks.config import WebhookSecurityConfig, get_webhook_security_config
from saas_os.core.webhooks.errors import (
    InvalidWebhookUrlError,
    WebhookConfigurationError,
    WebhookDestinationRejectedError,
)

_VARIABLE = "WEBHOOK_ALLOWED_PORTS"


@pytest.fixture(autouse=True)
def _fresh_config(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(_VARIABLE, raising=False)
    get_webhook_security_config.cache_clear()
    yield
    get_webhook_security_config.cache_clear()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _allow(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(_VARIABLE, value)
    get_webhook_security_config.cache_clear()


def test_unset_allows_any_port() -> None:
    assert get_webhook_security_config().allowed_ports is None
    assert WebhookSecurityConfig().allowed_ports is None
    for url in ("https://hooks.example/x", "http://hooks.example:8080/x", "https://h.example:1/x"):
        webhooks_service._validate_url(url)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("port", ["8443", "65535"])
def test_unset_allows_any_valid_port(port: str) -> None:
    url = f"https://hooks.example:{port}/x"
    webhooks_service._validate_url(url)  # pyright: ignore[reportPrivateUsage]
    webhooks_service._require_allowed_port(  # pyright: ignore[reportPrivateUsage]
        url, WebhookDestinationRejectedError
    )


@pytest.mark.parametrize("port", ["65536", "99999", "abc"])
def test_unset_still_refuses_a_port_that_is_not_a_port(port: str) -> None:
    """Out of range or not a number: no port the list could allow, so it is
    refused with the list unset too."""
    with pytest.raises(InvalidWebhookUrlError):
        webhooks_service._validate_url(  # pyright: ignore[reportPrivateUsage]
            f"https://hooks.example:{port}/x"
        )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("443", {443}), ("443,80", {443, 80}), (" 443 , 8443 ", {443, 8443}), ("1,65535", {1, 65535})],
)
def test_a_list_of_ports_is_read(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: set[int]
) -> None:
    _allow(monkeypatch, raw)
    assert get_webhook_security_config().allowed_ports == frozenset(expected)


@pytest.mark.parametrize(
    "raw", ["", " ", "443,", "443,,80", "https", "443;80", "-1", "0", "65536", "４４３"]
)
def test_anything_else_is_a_configuration_error(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    _allow(monkeypatch, raw)
    with pytest.raises(WebhookConfigurationError):
        get_webhook_security_config()


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://hooks.example/x", True),
        ("https://hooks.example:443/x", True),
        ("https://hooks.example:8443/x", False),
        ("http://hooks.example/x", False),
        ("http://hooks.example:443/x", True),
        ("https://hooks.example:99999/x", False),
    ],
)
def test_subscription_urls_are_checked_against_the_list(
    monkeypatch: pytest.MonkeyPatch, url: str, allowed: bool
) -> None:
    _allow(monkeypatch, "443")
    if allowed:
        webhooks_service._validate_url(url)  # pyright: ignore[reportPrivateUsage]
    else:
        with pytest.raises(InvalidWebhookUrlError):
            webhooks_service._validate_url(url)  # pyright: ignore[reportPrivateUsage]


def test_http_default_port_is_80(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow(monkeypatch, "80")
    webhooks_service._validate_url("http://hooks.example/x")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(InvalidWebhookUrlError):
        webhooks_service._validate_url("https://hooks.example/x")  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_a_delivery_to_a_port_no_longer_allowed_is_refused_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subscription created while any port was allowed is refused at its
    next delivery, permanently, without resolving or connecting."""
    resolved: list[str] = []
    connected: list[object] = []

    def resolve(host: str) -> list[str]:
        resolved.append(host)
        return ["93.184.216.34"]

    def client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        connected.append(kwargs)
        raise AssertionError("no connection may be made")

    monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", resolve)
    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", client)
    _allow(monkeypatch, "443")
    with pytest.raises(WebhookDestinationRejectedError):
        await webhooks_service._send_signed(  # pyright: ignore[reportPrivateUsage]
            uuid.UUID(int=1), "https://hooks.example:8443/x", "s3cret", b"{}"
        )
    assert resolved == [] and connected == []


@pytest.mark.anyio
async def test_a_delivery_to_an_allowed_port_proceeds(monkeypatch: pytest.MonkeyPatch) -> None:
    real = httpx.AsyncClient

    def client(*, timeout: float, follow_redirects: bool, trust_env: bool) -> httpx.AsyncClient:
        return real(transport=httpx.MockTransport(lambda request: httpx.Response(200)))

    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", client)
    monkeypatch.setattr(
        webhooks_service, "_default_resolve_hostname", lambda host: ["93.184.216.34"]
    )
    _allow(monkeypatch, "443,8443")
    status = await webhooks_service._send_signed(  # pyright: ignore[reportPrivateUsage]
        uuid.UUID(int=1), "https://hooks.example:8443/x", "s3cret", b"{}"
    )
    assert status == 200


@pytest.mark.anyio
@pytest.mark.parametrize("port", ["65536", "abc"])
async def test_a_delivery_to_a_malformed_port_is_refused_before_resolution_with_no_list(
    monkeypatch: pytest.MonkeyPatch, port: str
) -> None:
    """A subscription stored before malformed ports were refused is refused at
    its next delivery, permanently, without resolving or connecting -- even
    though its hostname would resolve to a public address -- and the error
    names no part of the URL."""
    resolved: list[str] = []
    connected: list[object] = []

    def resolve(host: str) -> list[str]:
        resolved.append(host)
        return ["93.184.216.34"]

    def client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        connected.append(kwargs)
        raise AssertionError("no connection may be made")

    monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", resolve)
    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", client)
    password = "pw-canary"  # pragma: allowlist secret -- a fake credential
    url = f"https://hook-user:{password}@hooks.example:{port}/in/tk-canary?token=tk-canary"
    with pytest.raises(WebhookDestinationRejectedError) as excinfo:
        await webhooks_service._send_signed(  # pyright: ignore[reportPrivateUsage]
            uuid.UUID(int=1), url, "s3cret", b"{}"
        )
    assert resolved == [] and connected == []
    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None
    for part in ("hook-user", "pw-canary", "hooks.example", "tk-canary", port):
        assert part not in str(excinfo.value)
