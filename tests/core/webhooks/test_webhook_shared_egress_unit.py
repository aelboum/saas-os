"""Webhook egress after the AI-B extraction (ADR-0054 section 8b; ADR-0035).

The address predicate, embedded-IPv4 extraction and pinning moved to
`saas_os.infra.egress.addresses`. These tests pin that webhook behaviour is
unchanged and that the module-level names other tests patch are still the
ones the delivery path calls at run time (a patched seam must take effect,
or those tests would pass without testing anything).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator

import pytest

from saas_os.core.webhooks import service as webhooks_service
from saas_os.core.webhooks.errors import (
    InvalidWebhookUrlError,
    WebhookDestinationRejectedError,
)
from saas_os.infra.egress import addresses as shared


def test_webhook_names_are_the_shared_primitives() -> None:
    assert webhooks_service._is_non_public_address is shared.is_non_public_address  # pyright: ignore[reportPrivateUsage]
    assert webhooks_service._embedded_ipv4_addresses is shared.embedded_ipv4_addresses  # pyright: ignore[reportPrivateUsage]
    assert webhooks_service._format_address_for_url is shared.format_address_for_url  # pyright: ignore[reportPrivateUsage]
    assert webhooks_service._NAT64_WELL_KNOWN_PREFIX == ipaddress.IPv6Network("64:ff9b::/96")  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("url", "address", "expected"),
    [
        (
            "https://hooks.example/path?q=1",
            "93.184.216.34",
            ("https://93.184.216.34/path?q=1", "hooks.example", "hooks.example"),
        ),
        (
            "http://hooks.example:8080/x",
            "93.184.216.34",
            ("http://93.184.216.34:8080/x", "hooks.example", "hooks.example:8080"),
        ),
        (
            "https://hooks.example:8443/x",
            "2606:4700:4700::1111",
            ("https://[2606:4700:4700::1111]:8443/x", "hooks.example", "hooks.example:8443"),
        ),
        (
            "https://user:pw@hooks.example/x",  # pragma: allowlist secret
            "8.8.8.8",
            ("https://8.8.8.8/x", "hooks.example", "hooks.example"),
        ),
    ],
)
def test_pinning_output_is_unchanged(
    url: str, address: str, expected: tuple[str, str, str]
) -> None:
    pinned = webhooks_service._pin_url_to_validated_address(url, ipaddress.ip_address(address))  # pyright: ignore[reportPrivateUsage]
    assert pinned == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example/x",
        "https://hooks.example:8443/x",
        "http://hooks.example:25/x",
        "https://93.184.216.34/x",
    ],
)
def test_webhook_url_policy_is_unchanged(url: str) -> None:
    """ADR-0035: http and https, any port, on a public destination. The AI
    endpoint policy (https/443 only) is not imposed on webhooks."""
    webhooks_service._validate_url(url)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("url", ["https://127.0.0.1/x", "http://[::1]/x", "ftp://hooks.example/"])
def test_webhook_url_refusals_are_unchanged(url: str) -> None:
    with pytest.raises(InvalidWebhookUrlError):
        webhooks_service._validate_url(url)  # pyright: ignore[reportPrivateUsage]


def test_webhook_delivery_timeout_is_unchanged() -> None:
    assert webhooks_service._DELIVERY_TIMEOUT_SECONDS == 10.0  # pyright: ignore[reportPrivateUsage]


@pytest.fixture
def private_answer(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", lambda host: ["10.0.0.7"])
    yield


def test_patched_resolver_seam_is_used_at_call_time(private_answer: None) -> None:
    del private_answer
    with pytest.raises(WebhookDestinationRejectedError):
        webhooks_service._validate_destination("https://hooks.example/x")  # pyright: ignore[reportPrivateUsage]


def test_patched_predicate_seam_is_used_at_call_time(
    private_answer: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Non-vacuity: replacing the module-level predicate changes the outcome,
    so tests that patch it exercise the real call path."""
    del private_answer
    monkeypatch.setattr(webhooks_service, "_is_non_public_address", lambda address: False)
    chosen = webhooks_service._validate_destination("https://hooks.example/x")  # pyright: ignore[reportPrivateUsage]
    assert str(chosen) == "10.0.0.7"
