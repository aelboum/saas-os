"""`WEBHOOK_ALLOW_HTTP` (owner decision of 2026-10-27, ADR-0035 amendment):
plain `http://` destinations are retired over two releases.

Release 1 (this code): unset still allows `http://`, with a warning that
names no URL; `false` refuses it at subscription and at delivery; `true`
allows it silently. Release 2 flips `HTTP_ALLOWED_WHEN_UNSET`; the tests
marked "release 2" show what that flip alone does.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Iterator

import pytest

from saas_os.core.outbox import PermanentEventError
from saas_os.core.webhooks import config as webhook_config
from saas_os.core.webhooks import service as webhooks_service
from saas_os.core.webhooks.config import WebhookSecurityConfig, get_webhook_security_config
from saas_os.core.webhooks.errors import (
    InvalidWebhookUrlError,
    WebhookConfigurationError,
    WebhookDestinationRejectedError,
)

HTTP_URL = "http://hooks.example/services/T/B/PATH-TOKEN?token=QUERY-TOKEN"
HTTPS_URL = "https://hooks.example/services/T/B/PATH-TOKEN?token=QUERY-TOKEN"
TENANT = uuid.UUID("00000000-0000-0000-0000-00000000000a")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("WEBHOOK_ALLOW_HTTP", raising=False)
    monkeypatch.delenv("WEBHOOK_ALLOWED_PORTS", raising=False)
    get_webhook_security_config.cache_clear()
    webhooks_service._warned_http_subscriptions.clear()  # pyright: ignore[reportPrivateUsage]
    yield
    get_webhook_security_config.cache_clear()
    webhooks_service._warned_http_subscriptions.clear()  # pyright: ignore[reportPrivateUsage]


def _set(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("WEBHOOK_ALLOW_HTTP", value)
    get_webhook_security_config.cache_clear()


def _require(url: str, **ids: uuid.UUID) -> None:
    webhooks_service._require_http_allowed(  # pyright: ignore[reportPrivateUsage]
        url, InvalidWebhookUrlError, phase="subscribe", **ids
    )


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.getMessage() == "webhook_http_destination_deprecated"]


# --- configuration ----------------------------------------------------------------


def test_unset_means_release_one_behaviour() -> None:
    config = get_webhook_security_config()
    assert config.allow_http is None
    assert webhook_config.HTTP_ALLOWED_WHEN_UNSET is True
    assert config.http_allowed is True


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("1", True),
        (" Yes ", True),
        ("on", True),
        ("false", False),
        ("0", False),
        ("NO", False),
        ("off", False),
    ],
)
def test_the_setting_is_a_boolean_like_the_others(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
) -> None:
    _set(monkeypatch, raw)
    config = get_webhook_security_config()
    assert config.allow_http is expected
    assert config.http_allowed is expected


@pytest.mark.parametrize("raw", ["", "maybe", "2", "enabled"])
def test_any_other_value_is_a_configuration_error(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    _set(monkeypatch, raw)
    with pytest.raises(WebhookConfigurationError, match="WEBHOOK_ALLOW_HTTP"):
        get_webhook_security_config()


# --- release 1: warn, never leak the URL --------------------------------------------


def test_https_is_never_affected(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for value in (None, "false", "true"):
        if value is not None:
            _set(monkeypatch, value)
        with caplog.at_level(logging.WARNING):
            _require(HTTPS_URL, tenant_id=TENANT)
    assert _warnings(caplog) == []


def test_unset_allows_http_with_a_warning_that_names_no_url(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        _require(HTTP_URL, tenant_id=TENANT)
    [record] = _warnings(caplog)
    assert record.phase == "subscribe"  # type: ignore[attr-defined]
    assert record.tenant_id == str(TENANT)  # type: ignore[attr-defined]
    assert record.setting == "WEBHOOK_ALLOW_HTTP"  # type: ignore[attr-defined]
    rendered = record.getMessage() + repr(record.__dict__)
    for secret in ("PATH-TOKEN", "QUERY-TOKEN", "hooks.example", "http://"):
        assert secret not in rendered


def test_a_delivery_warns_once_per_subscription(caplog: pytest.LogCaptureFixture) -> None:
    subscription = uuid.uuid4()
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            webhooks_service._require_http_allowed(  # pyright: ignore[reportPrivateUsage]
                HTTP_URL,
                WebhookDestinationRejectedError,
                phase="delivery",
                subscription_id=subscription,
            )
    [record] = _warnings(caplog)
    assert record.subscription_id == str(subscription)  # type: ignore[attr-defined]


def test_an_explicit_opt_in_allows_http_without_a_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _set(monkeypatch, "true")
    with caplog.at_level(logging.WARNING):
        _require(HTTP_URL, tenant_id=TENANT)
    assert _warnings(caplog) == []


def test_false_refuses_http_at_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    _set(monkeypatch, "false")
    with pytest.raises(InvalidWebhookUrlError):
        _require(HTTP_URL, tenant_id=TENANT)


def test_false_refuses_an_existing_http_subscription_before_any_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subscription created while HTTP was allowed is refused at its next
    delivery: permanent, nothing resolved, no message naming the URL."""
    _set(monkeypatch, "false")

    def resolve(*args: object, **kwargs: object) -> list[object]:
        raise AssertionError("resolution must not be reached")

    monkeypatch.setattr(webhooks_service, "_validate_destination_addresses", resolve)
    with pytest.raises(WebhookDestinationRejectedError) as excinfo:
        asyncio.run(
            webhooks_service._send_signed(  # pyright: ignore[reportPrivateUsage]
                uuid.uuid4(), HTTP_URL, "secret", b"{}"
            )
        )
    assert isinstance(excinfo.value, PermanentEventError)
    for secret in ("PATH-TOKEN", "QUERY-TOKEN", "hooks.example"):
        assert secret not in str(excinfo.value)


def test_unset_still_delivers_an_existing_http_subscription(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Release 1: an existing `http://` subscription keeps being delivered
    (here: it reaches resolution) and warns."""

    class _Reached(Exception):
        pass

    def resolve(*args: object, **kwargs: object) -> list[object]:
        raise _Reached

    monkeypatch.setattr(webhooks_service, "_validate_destination_addresses", resolve)
    with caplog.at_level(logging.WARNING), pytest.raises(_Reached):
        asyncio.run(
            webhooks_service._send_signed(  # pyright: ignore[reportPrivateUsage]
                uuid.uuid4(), HTTP_URL, "secret", b"{}"
            )
        )
    assert [r.phase for r in _warnings(caplog)] == ["delivery"]  # type: ignore[attr-defined]


def test_the_port_list_cannot_opt_in_to_http(monkeypatch: pytest.MonkeyPatch) -> None:
    """`WEBHOOK_ALLOWED_PORTS` naming 80 does not override `false`."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_PORTS", "80,443")
    _set(monkeypatch, "false")
    with pytest.raises(InvalidWebhookUrlError):
        _require(HTTP_URL, tenant_id=TENANT)


# --- release 2 ----------------------------------------------------------------------


def test_release_two_refuses_http_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webhook_config, "HTTP_ALLOWED_WHEN_UNSET", False)
    assert WebhookSecurityConfig().http_allowed is False
    with pytest.raises(InvalidWebhookUrlError):
        _require(HTTP_URL, tenant_id=TENANT)


def test_release_two_still_honours_an_explicit_opt_in(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(webhook_config, "HTTP_ALLOWED_WHEN_UNSET", False)
    _set(monkeypatch, "true")
    with caplog.at_level(logging.WARNING):
        _require(HTTP_URL, tenant_id=TENANT)
    assert _warnings(caplog) == []
