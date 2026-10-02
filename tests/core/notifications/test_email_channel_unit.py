"""P1.12 -- pure unit tests for `core/notifications/service.py`'s `"email"`
channel: validation before any outbox event is recorded, event payload shape
(the address only ever as an encrypted envelope -- RE-1), and
`_send_email_channel()`'s own success/failure handling. No database or
Redis needed -- mirrors `test_notifications_unit.py`'s own
monkeypatch-`append_event` pattern exactly.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import pytest
from core.email.errors import EmailConfigurationError, EmailProviderError
from core.notifications.errors import NotificationDispatchError

from core.notifications import service as notifications_service

_SESSION: Any = object()


@pytest.fixture(autouse=True)
def _tenant_lifecycle_fence_open(monkeypatch) -> None:
    """PRIV-03 P2: `dispatch_notification()` is lifecycle-fenced by
    `core.tenancy.lock_open_tenant()` -- a database read. Pure unit
    tests, random tenant id, no database: the fence is stubbed open here,
    exactly like `append_event` is stubbed below (see
    tests/core/tenancy/test_lifecycle_fencing_integration.py for the fence)."""
    monkeypatch.setattr(notifications_service, "lock_open_tenant", lambda session, tenant_id: None)


def _capture_append(monkeypatch) -> dict[str, object]:
    captured: dict[str, object] = {}

    def _fake_append_event(session, **kwargs):
        captured.update(kwargs)
        return uuid.UUID(int=456)

    monkeypatch.setattr(notifications_service, "append_event", _fake_append_event)
    return captured


# --- dispatch_notification(): validation before recording --------------------


def test_dispatch_notification_requires_recipient_email_for_email_channel(monkeypatch) -> None:
    captured = _capture_append(monkeypatch)

    with pytest.raises(ValueError, match="recipient_email is required"):
        notifications_service.dispatch_notification(
            _SESSION, uuid.uuid4(), uuid.uuid4(), "email", "body"
        )
    assert captured == {}


def test_dispatch_notification_rejects_malformed_recipient_email_without_recording(
    monkeypatch,
) -> None:
    captured = _capture_append(monkeypatch)

    with pytest.raises(ValueError):
        notifications_service.dispatch_notification(
            _SESSION,
            uuid.uuid4(),
            uuid.uuid4(),
            "email",
            "body",
            recipient_email="not-an-email",
        )
    assert captured == {}


def test_dispatch_notification_rejects_injection_recipient_email_without_recording(
    monkeypatch,
) -> None:
    captured = _capture_append(monkeypatch)

    with pytest.raises(ValueError):
        notifications_service.dispatch_notification(
            _SESSION,
            uuid.uuid4(),
            uuid.uuid4(),
            "email",
            "body",
            recipient_email="user@example.com\r\nBcc: attacker@evil.example",
        )
    assert captured == {}


def test_dispatch_notification_ignores_recipient_email_for_in_app_channel(monkeypatch) -> None:
    """A stray `recipient_email` on a non-email channel must not be
    validated or rejected -- `_validate_recipient_email()` is a no-op
    unless `channel == "email"`."""
    captured = _capture_append(monkeypatch)

    event_id = notifications_service.dispatch_notification(
        _SESSION,
        uuid.uuid4(),
        uuid.uuid4(),
        "in_app",
        "body",
        recipient_email="not-an-email-but-irrelevant",
    )
    assert event_id == uuid.UUID(int=456)
    assert "recipient_email" not in captured["payload"]  # type: ignore[operator]


# --- dispatch_notification(): payload shape ---------------------------------


def test_dispatch_notification_email_payload_holds_only_an_encrypted_recipient_email(
    monkeypatch,
) -> None:
    captured = _capture_append(monkeypatch)

    tenant_id = uuid.uuid4()
    recipient_id = uuid.uuid4()
    event_id = notifications_service.dispatch_notification(
        _SESSION,
        tenant_id,
        recipient_id,
        "email",
        "hello",
        subject="hi",
        recipient_email="user@example.com",
    )

    assert event_id == uuid.UUID(int=456)
    payload = captured["payload"]
    assert isinstance(payload, dict)
    envelope = payload.pop("recipient_email")
    assert payload == {
        "recipient_user_id": str(recipient_id),
        "channel": "email",
        "subject": "hi",
        "body": "hello",
    }
    assert isinstance(envelope, str)
    assert envelope.startswith("efv1:")
    assert "user@example.com" not in envelope
    assert notifications_service._decrypt_recipient_email(tenant_id, envelope) == (
        "user@example.com"
    )


def test_decrypt_recipient_email_passes_a_pre_outbox_plaintext_address_through() -> None:
    """A job queued before RE-1 carries the plaintext address."""
    assert (
        notifications_service._decrypt_recipient_email(uuid.uuid4(), "user@example.com")
        == "user@example.com"
    )


def test_dispatch_notification_in_app_payload_has_no_recipient_email_key(monkeypatch) -> None:
    """Regression guard: the pre-existing `"in_app"` payload shape must
    stay exactly 4 keys -- adding the `"email"` channel must never leak a
    `recipient_email` key onto an unrelated channel's payload."""
    captured = _capture_append(monkeypatch)

    notifications_service.dispatch_notification(
        _SESSION, uuid.uuid4(), uuid.uuid4(), "in_app", "hello", subject="hi"
    )

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert "recipient_email" not in payload
    assert set(payload) == {"recipient_user_id", "channel", "subject", "body"}


# --- _send_email_channel(): success/failure -------------------------------


class _StubEmailConfig:
    def __init__(self, default_sender: str | None) -> None:
        self.default_sender = default_sender


def test_send_email_channel_raises_when_default_sender_is_not_configured(monkeypatch) -> None:
    monkeypatch.setattr("core.email.get_email_config", lambda: _StubEmailConfig(None))

    with pytest.raises(NotificationDispatchError):
        notifications_service._send_email_channel(
            uuid.uuid4(), "subject", "body", "user@example.com"
        )


def test_send_email_channel_sends_through_core_email_send_email(monkeypatch) -> None:
    from core.email.provider import EmailMessage

    sent_messages: list[EmailMessage] = []

    def _fake_send_email(message, *, provider=None):
        sent_messages.append(message)
        from core.email.provider import EmailSendResult

        return EmailSendResult(accepted=True, provider_message_id="fake-1")

    monkeypatch.setattr(
        "core.email.get_email_config", lambda: _StubEmailConfig("no-reply@example.com")
    )
    monkeypatch.setattr("core.email.send_email", _fake_send_email)

    notifications_service._send_email_channel(uuid.uuid4(), "hi", "hello", "user@example.com")

    assert len(sent_messages) == 1
    message = sent_messages[0]
    assert message.sender == "no-reply@example.com"
    assert message.to == ("user@example.com",)
    assert message.subject == "hi"
    assert message.text_body == "hello"


def test_send_email_channel_normalizes_provider_failure(monkeypatch) -> None:
    def _failing_send_email(message, *, provider=None):
        raise EmailProviderError("send", "boom")

    monkeypatch.setattr(
        "core.email.get_email_config", lambda: _StubEmailConfig("no-reply@example.com")
    )
    monkeypatch.setattr("core.email.send_email", _failing_send_email)

    with pytest.raises(NotificationDispatchError):
        notifications_service._send_email_channel(uuid.uuid4(), "hi", "hello", "user@example.com")


def test_send_email_channel_does_not_log_recipient_or_body(monkeypatch, caplog) -> None:
    def _fake_send_email(message, *, provider=None):
        from core.email.provider import EmailSendResult

        return EmailSendResult(accepted=True, provider_message_id="fake-1")

    monkeypatch.setattr(
        "core.email.get_email_config", lambda: _StubEmailConfig("no-reply@example.com")
    )
    monkeypatch.setattr("core.email.send_email", _fake_send_email)

    secret_recipient = "very-secret-recipient@example.com"
    secret_body = "very secret body content"
    with caplog.at_level(logging.INFO, logger="core.notifications.service"):
        notifications_service._send_email_channel(uuid.uuid4(), "hi", secret_body, secret_recipient)

    for record in caplog.records:
        assert secret_recipient not in record.getMessage()
        assert secret_body not in record.getMessage()


def test_send_email_channel_failure_log_never_contains_configuration_detail(
    monkeypatch, caplog
) -> None:
    def _failing_send_email(message, *, provider=None):
        raise EmailProviderError("send", "some internal detail")

    monkeypatch.setattr(
        "core.email.get_email_config", lambda: _StubEmailConfig("no-reply@example.com")
    )
    monkeypatch.setattr("core.email.send_email", _failing_send_email)

    with caplog.at_level(logging.WARNING, logger="core.notifications.service"):
        with pytest.raises(NotificationDispatchError):
            notifications_service._send_email_channel(
                uuid.uuid4(), "hi", "hello", "user@example.com"
            )

    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warning_records) == 1
    assert "some internal detail" not in warning_records[0].getMessage()


# --- EmailConfigurationError from a missing SMTP_HOST is also normalized ---


def test_send_email_channel_normalizes_email_configuration_error(monkeypatch) -> None:
    def _raising_get_email_config():
        raise EmailConfigurationError("SMTP_HOST is not set.")

    monkeypatch.setattr("core.email.get_email_config", _raising_get_email_config)

    with pytest.raises(NotificationDispatchError):
        notifications_service._send_email_channel(uuid.uuid4(), "hi", "hello", "user@example.com")
