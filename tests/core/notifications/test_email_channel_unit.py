"""P1.12 -- pure unit tests for `core/notifications/service.py`'s `"email"`
channel: validation before any job is enqueued, payload shape, and
`_send_email_channel()`'s own success/failure handling. No database or
Redis needed -- mirrors `test_notifications_unit.py`'s own
monkeypatch-`enqueue_job` pattern exactly.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from core.email.errors import EmailConfigurationError, EmailProviderError
from core.notifications.errors import NotificationDispatchError

from core.notifications import service as notifications_service
from infra.jobs import TenantJobPayload

pytestmark = pytest.mark.anyio


# --- dispatch_notification(): validation before enqueue --------------------


async def test_dispatch_notification_requires_recipient_email_for_email_channel(
    monkeypatch,
) -> None:
    called = False

    async def _fake_enqueue_job(*args, **kwargs):
        nonlocal called
        called = True
        return "should-not-be-reached"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    with pytest.raises(ValueError, match="recipient_email is required"):
        await notifications_service.dispatch_notification(
            uuid.uuid4(), uuid.uuid4(), "email", "body"
        )
    assert called is False


async def test_dispatch_notification_rejects_malformed_recipient_email_without_enqueueing(
    monkeypatch,
) -> None:
    called = False

    async def _fake_enqueue_job(*args, **kwargs):
        nonlocal called
        called = True
        return "should-not-be-reached"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    with pytest.raises(ValueError):
        await notifications_service.dispatch_notification(
            uuid.uuid4(),
            uuid.uuid4(),
            "email",
            "body",
            recipient_email="not-an-email",
        )
    assert called is False


async def test_dispatch_notification_rejects_injection_recipient_email_without_enqueueing(
    monkeypatch,
) -> None:
    called = False

    async def _fake_enqueue_job(*args, **kwargs):
        nonlocal called
        called = True
        return "should-not-be-reached"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    with pytest.raises(ValueError):
        await notifications_service.dispatch_notification(
            uuid.uuid4(),
            uuid.uuid4(),
            "email",
            "body",
            recipient_email="user@example.com\r\nBcc: attacker@evil.example",
        )
    assert called is False


async def test_dispatch_notification_ignores_recipient_email_for_in_app_channel(
    monkeypatch,
) -> None:
    """A stray `recipient_email` on a non-email channel must not be
    validated or rejected -- `_validate_recipient_email()` is a no-op
    unless `channel == "email"`."""
    called = False

    async def _fake_enqueue_job(*args, **kwargs):
        nonlocal called
        called = True
        return "job-123"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    job_id = await notifications_service.dispatch_notification(
        uuid.uuid4(),
        uuid.uuid4(),
        "in_app",
        "body",
        recipient_email="not-an-email-but-irrelevant",
    )
    assert job_id == "job-123"
    assert called is True


# --- dispatch_notification(): payload shape ---------------------------------


async def test_dispatch_notification_email_payload_includes_recipient_email(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def _fake_enqueue_job(function_name, payload, *, queue_name=None):
        captured["function_name"] = function_name
        captured["payload"] = payload
        return "job-456"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    tenant_id = uuid.uuid4()
    recipient_id = uuid.uuid4()
    job_id = await notifications_service.dispatch_notification(
        tenant_id,
        recipient_id,
        "email",
        "hello",
        subject="hi",
        recipient_email="user@example.com",
    )

    assert job_id == "job-456"
    payload = captured["payload"]
    assert isinstance(payload, TenantJobPayload)
    assert payload.data == {
        "recipient_user_id": str(recipient_id),
        "channel": "email",
        "subject": "hi",
        "body": "hello",
        "recipient_email": "user@example.com",
    }


async def test_dispatch_notification_in_app_payload_has_no_recipient_email_key(
    monkeypatch,
) -> None:
    """Regression guard: the pre-existing `"in_app"` payload shape must
    stay exactly 4 keys -- adding the `"email"` channel must never leak a
    `recipient_email` key onto an unrelated channel's payload."""
    captured: dict[str, object] = {}

    async def _fake_enqueue_job(function_name, payload, *, queue_name=None):
        captured["payload"] = payload
        return "job-789"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    await notifications_service.dispatch_notification(
        uuid.uuid4(), uuid.uuid4(), "in_app", "hello", subject="hi"
    )

    payload = captured["payload"]
    assert isinstance(payload, TenantJobPayload)
    assert "recipient_email" not in payload.data
    assert set(payload.data) == {"recipient_user_id", "channel", "subject", "body"}


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
