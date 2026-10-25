"""P1.12 -- pure unit tests for `saas_os/core/notifications/service.py`'s `"email"`
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

from saas_os.core.email.errors import EmailConfigurationError, EmailProviderError
from saas_os.core.notifications import service as notifications_service
from saas_os.core.notifications.errors import (
    NotificationDispatchError,
    NotificationPermanentDispatchError,
)
from saas_os.core.outbox.errors import PermanentEventError

_SESSION: Any = object()


@pytest.fixture(autouse=True)
def _tenant_lifecycle_fence_open(monkeypatch) -> None:
    """PRIV-03 P2: `dispatch_notification()` is lifecycle-fenced by
    `saas_os.core.tenancy.lock_open_tenant()` -- a database read. Pure unit
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
#
# ADR-0057: the sender is `EMAIL_DEFAULT_SENDER`, read on its own -- never
# through the SMTP configuration -- so these tests set the environment
# variable rather than stubbing `get_email_config`.


@pytest.fixture
def _sender(monkeypatch) -> str:
    monkeypatch.delenv("EMAIL_PROVIDER", raising=False)
    monkeypatch.setenv("EMAIL_DEFAULT_SENDER", "no-reply@example.com")
    return "no-reply@example.com"


def _recording_send_email(sent: list):
    def _fake_send_email(message, *, provider=None):
        sent.append(message)
        from saas_os.core.email.provider import EmailSendResult

        return EmailSendResult(accepted=True, provider_message_id="fake-1")

    return _fake_send_email


def test_send_email_channel_raises_when_default_sender_is_not_configured(monkeypatch) -> None:
    monkeypatch.delenv("EMAIL_DEFAULT_SENDER", raising=False)
    sent: list = []
    monkeypatch.setattr("saas_os.core.email.send_email", _recording_send_email(sent))

    with pytest.raises(NotificationDispatchError):
        notifications_service._send_email_channel(
            uuid.uuid4(), "subject", "body", "user@example.com"
        )
    assert sent == []


def test_send_email_channel_sends_through_core_email_send_email(monkeypatch, _sender) -> None:
    sent: list = []
    monkeypatch.setattr("saas_os.core.email.send_email", _recording_send_email(sent))

    notifications_service._send_email_channel(uuid.uuid4(), "hi", "hello", "user@example.com")

    assert len(sent) == 1
    message = sent[0]
    assert message.sender == "no-reply@example.com"
    assert message.to == ("user@example.com",)
    assert message.subject == "hi"
    assert message.text_body == "hello"
    # No outbox event identity: the provider generates the Message-ID.
    assert message.message_id is None


def test_send_email_channel_sender_does_not_depend_on_smtp_configuration(
    monkeypatch, _sender
) -> None:
    """ADR-0057: a deployment whose provider is not SMTP must not need
    `SMTP_HOST` just to name a sender."""
    from saas_os.core.email.config import get_email_config

    monkeypatch.delenv("SMTP_HOST", raising=False)
    get_email_config.cache_clear()
    sent: list = []
    monkeypatch.setattr("saas_os.core.email.send_email", _recording_send_email(sent))
    try:
        notifications_service._send_email_channel(uuid.uuid4(), "hi", "hello", "u@example.com")
    finally:
        get_email_config.cache_clear()
    assert sent[0].sender == "no-reply@example.com"


def test_send_email_channel_message_id_is_stable_per_outbox_event(monkeypatch, _sender) -> None:
    """ADR-0057: every attempt of one outbox event carries the same
    Message-ID; a different event carries a different one."""
    sent: list = []
    monkeypatch.setattr("saas_os.core.email.send_email", _recording_send_email(sent))
    event_id = uuid.uuid4()
    other_event_id = uuid.uuid4()

    for attempt_event in (event_id, event_id, other_event_id):
        notifications_service._send_email_channel(
            uuid.uuid4(), "hi", "hello", "user@example.com", attempt_event
        )

    assert sent[0].message_id == f"<notification.{event_id}@example.com>"
    assert sent[1].message_id == sent[0].message_id
    assert sent[2].message_id == f"<notification.{other_event_id}@example.com>"


def test_send_email_channel_normalizes_provider_failure(monkeypatch, _sender) -> None:
    def _failing_send_email(message, *, provider=None):
        raise EmailProviderError("send", "boom")

    monkeypatch.setattr("saas_os.core.email.send_email", _failing_send_email)

    with pytest.raises(NotificationDispatchError) as excinfo:
        notifications_service._send_email_channel(uuid.uuid4(), "hi", "hello", "user@example.com")
    # Transient by default: the existing retry policy still owns it.
    assert not isinstance(excinfo.value, PermanentEventError)


def test_send_email_channel_permanent_provider_failure_is_a_permanent_event_error(
    monkeypatch, _sender
) -> None:
    """ADR-0057: a permanent provider refusal becomes a `PermanentEventError`,
    so the outbox dispatcher dead-letters it at once instead of resending."""

    def _failing_send_email(message, *, provider=None):
        raise EmailProviderError("send", "SMTPRecipientsRefused", permanent=True, reply_code=550)

    monkeypatch.setattr("saas_os.core.email.send_email", _failing_send_email)

    with pytest.raises(NotificationPermanentDispatchError) as excinfo:
        notifications_service._send_email_channel(uuid.uuid4(), "hi", "hello", "user@example.com")
    assert isinstance(excinfo.value, NotificationDispatchError)
    assert isinstance(excinfo.value, PermanentEventError)


def _all_record_text(records) -> str:
    """Every rendered message and every `extra` value of the captured
    records -- a redaction check must cover structured fields, not only the
    message text."""
    return "\n".join(
        record.getMessage() + " " + " ".join(repr(value) for value in vars(record).values())
        for record in records
    )


def test_send_email_channel_does_not_log_recipient_subject_or_body(
    monkeypatch, caplog, _sender
) -> None:
    sent: list = []
    monkeypatch.setattr("saas_os.core.email.send_email", _recording_send_email(sent))

    secret_recipient = "very-secret-recipient@example.com"
    private_subject = "very secret subject line"
    secret_body = "very secret body content"
    with caplog.at_level(logging.INFO, logger="saas_os.core.notifications.service"):
        notifications_service._send_email_channel(
            uuid.uuid4(), private_subject, secret_body, secret_recipient
        )

    logged = _all_record_text(caplog.records)
    assert secret_recipient not in logged
    assert private_subject not in logged
    assert secret_body not in logged
    succeeded = [r for r in caplog.records if r.getMessage() == "email_send_succeeded"]
    assert succeeded[0].email_provider == "smtp"


def test_send_email_channel_failure_log_never_contains_configuration_detail(
    monkeypatch, caplog, _sender
) -> None:
    def _failing_send_email(message, *, provider=None):
        raise EmailProviderError("send", "some internal detail", reply_code=451)

    monkeypatch.setattr("saas_os.core.email.send_email", _failing_send_email)

    with caplog.at_level(logging.WARNING, logger="saas_os.core.notifications.service"):
        with pytest.raises(NotificationDispatchError):
            notifications_service._send_email_channel(
                uuid.uuid4(), "secret subject", "hello", "recipient@example.com"
            )

    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warning_records) == 1
    logged = _all_record_text(warning_records)
    assert "some internal detail" not in logged
    assert "recipient@example.com" not in logged
    assert "secret subject" not in logged
    assert warning_records[0].smtp_reply_code == 451
    assert warning_records[0].permanent is False


# --- EmailConfigurationError from a missing SMTP_HOST is also normalized ---


def test_send_email_channel_normalizes_email_configuration_error(monkeypatch, _sender) -> None:
    """The real path, not a stub: no `EMAIL_PROVIDER` (the legacy SMTP
    default) and no `SMTP_HOST` -- the provider cannot be constructed."""
    from saas_os.core.email.config import get_email_config

    monkeypatch.delenv("SMTP_HOST", raising=False)
    get_email_config.cache_clear()
    try:
        with pytest.raises(NotificationDispatchError) as excinfo:
            notifications_service._send_email_channel(
                uuid.uuid4(), "hi", "hello", "user@example.com"
            )
    finally:
        get_email_config.cache_clear()
    assert isinstance(excinfo.value.__cause__, EmailConfigurationError)
    assert not isinstance(excinfo.value, PermanentEventError)


def test_send_email_channel_normalizes_an_unknown_provider(monkeypatch, _sender) -> None:
    monkeypatch.setenv("EMAIL_PROVIDER", "carrier-pigeon")

    with pytest.raises(NotificationDispatchError) as excinfo:
        notifications_service._send_email_channel(uuid.uuid4(), "hi", "hello", "user@example.com")
    assert isinstance(excinfo.value.__cause__, EmailConfigurationError)


# --- Through the real Resend adapter (ADR-0058) ----------------------------

_RESEND_TEST_KEY = "re_channel_test_key_0123"  # pragma: allowlist secret -- fake


@pytest.fixture
def _resend(monkeypatch, _sender) -> list:
    """`EMAIL_PROVIDER=resend` through the real selection path and adapter;
    only the network is replaced (a scripted resolver and a mock transport
    under the real strict egress client). Returns the recorded requests;
    `requests.status` and `requests.body` script the answer."""
    import httpx

    from egress_support import PUBLIC_V4, StaticResolver, mock_transport_factory
    from saas_os.core.email import resend_provider
    from saas_os.infra.egress import StrictEgressClient

    class _Requests(list):
        status = 200
        body: object = {"id": "re-email-id"}

    requests = _Requests()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(requests.status, json=requests.body)

    def client(policy):
        return StrictEgressClient(
            policy,
            resolver=StaticResolver([[PUBLIC_V4]]),
            transport_factory=mock_transport_factory(handler),
        )

    class _Secrets:
        def get(self, name):
            return _RESEND_TEST_KEY if name == "RESEND_API_KEY" else None

    monkeypatch.setattr(resend_provider, "StrictEgressClient", client)
    monkeypatch.setattr(resend_provider, "get_secrets_provider", lambda: _Secrets())
    monkeypatch.setenv("EMAIL_PROVIDER", "resend")
    return requests


def test_send_email_channel_through_resend_reuses_one_idempotency_key_per_event(
    caplog, _resend
) -> None:
    import json

    event_id = uuid.uuid4()
    with caplog.at_level(logging.INFO, logger="saas_os.core.notifications.service"):
        for _ in range(2):
            notifications_service._send_email_channel(
                uuid.uuid4(), "hi", "hello", "user@example.com", event_id
            )
        notifications_service._send_email_channel(
            uuid.uuid4(), "hi", "hello", "user@example.com", uuid.uuid4()
        )

    keys = [request.headers["idempotency-key"] for request in _resend]
    assert keys[0] == keys[1] != keys[2]
    payload = json.loads(_resend[0].content)
    assert payload["from"] == "no-reply@example.com"
    assert payload["to"] == ["user@example.com"]
    assert payload["headers"] == {"Message-ID": f"<notification.{event_id}@example.com>"}
    succeeded = [r for r in caplog.records if r.getMessage() == "email_send_succeeded"]
    assert [r.email_provider for r in succeeded] == ["resend"] * 3
    assert _RESEND_TEST_KEY not in _all_record_text(caplog.records)


def test_send_email_channel_resend_validation_refusal_is_permanent(caplog, _resend) -> None:
    _resend.status = 422
    _resend.body = {"name": "missing_required_field", "message": "detail-from-resend"}
    with caplog.at_level(logging.WARNING, logger="saas_os.core.notifications.service"):
        with pytest.raises(NotificationPermanentDispatchError):
            notifications_service._send_email_channel(
                uuid.uuid4(), "hi", "hello", "user@example.com", uuid.uuid4()
            )
    warning = [r for r in caplog.records if r.levelno == logging.WARNING][0]
    assert warning.email_provider == "resend"
    assert warning.permanent is True
    assert warning.smtp_reply_code == 422  # the HTTP status, for an HTTP provider
    logged = _all_record_text(caplog.records)
    assert "detail-from-resend" not in logged
    assert _RESEND_TEST_KEY not in logged
    assert "user@example.com" not in logged


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_send_email_channel_resend_retryable_refusal_keeps_the_retry_policy(
    _resend, status: int
) -> None:
    _resend.status = status
    _resend.body = {"name": "rate_limit_exceeded"}
    with pytest.raises(NotificationDispatchError) as excinfo:
        notifications_service._send_email_channel(
            uuid.uuid4(), "hi", "hello", "user@example.com", uuid.uuid4()
        )
    assert not isinstance(excinfo.value, PermanentEventError)


# --- The job handler runs the blocking send off the event loop ------------


def test_dispatch_job_runs_the_email_send_in_a_worker_thread(monkeypatch) -> None:
    """ADR-0057: `smtplib` blocks, so the async job handler must hand the
    send to `asyncio.to_thread` rather than call it on the event loop."""
    import asyncio
    import threading

    from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

    tenant_id = uuid.uuid4()
    event_id = uuid.uuid4()
    calls: list[tuple] = []
    loop_thread = threading.get_ident()

    def _record(*args):
        calls.append((threading.get_ident(), args))

    class _Scope:
        def __enter__(self):
            return object()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(notifications_service, "require_open_tenant", lambda tenant_id: None)
    monkeypatch.setattr(notifications_service, "_send_email_channel", _record)
    monkeypatch.setattr(notifications_service, "tenant_session_scope", lambda tid: _Scope())
    monkeypatch.setattr(notifications_service, "event_consumption_recorded", lambda *a, **k: False)
    # Stop after the send: the row write is covered by the integration suite.
    monkeypatch.setattr(notifications_service, "claim_event_consumption", lambda *a, **k: False)
    monkeypatch.setattr(notifications_service, "lock_open_tenant", lambda session, tid: None)

    payload = TenantJobPayload(
        tenant_id=str(tenant_id),
        data={
            "recipient_user_id": str(uuid.uuid4()),
            "channel": "email",
            "subject": "hi",
            "body": "hello",
            "recipient_email": "user@example.com",
        },
    )
    context = TenantJobContext(tenant_id=tenant_id, event_id=event_id)

    asyncio.run(notifications_service._dispatch_notification_job(context, payload))

    assert len(calls) == 1
    thread_id, args = calls[0]
    assert thread_id != loop_thread
    assert args[-1] == event_id
