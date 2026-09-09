"""Pure unit tests for `core/notifications/service.py` -- no database or
Redis needed. `dispatch_notification()`'s own input validation is proven
to happen *before* any job is ever enqueued, by monkeypatching
`enqueue_job` and asserting it is never called on invalid input.
"""

from __future__ import annotations

import uuid

import pytest
from core.notifications.errors import InvalidNotificationChannelError

from core.notifications import service as notifications_service
from infra.jobs import TenantJobPayload

pytestmark = pytest.mark.anyio


def test_validate_channel_rejects_unknown_channel() -> None:
    with pytest.raises(InvalidNotificationChannelError):
        notifications_service._validate_channel("carrier_pigeon")


def test_validate_channel_accepts_in_app() -> None:
    notifications_service._validate_channel("in_app")  # does not raise


def test_validate_subject_rejects_overlong_subject() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        notifications_service._validate_subject("x" * 256)


def test_validate_subject_accepts_none_and_short_subject() -> None:
    notifications_service._validate_subject(None)  # does not raise
    notifications_service._validate_subject("a short subject")  # does not raise


async def test_dispatch_notification_rejects_unknown_channel_without_enqueueing(
    monkeypatch,
) -> None:
    called = False

    async def _fake_enqueue_job(*args, **kwargs):
        nonlocal called
        called = True
        return "should-not-be-reached"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    with pytest.raises(InvalidNotificationChannelError):
        await notifications_service.dispatch_notification(
            uuid.uuid4(), uuid.uuid4(), "carrier_pigeon", "body"
        )
    assert called is False


async def test_dispatch_notification_rejects_overlong_subject_without_enqueueing(
    monkeypatch,
) -> None:
    called = False

    async def _fake_enqueue_job(*args, **kwargs):
        nonlocal called
        called = True
        return "should-not-be-reached"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    with pytest.raises(ValueError, match="exceeds"):
        await notifications_service.dispatch_notification(
            uuid.uuid4(), uuid.uuid4(), "in_app", "body", subject="x" * 256
        )
    assert called is False


async def test_dispatch_notification_enqueues_with_expected_payload_shape(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def _fake_enqueue_job(function_name, payload, *, queue_name=None):
        captured["function_name"] = function_name
        captured["payload"] = payload
        captured["queue_name"] = queue_name
        return "job-123"

    monkeypatch.setattr(notifications_service, "enqueue_job", _fake_enqueue_job)

    tenant_id = uuid.uuid4()
    recipient_id = uuid.uuid4()
    job_id = await notifications_service.dispatch_notification(
        tenant_id, recipient_id, "in_app", "hello", subject="hi"
    )

    assert job_id == "job-123"
    assert captured["function_name"] == "_dispatch_notification_job"
    payload = captured["payload"]
    assert isinstance(payload, TenantJobPayload)
    assert payload.tenant_id == str(tenant_id)
    assert payload.data == {
        "recipient_user_id": str(recipient_id),
        "channel": "in_app",
        "subject": "hi",
        "body": "hello",
    }
