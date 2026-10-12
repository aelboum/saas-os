"""Pure unit tests for `saas_os/core/notifications/service.py` -- no database or
Redis needed. `dispatch_notification()`'s own input validation is proven
to happen *before* any outbox event is recorded, by monkeypatching
`append_event` and asserting it is never called on invalid input (RE-1:
the producer records a `saas_os.core.outbox` event in the caller's transaction).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from saas_os.core.notifications import service as notifications_service
from saas_os.core.notifications.errors import InvalidNotificationChannelError

# Stands in for the caller's SQLAlchemy session: these tests never reach
# the database (the fence and append_event are stubbed).
_SESSION: Any = object()


@pytest.fixture(autouse=True)
def _tenant_lifecycle_fence_open(monkeypatch) -> None:
    """PRIV-03 P2: `dispatch_notification()` is lifecycle-fenced by
    `saas_os.core.tenancy.lock_open_tenant()` in the caller's transaction -- a
    database read. These are pure unit tests of validation and payload
    shape against a random tenant id with no database, so the fence is
    stubbed open here, exactly like `append_event` is stubbed below. The
    fence itself is proven against real PostgreSQL by
    tests/core/tenancy/test_lifecycle_fencing_integration.py."""
    monkeypatch.setattr(notifications_service, "lock_open_tenant", lambda session, tenant_id: None)


def _capture_append(monkeypatch) -> dict[str, object]:
    captured: dict[str, object] = {}

    def _fake_append_event(session, **kwargs):
        captured["session"] = session
        captured.update(kwargs)
        return uuid.UUID(int=123)

    monkeypatch.setattr(notifications_service, "append_event", _fake_append_event)
    return captured


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


def test_dispatch_notification_rejects_unknown_channel_without_recording(monkeypatch) -> None:
    captured = _capture_append(monkeypatch)

    with pytest.raises(InvalidNotificationChannelError):
        notifications_service.dispatch_notification(
            _SESSION, uuid.uuid4(), uuid.uuid4(), "carrier_pigeon", "body"
        )
    assert captured == {}


def test_dispatch_notification_rejects_overlong_subject_without_recording(monkeypatch) -> None:
    captured = _capture_append(monkeypatch)

    with pytest.raises(ValueError, match="exceeds"):
        notifications_service.dispatch_notification(
            _SESSION, uuid.uuid4(), uuid.uuid4(), "in_app", "body", subject="x" * 256
        )
    assert captured == {}


def test_dispatch_notification_records_expected_event_shape(monkeypatch) -> None:
    captured = _capture_append(monkeypatch)

    tenant_id = uuid.uuid4()
    recipient_id = uuid.uuid4()
    event_id = notifications_service.dispatch_notification(
        _SESSION, tenant_id, recipient_id, "in_app", "hello", subject="hi"
    )

    assert event_id == uuid.UUID(int=123)
    assert captured["session"] is _SESSION
    assert captured["tenant_id"] == tenant_id
    assert captured["event_type"] == notifications_service.NOTIFICATION_DISPATCH_EVENT_TYPE
    assert captured["aggregate_type"] == "user"
    assert captured["aggregate_id"] == str(recipient_id)
    assert captured["payload"] == {
        "recipient_user_id": str(recipient_id),
        "channel": "in_app",
        "subject": "hi",
        "body": "hello",
    }
