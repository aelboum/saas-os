"""Pure unit tests for `saas_os/core/usage/service.py` -- no database or Redis
needed. `ingest_event()`'s own input validation is proven to happen
*before* any outbox event is recorded (RE-1), by monkeypatching
`append_event` and asserting it is never called on invalid input. Mirrors
tests/core/notifications/test_notifications_unit.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest

from saas_os.core.usage import service as usage_service
from saas_os.core.usage.errors import InvalidUsageEventError

_SESSION: Any = object()


@pytest.fixture(autouse=True)
def _tenant_lifecycle_fence_open(monkeypatch) -> None:
    """PRIV-03 P2: `ingest_event()` is lifecycle-fenced by
    `saas_os.core.tenancy.lock_open_tenant()` -- a database read. Pure unit
    tests, random tenant id, no database: the fence is stubbed open here,
    exactly like `append_event` is stubbed below (see
    tests/core/tenancy/test_lifecycle_fencing_integration.py for the fence)."""
    monkeypatch.setattr(usage_service, "lock_open_tenant", lambda session, tenant_id: None)


def _capture_append(monkeypatch) -> dict[str, object]:
    captured: dict[str, object] = {}

    def _fake_append_event(session, **kwargs):
        captured["session"] = session
        captured.update(kwargs)
        return uuid.UUID(int=123)

    monkeypatch.setattr(usage_service, "append_event", _fake_append_event)
    return captured


# --- Validation ------------------------------------------------------------


def test_validate_metric_rejects_empty_string() -> None:
    with pytest.raises(InvalidUsageEventError):
        usage_service._validate_metric("")


def test_validate_metric_rejects_whitespace_only() -> None:
    with pytest.raises(InvalidUsageEventError):
        usage_service._validate_metric("   ")


def test_validate_metric_rejects_overlong_metric() -> None:
    with pytest.raises(InvalidUsageEventError, match="exceeds"):
        usage_service._validate_metric("x" * 101)


def test_validate_metric_accepts_normal_metric() -> None:
    usage_service._validate_metric("api_calls")  # does not raise


def test_validate_quantity_rejects_negative() -> None:
    with pytest.raises(InvalidUsageEventError):
        usage_service._validate_quantity(Decimal("-1"))


def test_validate_quantity_accepts_zero_and_positive() -> None:
    usage_service._validate_quantity(Decimal("0"))  # does not raise
    usage_service._validate_quantity(Decimal("42.5"))  # does not raise


# --- ingest_event() validates before recording -------------------------------


def test_ingest_event_rejects_invalid_metric_without_recording(monkeypatch) -> None:
    captured = _capture_append(monkeypatch)

    with pytest.raises(InvalidUsageEventError):
        usage_service.ingest_event(_SESSION, uuid.uuid4(), "", Decimal("1"))
    assert captured == {}


def test_ingest_event_rejects_negative_quantity_without_recording(monkeypatch) -> None:
    captured = _capture_append(monkeypatch)

    with pytest.raises(InvalidUsageEventError):
        usage_service.ingest_event(_SESSION, uuid.uuid4(), "api_calls", Decimal("-5"))
    assert captured == {}


def test_ingest_event_records_expected_event_shape(monkeypatch) -> None:
    captured = _capture_append(monkeypatch)

    tenant_id = uuid.uuid4()
    occurred_at = datetime(2026, 1, 1, tzinfo=UTC)
    event_id = usage_service.ingest_event(
        _SESSION, tenant_id, "api_calls", Decimal("3.5"), occurred_at=occurred_at
    )

    assert event_id == uuid.UUID(int=123)
    assert captured["session"] is _SESSION
    assert captured["tenant_id"] == tenant_id
    assert captured["event_type"] == usage_service.USAGE_INGESTION_EVENT_TYPE
    assert captured["aggregate_type"] == "usage_metric"
    assert captured["aggregate_id"] == "api_calls"
    assert captured["payload"] == {
        "metric": "api_calls",
        "quantity": "3.5",
        "occurred_at": occurred_at.isoformat(),
    }


def test_ingest_event_defaults_occurred_at_to_now(monkeypatch) -> None:
    captured = _capture_append(monkeypatch)

    before = datetime.now(UTC)
    usage_service.ingest_event(_SESSION, uuid.uuid4(), "api_calls", Decimal("1"))
    after = datetime.now(UTC)

    payload = captured["payload"]
    assert isinstance(payload, dict)
    recorded = datetime.fromisoformat(payload["occurred_at"])
    assert before <= recorded <= after


# --- Quota-limit interpretation ---------------------------------------------


def test_current_utc_month_window_spans_exactly_one_calendar_month() -> None:
    start, end = usage_service._current_utc_month_window()
    assert start.day == 1
    assert start.hour == 0
    assert end > start
    assert (end - start).days >= 28
    assert (end - start).days <= 31
