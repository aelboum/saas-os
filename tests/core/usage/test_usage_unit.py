"""Pure unit tests for `core/usage/service.py` -- no database or Redis
needed. `ingest_event()`'s own input validation is proven to happen
*before* any job is ever enqueued, by monkeypatching `enqueue_job` and
asserting it is never called on invalid input. Mirrors
tests/core/notifications/test_notifications_unit.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from core.usage.errors import InvalidUsageEventError

from core.usage import service as usage_service
from infra.jobs import TenantJobPayload

pytestmark = pytest.mark.anyio


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


# --- ingest_event() validates before enqueueing -----------------------------


async def test_ingest_event_rejects_invalid_metric_without_enqueueing(monkeypatch) -> None:
    called = False

    async def _fake_enqueue_job(*args, **kwargs):
        nonlocal called
        called = True
        return "should-not-be-reached"

    monkeypatch.setattr(usage_service, "enqueue_job", _fake_enqueue_job)

    with pytest.raises(InvalidUsageEventError):
        await usage_service.ingest_event(uuid.uuid4(), "", Decimal("1"))
    assert called is False


async def test_ingest_event_rejects_negative_quantity_without_enqueueing(monkeypatch) -> None:
    called = False

    async def _fake_enqueue_job(*args, **kwargs):
        nonlocal called
        called = True
        return "should-not-be-reached"

    monkeypatch.setattr(usage_service, "enqueue_job", _fake_enqueue_job)

    with pytest.raises(InvalidUsageEventError):
        await usage_service.ingest_event(uuid.uuid4(), "api_calls", Decimal("-5"))
    assert called is False


async def test_ingest_event_enqueues_with_expected_payload_shape(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def _fake_enqueue_job(function_name, payload, *, queue_name=None):
        captured["function_name"] = function_name
        captured["payload"] = payload
        captured["queue_name"] = queue_name
        return "job-123"

    monkeypatch.setattr(usage_service, "enqueue_job", _fake_enqueue_job)

    tenant_id = uuid.uuid4()
    occurred_at = datetime(2026, 1, 1, tzinfo=UTC)
    job_id = await usage_service.ingest_event(
        tenant_id, "api_calls", Decimal("3.5"), occurred_at=occurred_at
    )

    assert job_id == "job-123"
    assert captured["function_name"] == "_ingest_usage_event_job"
    payload = captured["payload"]
    assert isinstance(payload, TenantJobPayload)
    assert payload.tenant_id == str(tenant_id)
    assert payload.data == {
        "metric": "api_calls",
        "quantity": "3.5",
        "occurred_at": occurred_at.isoformat(),
    }


async def test_ingest_event_defaults_occurred_at_to_now(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def _fake_enqueue_job(function_name, payload, *, queue_name=None):
        captured["payload"] = payload
        return "job-123"

    monkeypatch.setattr(usage_service, "enqueue_job", _fake_enqueue_job)

    before = datetime.now(UTC)
    await usage_service.ingest_event(uuid.uuid4(), "api_calls", Decimal("1"))
    after = datetime.now(UTC)

    payload = captured["payload"]
    assert isinstance(payload, TenantJobPayload)
    recorded = datetime.fromisoformat(payload.data["occurred_at"])
    assert before <= recorded <= after


# --- Quota-limit interpretation ---------------------------------------------


def test_current_utc_month_window_spans_exactly_one_calendar_month() -> None:
    start, end = usage_service._current_utc_month_window()
    assert start.day == 1
    assert start.hour == 0
    assert end > start
    assert (end - start).days >= 28
    assert (end - start).days <= 31
