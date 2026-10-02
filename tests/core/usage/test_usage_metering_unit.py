"""Phase 5.2 metering rules without a database (ADR-0037): quantity,
timestamp and window validation, and parsing a recorded usage event."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from core.usage.errors import InvalidUsageEventError, MalformedUsageEventError

from core.outbox import PermanentEventError
from core.usage import service as usage_service


@pytest.mark.parametrize(
    ("quantity", "expected"),
    [
        (Decimal("0"), Decimal("0")),
        (Decimal("2.50"), Decimal("2.50")),
        (7, Decimal("7")),
        (Decimal("999999999999999999.999999999999999999"), None),
        (Decimal("1E-18"), Decimal("1E-18")),
    ],
)
def test_valid_quantities_are_kept_exact(quantity: Any, expected: Decimal | None) -> None:
    result = usage_service._validate_quantity(quantity)
    assert isinstance(result, Decimal)
    assert result == (expected if expected is not None else quantity)


@pytest.mark.parametrize(
    "quantity",
    [
        Decimal("-0.1"),
        Decimal("NaN"),
        Decimal("sNaN"),
        Decimal("Infinity"),
        0.5,
        True,
        "1",
        None,
        Decimal("1E18"),
        Decimal("1E-19"),
    ],
)
def test_invalid_quantities_are_refused_not_coerced(quantity: Any) -> None:
    with pytest.raises(InvalidUsageEventError):
        usage_service._validate_quantity(quantity)


def test_times_are_normalized_to_utc_and_naive_times_refused() -> None:
    at = datetime(2026, 6, 1, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    assert usage_service._utc("occurred_at", at) == datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
    with pytest.raises(InvalidUsageEventError):
        usage_service._utc("occurred_at", datetime(2026, 6, 1))


def test_the_default_window_is_the_current_utc_calendar_month() -> None:
    start, end = usage_service._window(None, None)
    assert start.tzinfo is UTC and start.day == 1 and start.hour == 0
    assert end > start and end.day == 1


@pytest.mark.parametrize(
    ("since", "until"),
    [
        (datetime(2026, 6, 1, tzinfo=UTC), None),
        (None, datetime(2026, 6, 1, tzinfo=UTC)),
        (datetime(2026, 6, 2, tzinfo=UTC), datetime(2026, 6, 1, tzinfo=UTC)),
        (datetime(2026, 6, 1), datetime(2026, 6, 2)),
    ],
)
def test_invalid_windows_are_refused(since: Any, until: Any) -> None:
    with pytest.raises(InvalidUsageEventError):
        usage_service._window(since, until)


def test_a_valid_recorded_event_parses_and_a_legacy_naive_time_reads_as_utc() -> None:
    metric, quantity, at = usage_service._parse_ingestion(
        {"metric": "calls", "quantity": "3", "occurred_at": "2026-06-01T12:00:00"}
    )
    assert (metric, quantity, at) == ("calls", Decimal("3"), datetime(2026, 6, 1, 12, tzinfo=UTC))


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"metric": "", "quantity": "1", "occurred_at": "2026-06-01T12:00:00+00:00"},
        {"metric": "calls", "quantity": "NaN", "occurred_at": "2026-06-01T12:00:00+00:00"},
        {"metric": "calls", "quantity": "x", "occurred_at": "2026-06-01T12:00:00+00:00"},
        {"metric": "calls", "quantity": "1", "occurred_at": "yesterday"},
    ],
)
def test_a_malformed_recorded_event_is_a_permanent_failure(data: dict[str, object]) -> None:
    with pytest.raises(MalformedUsageEventError) as excinfo:
        usage_service._parse_ingestion(data)
    assert isinstance(excinfo.value, PermanentEventError)
