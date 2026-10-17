"""AI-F accounting -- hermetic checks (ADR-0054 Phase AI-F).

- Cost estimates: per-million rates, cached input at its own rate, exact
  `Decimal` arithmetic, never an estimate without a price or a count.
- The soft token quota: refuses a request whose projection exceeds the
  monthly limit; a missing limit passes unless a limit is required; any
  unreadable configuration refuses.
- Price configuration validation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest

from saas_os.control_plane.inference import accounting
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.config.errors import AIConfigurationError
from saas_os.control_plane.inference.config.models import AIModelPrice
from saas_os.control_plane.inference.errors import InferenceQuotaExceededError


def _price(cached: str | None = None) -> AIModelPrice:
    return AIModelPrice(
        model_ref=uuid.uuid4(),
        pricing_version="2026-10",
        currency="USD",
        input_per_million=Decimal("2.50"),
        output_per_million=Decimal("10.00"),
        cached_input_per_million=Decimal(cached) if cached else None,
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_cost_is_rate_per_million_tokens() -> None:
    cost = accounting.estimate_cost(_price(), input_tokens=1000, output_tokens=500)
    assert cost == accounting.CostEstimate(Decimal("0.00750000"), "USD", "2026-10")


def test_cached_input_is_priced_at_its_own_rate_when_configured() -> None:
    cost = accounting.estimate_cost(
        _price(cached="0.25"), input_tokens=1000, output_tokens=0, cached_input_tokens=800
    )
    assert cost is not None
    # 200 plain at 2.50 plus 800 cached at 0.25, per million.
    assert cost.amount == Decimal("0.00070000")
    # Without a cached rate, cached tokens count as ordinary input.
    plain = accounting.estimate_cost(
        _price(), input_tokens=1000, output_tokens=0, cached_input_tokens=800
    )
    assert plain is not None and plain.amount == Decimal("0.00250000")


@pytest.mark.parametrize(
    ("price", "inputs", "outputs"),
    [(None, 1, 1), (_price(), None, 1), (_price(), 1, None)],
)
def test_no_estimate_without_a_price_or_a_count(
    price: AIModelPrice | None, inputs: int | None, outputs: int | None
) -> None:
    assert accounting.estimate_cost(price, input_tokens=inputs, output_tokens=outputs) is None


def _check(limit: object, used: int, *, required: bool = False, max_output: int = 100) -> None:
    accounting.check_soft_token_quota(
        uuid.uuid4(),
        input_bytes=400,  # about 100 tokens
        max_output_tokens=max_output,
        required=required,
        entitlements=lambda t: {} if limit is None else {"ai.tokens": limit},
        recorded=lambda t, s, u: used,
    )


def test_a_request_within_the_monthly_limit_passes() -> None:
    _check(limit=1000, used=800)  # 800 + 100 + 100 = 1000


def test_a_request_whose_projection_exceeds_the_limit_is_refused() -> None:
    with pytest.raises(InferenceQuotaExceededError, match="monthly_token_quota"):
        _check(limit=1000, used=801)


@pytest.mark.parametrize("value", [None, True, "1000", 1.5, -1])
def test_a_missing_or_invalid_limit_is_no_limit_unless_required(value: object) -> None:
    _check(limit=value, used=10**9)
    with pytest.raises(InferenceQuotaExceededError, match="quota_not_configured"):
        _check(limit=value, used=0, required=True)


def test_unreadable_configuration_or_ledger_refuses() -> None:
    def broken(*args: object) -> Any:
        raise RuntimeError("database down")

    with pytest.raises(InferenceQuotaExceededError, match="quota_unavailable"):
        accounting.check_soft_token_quota(
            uuid.uuid4(), input_bytes=1, max_output_tokens=1, entitlements=broken
        )
    with pytest.raises(InferenceQuotaExceededError, match="quota_unavailable"):
        accounting.check_soft_token_quota(
            uuid.uuid4(),
            input_bytes=1,
            max_output_tokens=1,
            entitlements=lambda t: {"ai.tokens": 10},
            recorded=broken,
        )


def test_quota_required_reads_the_environment() -> None:
    assert accounting.quota_required({"AI_INFERENCE_TOKEN_QUOTA_REQUIRED": "true"})
    assert not accounting.quota_required({})


def test_the_month_window_is_the_utc_calendar_month() -> None:
    start, end = accounting.month_window(datetime(2026, 12, 17, 13, tzinfo=UTC))
    assert (start, end) == (datetime(2026, 12, 1, tzinfo=UTC), datetime(2027, 1, 1, tzinfo=UTC))


@pytest.mark.parametrize(
    "overrides",
    [
        {"pricing_version": "bad version"},
        {"currency": "usd"},
        {"input_per_million": Decimal("-1")},
        {"output_per_million": Decimal("NaN")},
        {"input_per_million": 2.5},  # a float is never accepted for money
        {"input_per_million": Decimal("0.000000001")},  # beyond 8 decimal places
        {"effective_from": datetime(2026, 1, 1)},  # naive
    ],
)
def test_invalid_prices_are_refused_before_any_transaction(overrides: dict) -> None:
    values: dict = {
        "provider_key": "p",
        "model_id": "m",
        "pricing_version": "v1",
        "currency": "USD",
        "input_per_million": Decimal("1"),
        "output_per_million": Decimal("1"),
        "effective_from": datetime(2026, 1, 1, tzinfo=UTC),
        "caller": object(),
        "reason": "r",
    }
    values.update(overrides)
    with pytest.raises(AIConfigurationError):
        ai_config.set_model_price(**values)
