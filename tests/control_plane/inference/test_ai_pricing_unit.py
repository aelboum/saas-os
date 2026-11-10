"""Gap 21a pricing -- hermetic checks (ADR-0054 amendment of 2026-11-09).

- Cost math over every billable unit of a price (input, output, cached input,
  cache write, a flat amount per request, other units) against an oracle
  written independently of `estimate_cost`: exact rational arithmetic and an
  integer rounding step, no `Decimal.quantize`.
- A unit the attempt used that the price has no rate for makes the cost
  unknown (`None`), never zero and never a part of the amount.
- Price staleness: the status of a price at a moment, with the 24-hour limit
  at its exact boundary, and the deployment setting that can only shorten it.
  Nothing refuses on the status in this stage; these tests pin the
  classification the spend-limit stage (Gap 21b) will rely on.
- Validation of the new price fields before any transaction.
- The new price text never claims a ceiling or an invoice amount.
"""

from __future__ import annotations

import inspect
import random
import re
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from fractions import Fraction
from typing import Any

import pytest

from saas_os.control_plane.inference import accounting
from saas_os.control_plane.inference.accounting import PriceStatus
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.config.errors import AIConfigurationError
from saas_os.control_plane.inference.config.models import (
    MAX_RATE,
    AIModelPrice,
    decode_unit_rates,
)
from saas_os.control_plane.inference.errors import InferenceInternalError

_NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
_MICRO = timedelta(microseconds=1)


def _price(**fields: Any) -> AIModelPrice:
    values: dict[str, Any] = {
        "model_ref": uuid.uuid4(),
        "pricing_version": "2026-11",
        "currency": "USD",
        "input_per_million": Decimal("2.50"),
        "output_per_million": Decimal("10.00"),
        "effective_from": datetime(2026, 1, 1, tzinfo=UTC),
    }
    values.update(fields)
    return AIModelPrice(**values)


# --- the oracle ------------------------------------------------------------------------------


def _oracle(
    *,
    rates: dict[str, Decimal | None],
    unit_rates: dict[str, Decimal],
    usage: dict[str, int | None],
    other_units: dict[str, int],
) -> Decimal | None:
    """The expected cost, or None for unknown. Written from the contract, not
    from `estimate_cost`: fractions throughout, half-up rounding to 1e-8 done
    on integers."""
    if usage["input"] is None or usage["output"] is None:
        return None
    total = Fraction(0)
    cached = usage["cached"] or 0
    if rates["cached"] is None:
        total += Fraction(usage["input"]) * Fraction(rates["input"]) / 1_000_000  # type: ignore[arg-type]
    else:
        at_cached_rate = min(cached, usage["input"])
        total += Fraction(at_cached_rate) * Fraction(rates["cached"]) / 1_000_000
        total += (
            Fraction(usage["input"] - at_cached_rate) * Fraction(rates["input"]) / 1_000_000  # type: ignore[arg-type]
        )
    total += Fraction(usage["output"]) * Fraction(rates["output"]) / 1_000_000  # type: ignore[arg-type]
    cache_write = usage["cache_write"] or 0
    if cache_write > 0:
        if rates["cache_write"] is None:
            return None
        total += Fraction(cache_write) * Fraction(rates["cache_write"]) / 1_000_000
    if rates["per_request"] is not None:
        total += Fraction(rates["per_request"])
    for name, quantity in other_units.items():
        if quantity == 0:
            continue
        if name not in unit_rates:
            return None
        total += Fraction(quantity) * Fraction(unit_rates[name])
    # Half up at 1e-8 (the amount is never negative).
    scaled = total * 100_000_000
    units = (2 * scaled.numerator + scaled.denominator) // (2 * scaled.denominator)
    return Decimal(units) / Decimal(100_000_000)


def _random_rate(rng: random.Random, *, optional: bool) -> Decimal | None:
    if optional and rng.random() < 0.35:
        return None
    return Decimal(rng.randrange(0, 5_000_000_000)) / Decimal(100_000_000)


def _random_count(rng: random.Random, *, optional: bool) -> int | None:
    if optional and rng.random() < 0.2:
        return None
    return rng.choice([0, 0, 1, 7, rng.randrange(0, 2_000), rng.randrange(0, 20_000_000)])


_UNITS = ("web_search_requests", "image_inputs", "code_execution_seconds")


def test_the_cost_of_every_unit_matches_an_independent_oracle() -> None:
    rng = random.Random(21)
    known = unknown = 0
    for _ in range(600):
        rates = {
            "input": _random_rate(rng, optional=False),
            "output": _random_rate(rng, optional=False),
            "cached": _random_rate(rng, optional=True),
            "cache_write": _random_rate(rng, optional=True),
            "per_request": _random_rate(rng, optional=True),
        }
        unit_rates: dict[str, Decimal] = {}
        for name in _UNITS:
            rate = _random_rate(rng, optional=True)
            if rate is not None:
                unit_rates[name] = rate
        usage = {
            "input": _random_count(rng, optional=False),
            "output": _random_count(rng, optional=False),
            "cached": _random_count(rng, optional=True),
            "cache_write": _random_count(rng, optional=True),
        }
        other_units = {
            name: rng.choice([0, 1, 3, rng.randrange(0, 500)])
            for name in _UNITS
            if rng.random() < 0.5
        }
        price = _price(
            input_per_million=rates["input"],
            output_per_million=rates["output"],
            cached_input_per_million=rates["cached"],
            cache_write_per_million=rates["cache_write"],
            per_request=rates["per_request"],
            unit_rates={name: format(rate, "f") for name, rate in unit_rates.items()} or None,
        )
        expected = _oracle(rates=rates, unit_rates=unit_rates, usage=usage, other_units=other_units)
        actual = accounting.estimate_cost(
            price,
            input_tokens=usage["input"],
            output_tokens=usage["output"],
            cached_input_tokens=usage["cached"],
            cache_write_tokens=usage["cache_write"],
            other_units=other_units,
        )
        case = (rates, unit_rates, usage, other_units)
        if expected is None:
            unknown += 1
            assert actual is None, case
        else:
            known += 1
            assert actual is not None, case
            assert actual.amount == expected, case
            assert (actual.currency, actual.pricing_version) == ("USD", "2026-11")
    # Both outcomes are exercised, so neither branch is vacuous.
    assert known > 100 and unknown > 100


def test_each_unit_adds_its_own_amount() -> None:
    base = accounting.estimate_cost(_price(), input_tokens=1000, output_tokens=500)
    assert base is not None and base.amount == Decimal("0.00750000")

    cache_write = accounting.estimate_cost(
        _price(cache_write_per_million=Decimal("3.75")),
        input_tokens=1000,
        output_tokens=500,
        cache_write_tokens=2000,
    )
    # 2000 cache-write tokens at 3.75 per million, on top of the base.
    assert cache_write is not None and cache_write.amount == Decimal("0.01500000")

    per_request = accounting.estimate_cost(
        _price(per_request=Decimal("0.01")), input_tokens=1000, output_tokens=500
    )
    assert per_request is not None and per_request.amount == Decimal("0.01750000")

    other = accounting.estimate_cost(
        _price(unit_rates={"web_search_requests": "0.01", "image_inputs": "0.002"}),
        input_tokens=1000,
        output_tokens=500,
        other_units={"web_search_requests": 3, "image_inputs": 5},
    )
    assert other is not None and other.amount == Decimal("0.04750000")


def test_a_per_request_amount_is_added_even_when_no_token_was_used() -> None:
    cost = accounting.estimate_cost(
        _price(per_request=Decimal("0.02")), input_tokens=0, output_tokens=0
    )
    assert cost is not None and cost.amount == Decimal("0.02000000")


def test_cache_write_tokens_are_not_taken_from_the_input_count() -> None:
    """Cached input is a part of `input_tokens`; cache-write tokens are a count
    of their own and never reduce the input priced at the input rate."""
    cost = accounting.estimate_cost(
        _price(cached_input_per_million=Decimal("0.25"), cache_write_per_million=Decimal("3.00")),
        input_tokens=1000,
        output_tokens=0,
        cached_input_tokens=800,
        cache_write_tokens=1000,
    )
    # 200 plain at 2.50, 800 cached at 0.25, 1000 written at 3.00, per million.
    assert cost is not None and cost.amount == Decimal("0.00370000")


@pytest.mark.parametrize(
    ("price_fields", "usage"),
    [
        # cache-write tokens under a price without a cache-write rate
        ({}, {"cache_write_tokens": 1}),
        # a unit the price does not name
        ({}, {"other_units": {"web_search_requests": 1}}),
        ({"unit_rates": {"image_inputs": "0.01"}}, {"other_units": {"web_search_requests": 1}}),
        # one priced unit and one unpriced unit: the priced part is not reported
        (
            {"unit_rates": {"image_inputs": "0.01"}},
            {"other_units": {"image_inputs": 2, "web_search_requests": 1}},
        ),
        # a stored rate that cannot be used reads as no rate
        (
            {"unit_rates": {"web_search_requests": "abc"}},
            {"other_units": {"web_search_requests": 1}},
        ),
        (
            {"unit_rates": {"web_search_requests": "-1"}},
            {"other_units": {"web_search_requests": 1}},
        ),
        (
            {"unit_rates": {"web_search_requests": "NaN"}},
            {"other_units": {"web_search_requests": 1}},
        ),
        (
            {"unit_rates": {"web_search_requests": 0.01}},
            {"other_units": {"web_search_requests": 1}},
        ),
        (
            {"unit_rates": {"web_search_requests": "1000000.00000001"}},
            {"other_units": {"web_search_requests": 1}},
        ),
        ({"unit_rates": ["web_search_requests"]}, {"other_units": {"web_search_requests": 1}}),
        # a quantity that is not a non-negative whole number
        (
            {"unit_rates": {"web_search_requests": "0.01"}},
            {"other_units": {"web_search_requests": -1}},
        ),
        (
            {"unit_rates": {"web_search_requests": "0.01"}},
            {"other_units": {"web_search_requests": True}},
        ),
        (
            {"unit_rates": {"web_search_requests": "0.01"}},
            {"other_units": {"web_search_requests": 1.5}},
        ),
    ],
)
def test_a_used_unit_without_a_rate_makes_the_cost_unknown_never_zero(
    price_fields: dict[str, Any], usage: dict[str, Any]
) -> None:
    cost = accounting.estimate_cost(
        _price(**price_fields), input_tokens=1000, output_tokens=500, **usage
    )
    # None, not a `CostEstimate` of zero or of the priced part.
    assert cost is None


@pytest.mark.parametrize(
    "usage",
    [
        {"cache_write_tokens": None},
        {"cache_write_tokens": 0},
        {"other_units": None},
        {"other_units": {}},
        {"other_units": {"web_search_requests": 0}},
    ],
)
def test_a_unit_that_was_not_used_needs_no_rate(usage: dict[str, Any]) -> None:
    cost = accounting.estimate_cost(_price(), input_tokens=1000, output_tokens=500, **usage)
    assert cost is not None and cost.amount == Decimal("0.00750000")


def test_the_amount_is_rounded_half_up_at_eight_places() -> None:
    def amount(rate: str) -> Decimal:
        cost = accounting.estimate_cost(
            _price(input_per_million=Decimal(rate), output_per_million=Decimal(0)),
            input_tokens=1,
            output_tokens=0,
        )
        assert cost is not None
        return cost.amount

    assert amount("0.005") == Decimal("0.00000001")  # exactly half: up
    assert amount("0.00499999") == Decimal("0.00000000")
    assert amount("0.015") == Decimal("0.00000002")  # half up, not half even


def test_stored_unit_rates_are_decoded_strictly() -> None:
    assert decode_unit_rates(None) == {}
    assert decode_unit_rates("{}") == {}
    assert decode_unit_rates([("a", "1")]) == {}
    assert decode_unit_rates(
        {
            "ok": "0.01",
            "zero": "0",
            "top": format(MAX_RATE, "f"),
            "over": "1000000.00000001",
            "negative": "-0.01",
            "nan": "NaN",
            "infinite": "Infinity",
            "word": "free",
            "number": 1,
            "float": 0.5,
            "none": None,
            7: "1",
        }
    ) == {"ok": Decimal("0.01"), "zero": Decimal(0), "top": MAX_RATE}


# --- price staleness -------------------------------------------------------------------------


def test_the_statuses_are_a_closed_set() -> None:
    assert {status.value for status in PriceStatus} == {
        "fresh",
        "stale",
        "unverifiable",
        "missing",
    }


def test_the_limit_is_twenty_four_hours() -> None:
    assert accounting.PRICE_MAX_AGE == timedelta(hours=24)
    assert accounting.price_max_age({}) == timedelta(hours=24)


@pytest.mark.parametrize(
    ("reviewed_at", "expected"),
    [
        (_NOW, PriceStatus.FRESH),
        (_NOW - timedelta(hours=23, minutes=59), PriceStatus.FRESH),
        (_NOW - timedelta(hours=24), PriceStatus.FRESH),  # exactly at the limit
        (_NOW - timedelta(hours=24) - _MICRO, PriceStatus.STALE),
        (_NOW - timedelta(days=30), PriceStatus.STALE),
        (None, PriceStatus.UNVERIFIABLE),  # never confirmed
        (datetime(2026, 11, 10, 11, 0), PriceStatus.UNVERIFIABLE),  # naive: no instant
        (_NOW + timedelta(minutes=5), PriceStatus.FRESH),  # clock difference
        (_NOW + timedelta(minutes=5) + _MICRO, PriceStatus.UNVERIFIABLE),
        (_NOW + timedelta(days=365), PriceStatus.UNVERIFIABLE),
    ],
)
def test_a_price_is_classified_by_its_last_confirmation(
    reviewed_at: datetime | None, expected: PriceStatus
) -> None:
    price = _price(reviewed_at=reviewed_at)
    assert accounting.price_status(price, at=_NOW, max_age=timedelta(hours=24)) is expected


def test_no_price_is_missing() -> None:
    assert (
        accounting.price_status(None, at=_NOW, max_age=timedelta(hours=24)) is PriceStatus.MISSING
    )


def test_the_age_is_counted_from_the_confirmation_not_from_effective_from() -> None:
    old_but_confirmed = _price(
        effective_from=_NOW - timedelta(days=400), reviewed_at=_NOW - timedelta(hours=1)
    )
    assert accounting.price_status(old_but_confirmed, at=_NOW, max_age=None) is PriceStatus.FRESH
    new_but_unconfirmed = _price(effective_from=_NOW - timedelta(minutes=1), reviewed_at=None)
    assert (
        accounting.price_status(new_but_unconfirmed, at=_NOW, max_age=None)
        is PriceStatus.UNVERIFIABLE
    )


def test_a_shorter_limit_applies_and_a_longer_one_does_not() -> None:
    hour_old = _price(reviewed_at=_NOW - timedelta(hours=1) - _MICRO)
    assert accounting.price_status(hour_old, at=_NOW, max_age=timedelta(hours=1)) is (
        PriceStatus.STALE
    )
    day_old = _price(reviewed_at=_NOW - timedelta(hours=24) - _MICRO)
    # Nothing lengthens the 24 hours, not even a caller passing more.
    assert accounting.price_status(day_old, at=_NOW, max_age=timedelta(days=7)) is PriceStatus.STALE


def test_the_deployment_setting_is_the_default_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    price = _price(reviewed_at=_NOW - timedelta(seconds=61))
    monkeypatch.delenv("AI_PRICE_MAX_AGE_SECONDS", raising=False)
    assert accounting.price_status(price, at=_NOW) is PriceStatus.FRESH
    monkeypatch.setenv("AI_PRICE_MAX_AGE_SECONDS", "60")
    assert accounting.price_status(price, at=_NOW) is PriceStatus.STALE
    # An unreadable setting never reads as "fresh".
    monkeypatch.setenv("AI_PRICE_MAX_AGE_SECONDS", "one day")
    with pytest.raises(InferenceInternalError, match="invalid_ai_price_max_age_seconds"):
        accounting.price_status(price, at=_NOW)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", timedelta(hours=24)),
        ("   ", timedelta(hours=24)),
        ("1", timedelta(seconds=1)),
        ("3600", timedelta(hours=1)),
        (" 3600 ", timedelta(hours=1)),
        ("86400", timedelta(hours=24)),
    ],
)
def test_the_setting_accepts_whole_seconds_up_to_a_day(raw: str, expected: timedelta) -> None:
    assert accounting.price_max_age({"AI_PRICE_MAX_AGE_SECONDS": raw}) == expected


@pytest.mark.parametrize("raw", ["0", "-1", "86401", "172800", "1.5", "24h", "one day", "1e3"])
def test_any_other_value_of_the_setting_refuses(raw: str) -> None:
    with pytest.raises(InferenceInternalError, match="invalid_ai_price_max_age_seconds") as info:
        accounting.price_max_age({"AI_PRICE_MAX_AGE_SECONDS": raw})
    # The error names the setting, never its value.
    assert raw not in str(info.value)


# --- price configuration validation ----------------------------------------------------------


def _price_request(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
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
    return values


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"cache_write_per_million": Decimal("-1")}, "invalid_rate"),
        ({"cache_write_per_million": Decimal("NaN")}, "invalid_rate"),
        ({"cache_write_per_million": 3.75}, "invalid_rate"),  # a float is never money
        ({"cache_write_per_million": Decimal("0.000000001")}, "invalid_rate"),
        ({"cache_write_per_million": Decimal("1000000.01")}, "invalid_rate"),
        ({"per_request": Decimal("-0.01")}, "invalid_rate"),
        ({"per_request": Decimal("Infinity")}, "invalid_rate"),
        ({"per_request": "0.01"}, "invalid_rate"),
        ({"per_request": Decimal("0.000000001")}, "invalid_rate"),
        ({"unit_rates": [("web_search_requests", Decimal("0.01"))]}, "invalid_unit_rates"),
        ({"unit_rates": "web_search_requests"}, "invalid_unit_rates"),
        (
            {"unit_rates": {f"unit_{n}": Decimal("1") for n in range(17)}},
            "invalid_unit_rates",
        ),
        ({"unit_rates": {"Web_Search": Decimal("1")}}, "invalid_unit_name"),
        ({"unit_rates": {"1st": Decimal("1")}}, "invalid_unit_name"),
        ({"unit_rates": {"web-search": Decimal("1")}}, "invalid_unit_name"),
        ({"unit_rates": {"": Decimal("1")}}, "invalid_unit_name"),
        ({"unit_rates": {"u" * 65: Decimal("1")}}, "invalid_unit_name"),
        ({"unit_rates": {7: Decimal("1")}}, "invalid_unit_name"),
        ({"unit_rates": {"web_search_requests": None}}, "invalid_rate"),
        ({"unit_rates": {"web_search_requests": Decimal("-1")}}, "invalid_rate"),
        ({"unit_rates": {"web_search_requests": 0.01}}, "invalid_rate"),
        ({"unit_rates": {"web_search_requests": "0.01"}}, "invalid_rate"),
        ({"unit_rates": {"web_search_requests": Decimal("0.000000001")}}, "invalid_rate"),
    ],
)
def test_invalid_units_of_a_price_are_refused_before_any_transaction(
    overrides: dict[str, Any], reason: str
) -> None:
    # `caller` is no caller at all: reaching authorization would fail otherwise.
    with pytest.raises(AIConfigurationError) as info:
        ai_config.set_model_price(**_price_request(**overrides))
    assert info.value.reason == reason


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"provider_key": "Bad Key"}, "invalid_provider_key"),
        ({"pricing_version": "bad version"}, "invalid_pricing_version"),
        ({"pricing_version": ""}, "invalid_pricing_version"),
        ({"pricing_version": 7}, "invalid_pricing_version"),
    ],
)
def test_an_invalid_confirmation_is_refused_before_any_transaction(
    overrides: dict[str, Any], reason: str
) -> None:
    values: dict[str, Any] = {
        "provider_key": "p",
        "model_id": "m",
        "pricing_version": "v1",
        "caller": object(),
        "reason": "r",
    }
    values.update(overrides)
    with pytest.raises(AIConfigurationError) as info:
        ai_config.confirm_model_price(**values)
    assert info.value.reason == reason


# --- wording ---------------------------------------------------------------------------------

_PRICE_TEXT_OWNERS = (
    accounting.estimate_cost,
    accounting.price_status,
    accounting.price_max_age,
    accounting.PriceStatus,
    accounting.CostEstimate,
    ai_config.set_model_price,
    ai_config.confirm_model_price,
    ai_config.ModelPriceView,
    AIModelPrice,
    decode_unit_rates,
)
_SENTENCE = re.compile(r"(?<=[.;:])\s+")


def test_the_price_text_claims_no_ceiling_and_no_invoice_amount() -> None:
    """Gap 21 criterion 13, for the text this stage adds: a cost is estimated
    platform spend. The words that would claim more appear nowhere, and a
    provider's invoice is mentioned only to say the amount is not one."""
    for owner in _PRICE_TEXT_OWNERS:
        doc = " ".join((inspect.getdoc(owner) or "").split())
        lowered = doc.lower()
        assert not re.search(r"\bhard\b|guarantee", lowered), owner
        for sentence in _SENTENCE.split(lowered):
            if "invoic" in sentence or "billed" in sentence:
                assert re.search(r"\bnever\b|\bnot\b", sentence), (owner, sentence)
    for status in PriceStatus:
        assert not re.search(r"hard|guarantee|invoice|cap", status.value)
