"""The monetary AI budget's pure parts (ADR-0054 amendment of 2026-11-10; Gap
21b). No database: the worst-case cost against an independent `Decimal`
oracle, the effective limit rules (owner decisions 3 and 10), the
`AI_INFERENCE_BUDGET_REQUIRED` setting, and the honesty rule (Gap 21
acceptance criterion 13: nothing claims a hard, guaranteed or invoice cap).
"""

from __future__ import annotations

import inspect
import re
import uuid
from decimal import ROUND_CEILING, Decimal
from types import SimpleNamespace

import pytest

from saas_os.control_plane.inference import budget, budget_admin, budget_models
from saas_os.control_plane.inference.budget import (
    BUDGET_REASONS,
    BudgetParts,
    BudgetSource,
    budget_required,
    effective_limit,
    worst_case_cost,
)
from saas_os.control_plane.inference.errors import InferenceInternalError

_Q = Decimal("0.00000001")


def _price(**rates: Decimal | None) -> SimpleNamespace:
    values: dict[str, Decimal | None] = {
        "input_per_million": Decimal("3"),
        "output_per_million": Decimal("15"),
        "cached_input_per_million": None,
        "cache_write_per_million": None,
        "per_request": None,
    }
    values.update(rates)
    return SimpleNamespace(id=uuid.uuid4(), currency="USD", pricing_version="v1", **values)


def _oracle(price: SimpleNamespace, input_bytes: int, max_output: int) -> Decimal:
    rates = [price.input_per_million]
    rates += [r for r in (price.cached_input_per_million, price.cache_write_per_million) if r]
    tokens_in = Decimal(input_bytes if input_bytes > 0 else 1)
    total = (tokens_in * max(rates) + Decimal(max_output) * price.output_per_million) / Decimal(
        10**6
    )
    if price.per_request is not None:
        total += price.per_request
    return total.quantize(_Q, rounding=ROUND_CEILING)


@pytest.mark.parametrize(
    ("rates", "input_bytes", "max_output"),
    [
        ({}, 1000, 512),
        ({}, 0, 1),
        ({"cached_input_per_million": Decimal("0.3")}, 4096, 4096),
        ({"cached_input_per_million": Decimal("9")}, 7, 3),
        ({"cache_write_per_million": Decimal("3.75")}, 333, 77),
        ({"per_request": Decimal("0.002")}, 1, 1),
        ({"input_per_million": Decimal("0.00000001")}, 1, 1),
        ({"output_per_million": Decimal("1000000")}, 1_000_000, 128_000),
    ],
)
def test_the_worst_case_matches_an_independent_oracle(
    rates: dict[str, Decimal], input_bytes: int, max_output: int
) -> None:
    price = _price(**rates)
    got = worst_case_cost(price, input_bytes=input_bytes, max_output_tokens=max_output)  # type: ignore[arg-type]
    assert got == _oracle(price, input_bytes, max_output)
    assert got.as_tuple().exponent == -8


def test_the_worst_case_rounds_up_never_down() -> None:
    # 1 byte at 0.00000001 per million is 1e-14: rounded up to 1e-8, not to 0.
    price = _price(input_per_million=Decimal("0.00000001"), output_per_million=Decimal(0))
    assert worst_case_cost(price, input_bytes=1, max_output_tokens=1) == _Q  # type: ignore[arg-type]


def test_the_worst_case_takes_the_highest_input_side_rate() -> None:
    plain = worst_case_cost(_price(), input_bytes=1_000_000, max_output_tokens=1)  # type: ignore[arg-type]
    dearer_cache = worst_case_cost(
        _price(cache_write_per_million=Decimal("6")),  # type: ignore[arg-type]
        input_bytes=1_000_000,
        max_output_tokens=1,
    )
    assert dearer_cache - plain == Decimal("3")


def _parts(
    *,
    plan: str | None = None,
    override: str | None = None,
    cap: str | None = None,
) -> BudgetParts:
    def dec(value: str | None) -> Decimal | None:
        return None if value is None else Decimal(value)

    return BudgetParts(
        currency="EUR" if (plan or override or cap) else None,
        plan=dec(plan),
        plan_version="v1" if plan else None,
        override=dec(override),
        override_expires_at=None,
        cap=dec(cap),
    )


@pytest.mark.parametrize(
    ("parts", "frozen", "expected", "source"),
    [
        # nothing configured: no limit
        (_parts(), None, None, None),
        # the plan budget alone
        (_parts(plan="100"), None, Decimal("100"), BudgetSource.PLAN),
        # a lower plan budget mid-month applies at once (decision 10)
        (_parts(plan="50"), Decimal("100"), Decimal("50"), BudgetSource.PLAN),
        # a higher plan budget mid-month waits for the next month
        (_parts(plan="500"), Decimal("100"), Decimal("100"), BudgetSource.PLAN),
        # the plan disappeared mid-month: the frozen part still bounds it
        (_parts(cap="1000"), Decimal("100"), Decimal("100"), BudgetSource.PLAN),
        # an operator override replaces the plan part, upwards too (decision 3)
        (_parts(plan="100", override="300"), Decimal("100"), Decimal("300"), BudgetSource.OVERRIDE),
        # a tenant cap lowers the limit
        (_parts(plan="100", cap="40"), None, Decimal("40"), BudgetSource.TENANT_CAP),
        # a tenant cap above the plan changes nothing
        (_parts(plan="100", cap="400"), None, Decimal("100"), BudgetSource.PLAN),
        # a tenant cap above an override changes nothing; below it, it applies
        (_parts(override="300", cap="400"), None, Decimal("300"), BudgetSource.OVERRIDE),
        (_parts(override="300", cap="200"), None, Decimal("200"), BudgetSource.TENANT_CAP),
        # a cap alone is a budget
        (_parts(cap="25"), None, Decimal("25"), BudgetSource.TENANT_CAP),
        # a zero budget refuses everything later, it is not "no budget"
        (_parts(plan="0"), None, Decimal("0"), BudgetSource.PLAN),
    ],
)
def test_the_effective_limit_follows_the_owner_decisions(
    parts: BudgetParts,
    frozen: Decimal | None,
    expected: Decimal | None,
    source: BudgetSource | None,
) -> None:
    assert effective_limit(parts, frozen) == (expected, source)


def test_a_tenant_can_only_lower_its_budget() -> None:
    for cap in ("0", "1", "99.99999999", "100", "100.00000001", "1000000"):
        limit, _ = effective_limit(_parts(plan="100", cap=cap), None)
        assert limit is not None and limit <= Decimal("100")


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", " FALSE "])
def test_the_requirement_is_off_by_default_and_when_false(value: str) -> None:
    assert budget_required({"AI_INFERENCE_BUDGET_REQUIRED": value}) is False
    assert budget_required({}) is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", " True "])
def test_the_requirement_is_on_when_true(value: str) -> None:
    assert budget_required({"AI_INFERENCE_BUDGET_REQUIRED": value}) is True


@pytest.mark.parametrize("value", ["maybe", "2", "enabled", "tru"])
def test_any_other_value_of_the_requirement_refuses(value: str) -> None:
    with pytest.raises(InferenceInternalError) as raised:
        budget_required({"AI_INFERENCE_BUDGET_REQUIRED": value})
    assert raised.value.reason == "invalid_ai_inference_budget_required"


def test_the_refusal_reasons_are_a_closed_set() -> None:
    assert (
        frozenset(
            {
                "monthly_budget_exhausted",
                "budget_pricing_unavailable",
                "budget_currency_conflict",
                "budget_unavailable",
                "budget_not_configured",
            }
        )
        == BUDGET_REASONS
    )


@pytest.mark.parametrize(
    "amount",
    [Decimal("-1"), Decimal("NaN"), Decimal("Infinity"), Decimal("1.000000001"), 5, 1.5, "3"],
)
def test_invalid_amounts_are_refused(amount: object) -> None:
    with pytest.raises(budget_admin.AIBudgetError) as raised:
        budget_admin._amount(amount)  # pyright: ignore[reportPrivateUsage]
    assert raised.value.reason == "invalid_amount"


def test_the_largest_amount_fits_the_column() -> None:
    assert budget_admin._amount(budget_admin.MAX_AMOUNT) == budget_admin.MAX_AMOUNT  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(budget_admin.AIBudgetError):
        budget_admin._amount(budget_admin.MAX_AMOUNT + _Q)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("currency", ["usd", "US", "USDX", "", None, "U$D"])
def test_invalid_currencies_are_refused(currency: object) -> None:
    with pytest.raises(budget_admin.AIBudgetError) as raised:
        budget_admin._currency(currency)  # pyright: ignore[reportPrivateUsage]
    assert raised.value.reason == "invalid_currency"


_PROHIBITED = re.compile(
    r"\bhard[- ](cap|ceiling|limit|spending)|\bguarantee|\binvoice[- ](cap|limit)|"
    r"\bcaps? (the )?invoice",
    re.IGNORECASE,
)


def test_no_public_text_of_the_budget_claims_a_hard_or_invoice_cap() -> None:
    """Acceptance criterion 13: docstrings and refusal codes never call the
    budget a hard, guaranteed or invoice cap; it limits estimated platform
    spend."""
    texts: list[str] = []
    for module in (budget, budget_admin, budget_models):
        texts.append(inspect.getdoc(module) or "")
        for _, member in inspect.getmembers(module):
            if (inspect.isfunction(member) or inspect.isclass(member)) and (
                getattr(member, "__module__", None) == module.__name__
            ):
                texts.append(inspect.getdoc(member) or "")
    texts.extend(BUDGET_REASONS)
    offending = [t for t in texts if _PROHIBITED.search(t)]
    assert offending == []
    assert "estimated platform spend" in (inspect.getdoc(budget) or "").lower()
