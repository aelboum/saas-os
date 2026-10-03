"""Phase 5.3 step 6 -- combining entitlements across live subscriptions
(ADR-0029 amendment, "Entitlements across merchants"), without a database."""

from __future__ import annotations

import math
from decimal import Decimal

import pytest
from core.billing.catalog import validate_entitlements
from core.billing.errors import InvalidCatalogValueError
from core.billing.service import combine_entitlements
from core.usage.service import _numeric_limit

from core.billing import service


def test_booleans_combine_with_or() -> None:
    assert combine_entitlements([{"reports": False}, {"reports": True}]) == {"reports": True}
    assert combine_entitlements([{"reports": False}, {"reports": False}]) == {"reports": False}


def test_numbers_combine_with_max_never_a_sum() -> None:
    assert combine_entitlements([{"api_calls": 100}, {"api_calls": 250}]) == {"api_calls": 250}
    assert combine_entitlements([{"seats": Decimal("2.5")}, {"seats": 2}]) == {
        "seats": Decimal("2.5")
    }


def test_only_plans_that_define_a_key_contribute() -> None:
    combined = combine_entitlements([{"api_calls": 100}, {"exports": True}])
    assert combined == {"api_calls": 100, "exports": True}


def test_a_number_wins_over_any_non_numeric_value_for_the_same_key() -> None:
    """Post-5.3 audit remediation R4: a newest non-numeric value no longer
    replaces an older numeric limit (it read as "no limit": unlimited)."""
    for newest in (True, False, None, "100", "unlimited", [1], {"max": 1}):
        combined = combine_entitlements([{"api_calls": newest}, {"api_calls": 100}])
        assert combined == {"api_calls": 100}, newest
        assert _numeric_limit(combined, "api_calls") == Decimal(100), newest
    assert combine_entitlements([{"x": True}, {"x": 5}, {"x": 7}]) == {"x": 7}


def test_booleans_still_combine_with_or_beside_invalid_legacy_values() -> None:
    assert combine_entitlements([{"reports": "yes"}, {"reports": True}]) == {"reports": True}


def test_only_invalid_legacy_values_keep_the_newest_and_set_no_limit() -> None:
    """Possible only in plans persisted before write validation: unchanged
    compatibility, and never a numeric limit."""
    combined = combine_entitlements([{"tier": "gold"}, {"tier": "silver"}])
    assert combined == {"tier": "gold"}
    assert _numeric_limit(combined, "tier") is None


def test_no_subscription_means_no_entitlements() -> None:
    assert combine_entitlements([]) == {}


# --- Write-boundary validation (post-5.3 audit remediation R4) -------------------------


def test_booleans_and_finite_non_negative_numbers_are_valid() -> None:
    entitlements = {"reports": True, "exports": False, "api_calls": 100, "storage_gb": 2.5, "x": 0}
    validated = validate_entitlements(entitlements)
    assert validated == entitlements and validated is not entitlements
    assert validate_entitlements(None) == {}


@pytest.mark.parametrize(
    "value",
    ["100", "unlimited", "", None, [1], {"max": 1}, -1, -0.5, math.nan, math.inf, Decimal("5")],
)
def test_anything_else_is_refused_not_converted(value: object) -> None:
    with pytest.raises(InvalidCatalogValueError) as excinfo:
        validate_entitlements({"api_calls": value})
    assert "api_calls" in str(excinfo.value)


@pytest.mark.parametrize("entitlements", [["api_calls"], "api_calls=1", {"": True}, {1: True}])
def test_the_mapping_and_its_keys_are_validated(entitlements: object) -> None:
    with pytest.raises(InvalidCatalogValueError):
        validate_entitlements(entitlements)


@pytest.mark.parametrize("value", ["100", None, [1]])
def test_the_legacy_create_plan_refuses_before_any_database_access(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    monkeypatch.setattr(service, "session_scope", lambda *_: pytest.fail("no DB access"))
    with pytest.raises(InvalidCatalogValueError):
        service.create_plan("legacy-plan", "Legacy", entitlements={"api_calls": value})
