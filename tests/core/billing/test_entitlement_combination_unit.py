"""Phase 5.3 step 6 -- combining entitlements across live subscriptions
(ADR-0029 amendment, "Entitlements across merchants"), without a database."""

from __future__ import annotations

from decimal import Decimal

from core.billing.service import combine_entitlements


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


def test_other_or_mixed_values_keep_the_newest() -> None:
    newest_first = [{"tier": "gold", "x": True}, {"tier": "silver", "x": 5}]
    assert combine_entitlements(newest_first) == {"tier": "gold", "x": True}


def test_no_subscription_means_no_entitlements() -> None:
    assert combine_entitlements([]) == {}
