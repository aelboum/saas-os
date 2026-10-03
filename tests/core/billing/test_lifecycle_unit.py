"""Billing Foundation v2 Phase 3 -- lifecycle safety, pure unit tests (no
database): the state machine, the provider-state mapping, the single
status-assignment point, the provider-neutral status boundary of both
adapters, provider idempotency in the fake adapter, and static guards against status mutation and
billing-inheritance use.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import stripe
from core.billing.errors import BillingProviderError, InvalidSubscriptionTransitionError
from core.billing.lifecycle import (
    ALLOWED_TRANSITIONS,
    ENTITLEMENT_GRANTING_STATUSES,
    LIVE_STATUSES,
    SubscriptionStatus,
    VerificationState,
    set_subscription_status,
    target_status_for,
    validate_transition,
)
from core.billing.models import Plan, Subscription
from core.billing.provider import FakeBillingProvider, ProviderSubscriptionState
from core.billing.service import cancel_at_provider
from core.billing.stripe_provider import StripeBillingProvider

from core.billing import stripe_provider

_BILLING_DIR = Path(__file__).resolve().parents[3] / "core" / "billing"

S = SubscriptionStatus


# --- State machine -----------------------------------------------------------


def test_allowed_transitions_are_exactly_the_documented_table() -> None:
    assert ALLOWED_TRANSITIONS == {
        S.PENDING: {S.ACTIVE, S.PAST_DUE, S.CANCELED},
        S.ACTIVE: {S.PAST_DUE, S.CANCELED},
        S.PAST_DUE: {S.ACTIVE, S.CANCELED},
        S.CANCELED: set(),
    }


def test_live_and_entitlement_granting_sets() -> None:
    assert LIVE_STATUSES == {S.PENDING, S.ACTIVE, S.PAST_DUE}
    assert ENTITLEMENT_GRANTING_STATUSES == {S.ACTIVE}
    assert {v.value for v in VerificationState} == {"verified", "legacy_unverified"}


@pytest.mark.parametrize("status", list(S))
def test_same_state_is_an_allowed_no_op(status: SubscriptionStatus) -> None:
    assert validate_transition(status.value, status) is status


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (S.ACTIVE, S.PENDING),
        (S.PAST_DUE, S.PENDING),
        (S.CANCELED, S.ACTIVE),
        (S.CANCELED, S.PENDING),
        (S.CANCELED, S.PAST_DUE),
    ],
)
def test_forbidden_transitions_are_rejected(
    current: SubscriptionStatus, target: SubscriptionStatus
) -> None:
    with pytest.raises(InvalidSubscriptionTransitionError):
        validate_transition(current.value, target)


def test_unrecognized_stored_status_is_rejected() -> None:
    with pytest.raises(InvalidSubscriptionTransitionError):
        validate_transition("trialing", S.ACTIVE)


def test_set_subscription_status_validates_and_reports_change() -> None:
    row = Subscription(status=S.PENDING.value)
    assert set_subscription_status(row, S.ACTIVE) is True
    assert row.status == "active"
    assert set_subscription_status(row, S.ACTIVE) is False
    set_subscription_status(row, S.CANCELED)
    with pytest.raises(InvalidSubscriptionTransitionError):
        set_subscription_status(row, S.ACTIVE)
    assert row.status == "canceled"


def test_provider_states_map_and_unconfirmable_states_never_do() -> None:
    assert target_status_for(ProviderSubscriptionState.ACTIVE) is S.ACTIVE
    assert target_status_for(ProviderSubscriptionState.PENDING) is S.PENDING
    assert target_status_for(ProviderSubscriptionState.PAST_DUE) is S.PAST_DUE
    assert target_status_for(ProviderSubscriptionState.CANCELED) is S.CANCELED
    assert target_status_for(ProviderSubscriptionState.NOT_FOUND) is None
    assert target_status_for(ProviderSubscriptionState.UNKNOWN) is None


# --- Static guards -------------------------------------------------------------


def _status_assignments(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    targets = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "status"
                    and ast.unparse(target.value) != "self"  # an error's own attribute
                ):
                    targets.append(ast.unparse(target.value))
    return targets


def test_subscription_status_is_assigned_only_by_the_lifecycle_module() -> None:
    """No billing code mutates a status by assignment except
    `lifecycle.set_subscription_status()` (subscriptions), the merchant
    status setter in `parties.py`, and the catalog's own plan withdrawal and
    offer revocation (`catalog.py`, Catalog v2) -- and no product/API code
    at all."""
    offenders = {}
    for path in sorted(_BILLING_DIR.glob("*.py")):
        found = _status_assignments(path)
        if found:
            offenders[path.name] = found
    assert offenders == {
        "catalog.py": ["plan", "offer"],
        "lifecycle.py": ["subscription"],
        "parties.py": ["merchant"],
    }


def test_commercial_rows_are_only_ever_inserted_pending() -> None:
    tree = ast.parse((_BILLING_DIR / "commercial.py").read_text(encoding="utf-8"))
    statuses = [
        ast.unparse(keyword.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "Subscription"
        for keyword in node.keywords
        if keyword.arg == "status"
    ]
    assert statuses == ["SubscriptionStatus.PENDING.value"]


@pytest.mark.parametrize("module", ["lifecycle.py", "commercial.py"])
def test_lifecycle_code_never_consults_billing_inheritance(module: str) -> None:
    source = (_BILLING_DIR / module).read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {
        node.attr if isinstance(node, ast.Attribute) else node.id
        for node in ast.walk(tree)
        if isinstance(node, (ast.Attribute, ast.Name))
    }
    forbidden = {"resolve_billing_owner", "get_ancestor_chain"}
    if module != "commercial.py":
        # commercial.py may read `inherits_billing` only to refuse it and
        # assign it only `False` (Phase 5.3 step 5) -- pinned by
        # test_commercial_parties_unit.py.
        forbidden.add("inherits_billing")
    assert not names & forbidden


@pytest.mark.parametrize("module", ["lifecycle.py", "commercial.py", "provider.py"])
def test_no_provider_specific_type_leaks_into_core_lifecycle(module: str) -> None:
    tree = ast.parse((_BILLING_DIR / module).read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not {name for name in imported if "stripe" in name}


# --- Provider adapters: provider-neutral status boundary ----------------------


def test_shipped_adapters_explicitly_declare_honoring_idempotency_keys() -> None:
    assert FakeBillingProvider.honors_idempotency_keys is True
    assert StripeBillingProvider.honors_idempotency_keys is True


def test_fake_provider_honours_idempotency_keys() -> None:
    provider = FakeBillingProvider()
    plan = Plan(key="p", name="P")
    first = provider.create_subscription(tenant_id=uuid.uuid4(), plan=plan, idempotency_key="k")
    again = provider.create_subscription(tenant_id=uuid.uuid4(), plan=plan, idempotency_key="k")
    other = provider.create_subscription(tenant_id=uuid.uuid4(), plan=plan, idempotency_key="k2")
    assert first == again != other


def test_fake_provider_reports_controlled_states_and_outages() -> None:
    provider = FakeBillingProvider(initial_state=ProviderSubscriptionState.PENDING)
    sub_id = provider.create_subscription(tenant_id=uuid.uuid4(), plan=Plan(key="p", name="P"))
    assert provider.get_subscription_status(provider_subscription_id=sub_id) == "pending"
    provider.set_state(sub_id, ProviderSubscriptionState.ACTIVE)
    assert provider.get_subscription_status(provider_subscription_id=sub_id) == "active"
    assert provider.get_subscription_status(provider_subscription_id="nope") == "not_found"
    provider.status_unavailable = True
    with pytest.raises(BillingProviderError):
        provider.get_subscription_status(provider_subscription_id=sub_id)


class _FakeStripeSubscriptions:
    def __init__(self, *, status: str | None = None, error: Exception | None = None) -> None:
        self.status = status
        self.error = error
        self.create_options: list[Any] = []

    def retrieve(self, _id: str) -> Any:
        if self.error is not None:
            raise self.error
        return SimpleNamespace(status=self.status)

    def create(self, params: Any = None, options: Any = None) -> Any:
        self.create_options.append(options)
        return SimpleNamespace(id="sub_123")


def _stripe_adapter(subscriptions: _FakeStripeSubscriptions) -> tuple[StripeBillingProvider, Any]:
    adapter = StripeBillingProvider.__new__(StripeBillingProvider)
    customers = _FakeStripeSubscriptions()
    customers.create = lambda params=None, options=None: (  # type: ignore[method-assign]
        customers.create_options.append(options) or SimpleNamespace(id="cus_1")
    )
    adapter._client = SimpleNamespace(  # type: ignore[attr-defined]
        v1=SimpleNamespace(subscriptions=subscriptions, customers=customers)
    )
    return adapter, customers


@pytest.mark.parametrize(
    ("stripe_status", "expected"),
    [
        ("active", ProviderSubscriptionState.ACTIVE),
        ("incomplete", ProviderSubscriptionState.PENDING),
        ("past_due", ProviderSubscriptionState.PAST_DUE),
        ("unpaid", ProviderSubscriptionState.PAST_DUE),
        ("canceled", ProviderSubscriptionState.CANCELED),
        ("incomplete_expired", ProviderSubscriptionState.CANCELED),
        ("trialing", ProviderSubscriptionState.UNKNOWN),
        ("paused", ProviderSubscriptionState.UNKNOWN),
        ("some_future_status", ProviderSubscriptionState.UNKNOWN),
    ],
)
def test_stripe_statuses_translate_to_neutral_states(
    stripe_status: str, expected: ProviderSubscriptionState
) -> None:
    adapter, _ = _stripe_adapter(_FakeStripeSubscriptions(status=stripe_status))
    state = adapter.get_subscription_status(provider_subscription_id="sub_1")
    assert state is expected
    assert type(state) is ProviderSubscriptionState


def test_stripe_missing_subscription_is_not_found_and_other_errors_raise() -> None:
    missing = stripe.InvalidRequestError(
        "No such subscription", param="id", code="resource_missing"
    )
    adapter, _ = _stripe_adapter(_FakeStripeSubscriptions(error=missing))
    assert adapter.get_subscription_status(provider_subscription_id="x") is (
        ProviderSubscriptionState.NOT_FOUND
    )
    adapter, _ = _stripe_adapter(_FakeStripeSubscriptions(error=stripe.APIConnectionError("down")))
    with pytest.raises(BillingProviderError):
        adapter.get_subscription_status(provider_subscription_id="x")


def test_stripe_forwards_a_per_request_idempotency_key() -> None:
    subscriptions = _FakeStripeSubscriptions()
    adapter, customers = _stripe_adapter(subscriptions)
    plan = Plan(key="p", name="P", provider_price_id="price_1")
    assert (
        adapter.create_subscription(tenant_id=uuid.uuid4(), plan=plan, idempotency_key="op-1")
        == "sub_123"
    )
    assert customers.create_options == [{"idempotency_key": "op-1:customer"}]
    assert subscriptions.create_options == [{"idempotency_key": "op-1:subscription"}]
    assert stripe_provider._STRIPE_STATES["active"] is ProviderSubscriptionState.ACTIVE


# --- cancel_at_provider: tolerate only a confirmed provider-side cancellation -----


class _CancelRejectingProvider(FakeBillingProvider):
    def cancel_subscription(self, *, provider_subscription_id: str) -> None:
        raise BillingProviderError("cancel_subscription", "rejected")


def _subscription(provider: FakeBillingProvider) -> str:
    return provider.create_subscription(tenant_id=uuid.uuid4(), plan=Plan(key="p", name="P"))


def test_cancel_at_provider_succeeds_normally() -> None:
    provider = FakeBillingProvider()
    sub = _subscription(provider)
    cancel_at_provider(provider, sub)
    assert provider.get_subscription_status(provider_subscription_id=sub) is (
        ProviderSubscriptionState.CANCELED
    )


def test_cancel_at_provider_tolerates_a_confirmed_prior_cancellation() -> None:
    provider = _CancelRejectingProvider()
    sub = _subscription(provider)
    provider.set_state(sub, ProviderSubscriptionState.CANCELED)
    cancel_at_provider(provider, sub)  # no error


@pytest.mark.parametrize(
    "state",
    [
        ProviderSubscriptionState.NOT_FOUND,
        ProviderSubscriptionState.ACTIVE,
        ProviderSubscriptionState.PAST_DUE,
        ProviderSubscriptionState.UNKNOWN,
    ],
)
def test_cancel_at_provider_reraises_on_anything_but_confirmed_canceled(
    state: ProviderSubscriptionState,
) -> None:
    provider = _CancelRejectingProvider()
    sub = _subscription(provider)
    provider.set_state(sub, state)
    with pytest.raises(BillingProviderError):
        cancel_at_provider(provider, sub)


def test_cancel_at_provider_reraises_when_the_provider_cannot_be_asked() -> None:
    provider = _CancelRejectingProvider()
    sub = _subscription(provider)
    provider.status_unavailable = True
    with pytest.raises(BillingProviderError):
        cancel_at_provider(provider, sub)
