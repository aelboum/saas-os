"""The authorized commercial subscription entry points (Billing Foundation
v2 Phase 2 + Phase 3; docs/ADR/0029-commercial-parties-and-billing-
relationships.md).

`create_subscription()` creates a subscription with three explicitly
named parties:

    service tenant  -- `Subscription.tenant_id`: receives the service and
                       its entitlements; the subscription's RLS owner.
    payer           -- `(payer_tenant_id, billing_account_id)`: the
                       `BillingAccount` that is charged.
    payee           -- the billing account's merchant, recorded as
                       `Subscription.merchant_account_id` and guaranteed
                       by a composite foreign key to be that account's
                       own merchant.

**Dual authorization** (ADR-0029, invariant 6), both through
`core.rbac.can()` (`core/billing/authorization.py`):

    billing.account:charge        on the payer tenant
    billing.subscription:create   on the service tenant

The payer is never trusted because it was supplied: the caller must hold
`charge` on the payer tenant, and the billing account must actually belong
to that payer (it is read under the payer's own RLS scope). A denial is
the same `BillingNotAuthorizedError` whichever check failed.

**Lifecycle safety (Phase 3; `core/billing/lifecycle.py`).** Creation is

    authorize -> resolve payer/merchant/plan -> reserve idempotency
      -> provider creates (with a stable provider idempotency key)
      -> provider reference registered -> local row written as `pending`
      -> provider asked for its authoritative status -> transition

A subscription is `active` only when the provider positively confirms an
active state. Inserting the local row never activates anything: the row
is always written `pending`, and only `_apply_provider_state()` moves it,
through a validated transition, from a provider-confirmed state. If the
provider reports anything else, or cannot be asked, the row stays
`pending` (or moves to the confirmed non-active state) and the caller
receives that state -- the provider object is never deleted, and
`reconcile_subscription_status()` re-asks later.

**Provider idempotency.** The provider idempotency key and the local
subscription id are both derived from the `core.idempotency` reservation
record's id -- one durable row per `(service tenant, operation, client
idempotency key, request fingerprint)`, persisted in PostgreSQL. A retry
of the same logical request therefore sends the provider the same key
(the provider returns the subscription it already created), registers
the identical provider reference (idempotent), and resolves to the same
local row, across process restarts. Concurrent duplicates block on the
reservation itself (`IdempotencyInProgressError`); reusing a client key
for a different request fails (`IdempotencyKeyReusedError`).

**One live subscription per (service tenant, merchant).** Enforced by the
partial unique index `uq_billing_subscriptions_one_live_per_merchant`; an
application pre-check only gives a clearer error earlier. A race lost at
the index maps to `LiveSubscriptionExistsError`. If two *different*
requests race past the pre-check, the loser's provider subscription
already exists when the index rejects its local row: it is not deleted
(a provider object is never removed automatically), and its provider
reference stays registered, pointing at no local row, for later
reconciliation (Billing Foundation v2 Phase 6).

**Legacy rows.** `reconcile_legacy_subscription()` is the only way a
`legacy_unverified` row becomes `verified`: an authorized caller supplies
the authoritative payer billing account, the provider must confirm the
subscription exists, and only then are payer, merchant and provider
recorded on it. See that function.

**Scope boundaries kept** (later phases change them, not this one):

- Until Catalog v2 gives plans an owner and a merchant, every plan is sold
  only by a merchant owned by the platform tenant
  (`core.tenancy.get_platform_tenant_id()`); a billing account at any
  other merchant is rejected (`MerchantNotEligibleForPlanError`).
- The provider adapter must be the merchant's provider
  (`BillingProviderMismatchError`); the deployment's Stripe default is only
  constructed for a `"stripe"` merchant.
- No provider-event ingestion: status changes are learned synchronously,
  on creation and on `reconcile_subscription_status()`.
- No provider customer is recorded on the billing account.

**`inherits_billing` is never used to decide a payer.** A service tenant
that inherits billing is refused (`require_service_tenant_owns_billing()`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from core.audit_log import AuditOutcome
from core.audit_log import record as record_audit_event
from core.billing.authorization import (
    BILLING_ACCOUNT,
    BILLING_SUBSCRIPTION,
    BillingCaller,
    audit_actor,
    authorize_billing,
)
from core.billing.errors import (
    BillingProviderContractError,
    BillingProviderError,
    BillingProviderMismatchError,
    LegacyReconciliationError,
    LiveSubscriptionExistsError,
    MerchantNotEligibleForPlanError,
    ProviderReferenceMismatchError,
    ProviderRefNotFoundError,
    SubscriptionNotFoundError,
)
from core.billing.lifecycle import (
    LIVE_STATUSES,
    SubscriptionStatus,
    VerificationState,
    is_transition_allowed,
    parse_status,
    set_subscription_status,
    target_status_for,
)
from core.billing.models import BillingAccount, MerchantAccount, Subscription
from core.billing.parties import (
    get_billing_account,
    get_merchant_account,
    require_active_billing_account,
    require_active_merchant_account,
)
from core.billing.provider import BillingProvider, ProviderSubscriptionState
from core.billing.provider_refs import (
    LocalObjectType,
    ProviderObjectType,
    find_provider_object_ref,
    register_provider_ref,
    resolve_provider_ref,
)
from core.billing.service import (
    SubscribeResult,
    _default_provider,
    cancel_at_provider,
    get_plan,
    provider_name,
    require_service_tenant_owns_billing,
)
from core.idempotency import (
    IdempotencyStatus,
    begin_idempotent_operation,
    finalize_idempotent_operation,
)
from core.tenancy import get_platform_tenant_id, require_open_tenant
from infra.db import IntegrityError, select, tenant_session_scope

_OPERATION = "billing.subscription.create"
_ONE_LIVE_INDEX = "uq_billing_subscriptions_one_live_per_merchant"
_STRIPE = "stripe"
# Namespace for the deterministic local subscription id derived from the
# idempotency reservation (a fixed, arbitrary UUID -- never changes).
_SUBSCRIPTION_ID_NAMESPACE = uuid.UUID("5a3f1c2e-8b7d-4e61-9c0a-2f4d6b8e1a37")


@dataclass(frozen=True)
class SubscriptionReconciliation:
    """Outcome of one synchronous reconciliation against the provider."""

    subscription_id: uuid.UUID
    previous_status: str
    status: str
    provider_state: ProviderSubscriptionState
    changed: bool


# --- Shared resolution ------------------------------------------------------


def _resolve_merchant_context(
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_key: str,
    provider: BillingProvider | None,
) -> tuple[BillingAccount, MerchantAccount, BillingProvider]:
    account = require_active_billing_account(
        get_billing_account(payer_tenant_id, billing_account_id)
    )
    merchant = require_active_merchant_account(
        get_merchant_account(account.merchant_tenant_id, account.merchant_account_id)
    )
    if merchant.tenant_id != get_platform_tenant_id():
        raise MerchantNotEligibleForPlanError(merchant.id, plan_key)
    return account, merchant, _adapter_for(merchant.provider, provider)


def _adapter_for(expected: str | None, provider: BillingProvider | None) -> BillingProvider:
    if provider is not None:
        active_provider = provider
    elif expected == _STRIPE:
        active_provider = _default_provider()
    else:
        raise BillingProviderMismatchError(str(expected), None)
    adapter_name = provider_name(active_provider)
    if adapter_name != expected:
        raise BillingProviderMismatchError(str(expected), adapter_name)
    return active_provider


def _live_subscription_exists(service_tenant_id: uuid.UUID, merchant_account_id: uuid.UUID) -> bool:
    """Advisory pre-check only -- the partial unique index is authoritative."""
    with tenant_session_scope(service_tenant_id) as session:
        found = session.execute(
            select(Subscription.id).where(
                Subscription.tenant_id == service_tenant_id,
                Subscription.merchant_account_id == merchant_account_id,
                Subscription.status.in_([s.value for s in LIVE_STATUSES]),
            )
        ).first()
        return found is not None


def _violates_one_live_invariant(exc: IntegrityError) -> bool:
    """Whether a unique violation came from the one-live-subscription
    index (and not from any other constraint, which is re-raised as is)."""
    diag = getattr(getattr(exc, "orig", None), "diag", None)
    return getattr(diag, "constraint_name", None) == _ONE_LIVE_INDEX


def _load(service_tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> Subscription:
    with tenant_session_scope(service_tenant_id) as session:
        row = session.get(Subscription, subscription_id)
        if row is None or row.tenant_id != service_tenant_id:
            raise SubscriptionNotFoundError(service_tenant_id, subscription_id)
        session.expunge(row)
        return row


def _verify_provider_reference(row: Subscription) -> None:
    """Re-check a verified subscription's provider identity through the
    Phase 2 provider-reference index before any provider answer is applied
    to it: the payer's billing account (read under the payer's own RLS
    scope) names the merchant, whose provider account plus the row's
    provider and provider subscription id must resolve back to exactly this
    row in this tenant. Anything else -- no mapping, a mapping to another
    tenant or row, a missing account -- raises
    `ProviderReferenceMismatchError`. Provider-side metadata is never
    consulted."""
    if (
        row.provider is None
        or row.payer_tenant_id is None
        or row.billing_account_id is None
        or row.merchant_account_id is None
    ):
        raise ProviderReferenceMismatchError(row.id)
    try:
        account = get_billing_account(row.payer_tenant_id, row.billing_account_id)
        merchant = get_merchant_account(account.merchant_tenant_id, account.merchant_account_id)
        resolution = resolve_provider_ref(
            provider=row.provider,
            provider_account_ref=merchant.provider_account_ref,
            object_type=ProviderObjectType.SUBSCRIPTION,
            provider_object_ref=row.provider_subscription_id,
        )
    except (LookupError, ProviderRefNotFoundError):
        raise ProviderReferenceMismatchError(row.id) from None
    if (
        merchant.id != row.merchant_account_id
        or resolution.tenant_id != row.tenant_id
        or resolution.local_object_type is not LocalObjectType.BILLING_SUBSCRIPTION
        or resolution.local_object_id != row.id
    ):
        raise ProviderReferenceMismatchError(row.id)


def _apply_provider_state(
    service_tenant_id: uuid.UUID, subscription_id: uuid.UUID, state: ProviderSubscriptionState
) -> tuple[Subscription, str, bool]:
    """Move the row to the status the provider confirmed, if that is an
    allowed transition. `not_found`/`unknown`, or a transition the
    lifecycle forbids (e.g. resurrecting `canceled`), change nothing.
    Returns `(row, previous_status, changed)`."""
    target = target_status_for(state)
    with tenant_session_scope(service_tenant_id) as session:
        row = session.get(Subscription, subscription_id, with_for_update=True)
        if row is None or row.tenant_id != service_tenant_id:
            raise SubscriptionNotFoundError(service_tenant_id, subscription_id)
        previous = row.status
        changed = False
        if target is not None and is_transition_allowed(parse_status(previous), target):
            changed = set_subscription_status(row, target)
            session.flush()
            session.refresh(row)
        session.expunge(row)
    return row, previous, changed


# --- Creation ---------------------------------------------------------------


def create_subscription(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_key: str,
    idempotency_key: str,
    provider: BillingProvider | None = None,
) -> tuple[bool, SubscribeResult]:
    """Create a subscription for `service_tenant_id`, paid through
    `payer_tenant_id`'s billing account `billing_account_id`, against
    `plan_key`. `caller` is a `BillingActor` or an explicit
    `trusted_system(reason)` -- never `None`. Returns `(is_replay, result)`
    where `result.status` is the provider-confirmed lifecycle status:
    `active` only on positive provider confirmation, otherwise `pending`
    (or the confirmed non-active status). A replay returns the row's
    *current* state, not a stale copy. See the module docstring."""
    validated = authorize_billing(
        caller,
        [
            (payer_tenant_id, BILLING_ACCOUNT, "charge"),
            (service_tenant_id, BILLING_SUBSCRIPTION, "create"),
        ],
        operation=_OPERATION,
    )
    service_tenant = require_open_tenant(service_tenant_id)
    require_open_tenant(payer_tenant_id)
    require_service_tenant_owns_billing(service_tenant)

    account, merchant, active_provider = _resolve_merchant_context(
        payer_tenant_id, billing_account_id, plan_key, provider
    )
    if getattr(active_provider, "honors_idempotency_keys", False) is not True:
        raise BillingProviderContractError(provider_name(active_provider))
    plan = get_plan(plan_key)

    reservation = begin_idempotent_operation(
        service_tenant_id,
        _OPERATION,
        idempotency_key,
        {
            "plan_key": plan_key,
            "payer_tenant_id": str(payer_tenant_id),
            "billing_account_id": str(billing_account_id),
        },
    )
    if reservation.is_replay:
        assert reservation.result is not None
        stored = SubscribeResult.from_dict(reservation.result)
        return True, SubscribeResult.from_subscription(
            _load(service_tenant_id, stored.subscription_id)
        )

    operation_id = reservation.record_id
    subscription_id = uuid.uuid5(_SUBSCRIPTION_ID_NAMESPACE, str(operation_id))
    try:
        existing = _find_by_id(service_tenant_id, subscription_id)
        # Recovery: if an earlier attempt of this same operation already got a
        # provider subscription and durably recorded it -- on the local row,
        # or in the provider-reference index registered for this local id --
        # reuse it. The provider is not asked to create again, so a retry can
        # never create a second provider subscription, however long after the
        # provider's own idempotency window. Only a crash between the
        # provider call returning and the reference being registered leaves
        # nothing durable, and that window is covered by the provider
        # idempotency key alone.
        if existing is not None:
            provider_subscription_id = existing.provider_subscription_id
        else:
            recorded = find_provider_object_ref(
                provider=merchant.provider,
                provider_account_ref=merchant.provider_account_ref,
                object_type=ProviderObjectType.SUBSCRIPTION,
                tenant_id=service_tenant_id,
                local_object_type=LocalObjectType.BILLING_SUBSCRIPTION,
                local_object_id=subscription_id,
            )
            if recorded is None and _live_subscription_exists(service_tenant_id, merchant.id):
                raise LiveSubscriptionExistsError(service_tenant_id, merchant.id)
            provider_subscription_id = recorded or active_provider.create_subscription(
                tenant_id=payer_tenant_id,
                plan=plan,
                idempotency_key=f"saas-os:{_OPERATION}:{operation_id}",
            )
        register_provider_ref(
            provider=merchant.provider,
            provider_account_ref=merchant.provider_account_ref,
            object_type=ProviderObjectType.SUBSCRIPTION,
            provider_object_ref=provider_subscription_id,
            tenant_id=service_tenant_id,
            local_object_type=LocalObjectType.BILLING_SUBSCRIPTION,
            local_object_id=subscription_id,
        )
        if existing is None:
            _insert_pending(
                subscription_id=subscription_id,
                service_tenant_id=service_tenant_id,
                plan_id=plan.id,
                provider_subscription_id=provider_subscription_id,
                account=account,
                merchant=merchant,
            )
    except Exception:
        finalize_idempotent_operation(
            service_tenant_id, reservation.record_id, status=IdempotencyStatus.FAILED
        )
        raise

    # Confirmation: the only path from `pending` to anything else. A
    # provider that cannot be asked leaves the row `pending` -- never active.
    try:
        state = active_provider.get_subscription_status(
            provider_subscription_id=provider_subscription_id
        )
    except BillingProviderError:
        state = None
    if state is not None:
        subscription, _, _ = _apply_provider_state(service_tenant_id, subscription_id, state)
    else:
        subscription = _load(service_tenant_id, subscription_id)

    actor_type, actor_user_id, extra = audit_actor(validated)
    record_audit_event(
        tenant_id=service_tenant_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action="billing.subscription_created",
        resource_type="billing_subscription",
        resource_id=str(subscription.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "plan_key": plan_key,
            "payer_tenant_id": str(payer_tenant_id),
            "billing_account_id": str(account.id),
            "merchant_account_id": str(merchant.id),
            "status": subscription.status,
            "provider_state": state.value if state is not None else "unavailable",
            **extra,
        },
    )
    if payer_tenant_id != service_tenant_id:
        # The payer is charged for a subscription it does not hold -- it
        # gets its own audit record, under its own tenant.
        record_audit_event(
            tenant_id=payer_tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            action="billing.subscription_charged_to_account",
            resource_type="billing_account",
            resource_id=str(account.id),
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "plan_key": plan_key,
                "service_tenant_id": str(service_tenant_id),
                "subscription_id": str(subscription.id),
                **extra,
            },
        )

    result = SubscribeResult.from_subscription(subscription)
    finalize_idempotent_operation(
        service_tenant_id,
        reservation.record_id,
        status=IdempotencyStatus.SUCCEEDED,
        result=result.to_dict(),
    )
    return False, result


def _find_by_id(service_tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> Subscription | None:
    try:
        return _load(service_tenant_id, subscription_id)
    except SubscriptionNotFoundError:
        return None


def _insert_pending(
    *,
    subscription_id: uuid.UUID,
    service_tenant_id: uuid.UUID,
    plan_id: uuid.UUID,
    provider_subscription_id: str,
    account: BillingAccount,
    merchant: MerchantAccount,
) -> None:
    """Write the local row -- always `pending`, never `active`. A unique
    violation is either the live-subscription index (a concurrent request
    won) or, after a crash, this same row already existing; the latter is
    re-read and accepted, the former is `LiveSubscriptionExistsError`."""
    try:
        with tenant_session_scope(service_tenant_id) as session:
            session.add(
                Subscription(
                    id=subscription_id,
                    tenant_id=service_tenant_id,
                    plan_id=plan_id,
                    status=SubscriptionStatus.PENDING.value,
                    provider_subscription_id=provider_subscription_id,
                    payer_tenant_id=account.tenant_id,
                    billing_account_id=account.id,
                    merchant_account_id=merchant.id,
                    provider=merchant.provider,
                    verification=VerificationState.VERIFIED.value,
                )
            )
            session.flush()
    except IntegrityError as exc:
        existing = _find_by_id(service_tenant_id, subscription_id)
        if existing is not None and existing.provider_subscription_id == provider_subscription_id:
            return
        if _violates_one_live_invariant(exc):
            raise LiveSubscriptionExistsError(service_tenant_id, merchant.id) from None
        raise


# --- Synchronous reconciliation -------------------------------------------------


def reconcile_subscription_status(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    provider: BillingProvider | None = None,
) -> SubscriptionReconciliation:
    """Reconcile one *verified* commercial subscription with its provider:
    the Phase 3 synchronous reconciliation boundary (no provider events
    yet). Requires `billing.subscription:read` on the service tenant; the
    caller chooses nothing about the resulting status.

        local row (service tenant's RLS scope)
          -> provider reference re-verified (`_verify_provider_reference`)
          -> provider's authoritative state
          -> mapped onto the lifecycle
          -> applied only through an allowed transition

    Fails closed at every step: a provider reference that does not resolve
    back to this row raises `ProviderReferenceMismatchError`; a provider
    error raises `BillingProviderError`; `not_found`/`unknown` and
    lifecycle-forbidden transitions change nothing (`changed=False`).
    Idempotent: re-running with an unchanged provider state changes
    nothing. A `legacy_unverified` row is refused -- it has no verified
    provider identity and must go through `reconcile_legacy_subscription()`.
    This is also how a cancellation whose local write failed after the
    provider canceled is corrected (`canceled` at the provider ->
    `canceled` locally)."""
    validated = authorize_billing(
        caller,
        [(service_tenant_id, BILLING_SUBSCRIPTION, "read")],
        operation="billing.subscription.reconcile_status",
    )
    row = _load(service_tenant_id, subscription_id)
    if row.verification != VerificationState.VERIFIED.value:
        raise LegacyReconciliationError(
            subscription_id, "legacy-unverified subscriptions must be reconciled first"
        )
    _verify_provider_reference(row)
    active_provider = _adapter_for(row.provider, provider)
    state = active_provider.get_subscription_status(
        provider_subscription_id=row.provider_subscription_id
    )
    updated, previous, changed = _apply_provider_state(service_tenant_id, subscription_id, state)
    if changed:
        _audit_status_change(validated, updated, previous, state)
    return SubscriptionReconciliation(
        subscription_id=subscription_id,
        previous_status=previous,
        status=updated.status,
        provider_state=state,
        changed=changed,
    )


def _audit_status_change(
    caller: BillingCaller, row: Subscription, previous: str, state: ProviderSubscriptionState
) -> None:
    actor_type, actor_user_id, extra = audit_actor(caller)
    record_audit_event(
        tenant_id=row.tenant_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action="billing.subscription_status_changed",
        resource_type="billing_subscription",
        resource_id=str(row.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "previous_status": previous,
            "status": row.status,
            "provider_state": state.value,
            **extra,
        },
    )


# --- Cancellation -------------------------------------------------------------


def cancel_commercial_subscription(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    provider: BillingProvider | None = None,
) -> SubscribeResult:
    """Immediately cancel a *verified* commercial subscription
    (`billing.subscription:cancel` on the service tenant). Phase 3
    cancellation safety:

    - already `canceled` locally -> no provider call, returned unchanged
      (idempotent);
    - the provider reference is re-verified before the provider is
      touched (`ProviderReferenceMismatchError` otherwise);
    - the provider is asked to cancel through `cancel_at_provider()`, which
      tolerates a provider that has *already* canceled -- confirmed by the
      provider's own `canceled` state, never assumed from `not_found` or an
      outage, both of which raise and leave the local row as it was;
    - only then is the local row moved to `canceled` (an allowed transition
      from every live state).

    If the provider cancels but the local write fails, a retry of this
    function (the provider then confirms `canceled`) or
    `reconcile_subscription_status()` brings the row to `canceled`.
    Cancel-at-period-end and reactivation are later phases."""
    validated = authorize_billing(
        caller,
        [(service_tenant_id, BILLING_SUBSCRIPTION, "cancel")],
        operation="billing.subscription.cancel",
    )
    row = _load(service_tenant_id, subscription_id)
    if row.verification != VerificationState.VERIFIED.value:
        raise LegacyReconciliationError(
            subscription_id, "legacy-unverified subscriptions must be reconciled first"
        )
    if row.status == SubscriptionStatus.CANCELED.value:
        return SubscribeResult.from_subscription(row)
    _verify_provider_reference(row)
    active_provider = _adapter_for(row.provider, provider)
    cancel_at_provider(active_provider, row.provider_subscription_id)

    with tenant_session_scope(service_tenant_id) as session:
        locked = session.get(Subscription, subscription_id, with_for_update=True)
        if locked is None or locked.tenant_id != service_tenant_id:
            raise SubscriptionNotFoundError(service_tenant_id, subscription_id)
        previous = locked.status
        changed = set_subscription_status(locked, SubscriptionStatus.CANCELED)
        session.flush()
        session.refresh(locked)
        session.expunge(locked)

    if changed:
        actor_type, actor_user_id, extra = audit_actor(validated)
        record_audit_event(
            tenant_id=service_tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            action="billing.subscription_canceled",
            resource_type="billing_subscription",
            resource_id=str(subscription_id),
            outcome=AuditOutcome.SUCCESS,
            metadata={"previous_status": previous, **extra},
        )
    return SubscribeResult.from_subscription(locked)


# --- Legacy reconciliation ----------------------------------------------------


def reconcile_legacy_subscription(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    provider: BillingProvider | None = None,
) -> SubscribeResult:
    """Verify one `legacy_unverified` subscription and record its
    commercial relationship -- the only way such a row becomes `verified`.

    Nothing is guessed: the caller supplies the authoritative payer billing
    account, and must be authorized exactly as for creating that
    relationship (`billing.account:charge` on the payer AND
    `billing.subscription:create` on the service tenant). Then, in order,
    failing closed with the row unchanged at every step:

    1. the row must exist under the service tenant's own RLS scope and be
       `legacy_unverified`;
    2. the billing account must be active and belong to the payer, its
       merchant active and (pre-Catalog-v2) platform-owned, the adapter the
       merchant's provider; a payer, billing account or provider the row
       already records must agree with the supplied mapping;
    3. the provider must positively answer for the row's provider
       subscription id (`not_found`/`unknown` -> `LegacyReconciliationError`;
       an outage -> `BillingProviderError`);
    4. the provider's state must be reachable from the row's current status
       through an allowed transition (a `canceled` row is never revived);
    5. the provider reference is registered (a reference already mapped
       elsewhere -> `ProviderRefConflictError`);
    6. payer, billing account, merchant and provider are recorded, the
       status is set from the provider state, and the row becomes
       `verified` -- or, if that would give the service tenant a second
       live subscription at the merchant, `LiveSubscriptionExistsError`.

    Audited as `billing.subscription_reconciled`."""
    validated = authorize_billing(
        caller,
        [
            (payer_tenant_id, BILLING_ACCOUNT, "charge"),
            (service_tenant_id, BILLING_SUBSCRIPTION, "create"),
        ],
        operation="billing.subscription.reconcile_legacy",
    )
    require_open_tenant(service_tenant_id)
    require_open_tenant(payer_tenant_id)

    row = _load(service_tenant_id, subscription_id)
    if row.verification != VerificationState.LEGACY_UNVERIFIED.value:
        raise LegacyReconciliationError(subscription_id, "it is not legacy-unverified")
    if row.billing_account_id is not None and (
        row.billing_account_id != billing_account_id or row.payer_tenant_id != payer_tenant_id
    ):
        raise LegacyReconciliationError(
            subscription_id, "the supplied payer contradicts the payer it already records"
        )

    account, merchant, active_provider = _resolve_merchant_context(
        payer_tenant_id, billing_account_id, "(legacy subscription)", provider
    )
    if row.provider is not None and row.provider != merchant.provider:
        raise LegacyReconciliationError(
            subscription_id, "the merchant's provider is not the provider the row records"
        )

    state = active_provider.get_subscription_status(
        provider_subscription_id=row.provider_subscription_id
    )
    target = target_status_for(state)
    if target is None:
        raise LegacyReconciliationError(
            subscription_id, f"the provider cannot confirm the subscription ({state.value})"
        )
    if not is_transition_allowed(parse_status(row.status), target):
        raise LegacyReconciliationError(
            subscription_id,
            f"provider state {state.value!r} contradicts local status {row.status!r}",
        )

    register_provider_ref(
        provider=merchant.provider,
        provider_account_ref=merchant.provider_account_ref,
        object_type=ProviderObjectType.SUBSCRIPTION,
        provider_object_ref=row.provider_subscription_id,
        tenant_id=service_tenant_id,
        local_object_type=LocalObjectType.BILLING_SUBSCRIPTION,
        local_object_id=subscription_id,
    )

    previous = row.status
    try:
        with tenant_session_scope(service_tenant_id) as session:
            locked = session.get(Subscription, subscription_id, with_for_update=True)
            if (
                locked is None
                or locked.tenant_id != service_tenant_id
                or locked.verification != VerificationState.LEGACY_UNVERIFIED.value
            ):
                raise LegacyReconciliationError(subscription_id, "it changed concurrently")
            locked.payer_tenant_id = account.tenant_id
            locked.billing_account_id = account.id
            locked.merchant_account_id = merchant.id
            locked.provider = merchant.provider
            locked.verification = VerificationState.VERIFIED.value
            set_subscription_status(locked, target)
            session.flush()
            session.refresh(locked)
            session.expunge(locked)
    except IntegrityError as exc:
        if _violates_one_live_invariant(exc):
            raise LiveSubscriptionExistsError(service_tenant_id, merchant.id) from None
        raise

    actor_type, actor_user_id, extra = audit_actor(validated)
    record_audit_event(
        tenant_id=service_tenant_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action="billing.subscription_reconciled",
        resource_type="billing_subscription",
        resource_id=str(subscription_id),
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "payer_tenant_id": str(account.tenant_id),
            "billing_account_id": str(account.id),
            "merchant_account_id": str(merchant.id),
            "previous_status": previous,
            "status": locked.status,
            "provider_state": state.value,
            **extra,
        },
    )
    return SubscribeResult.from_subscription(locked)


# --- Bounded provider-reference lookup ---------------------------------------


def get_subscription_by_provider_ref(
    *, provider: str, provider_account_ref: str, provider_subscription_ref: str
) -> Subscription:
    """The bounded cross-tenant lookup: resolve a provider subscription
    reference through the global `core.billing_provider_refs` index, then
    read the subscription under `tenant_session_scope()` for the resolved
    tenant only. The row must itself carry the same provider and provider
    subscription id (defense in depth against a stale or dangling
    reference); otherwise `SubscriptionNotFoundError`."""
    resolution = resolve_provider_ref(
        provider=provider,
        provider_account_ref=provider_account_ref,
        object_type=ProviderObjectType.SUBSCRIPTION,
        provider_object_ref=provider_subscription_ref,
    )
    if resolution.local_object_type is not LocalObjectType.BILLING_SUBSCRIPTION:
        raise SubscriptionNotFoundError(resolution.tenant_id, resolution.local_object_id)
    with tenant_session_scope(resolution.tenant_id) as session:
        subscription = session.get(Subscription, resolution.local_object_id)
        if (
            subscription is None
            or subscription.tenant_id != resolution.tenant_id
            or subscription.provider != provider
            or subscription.provider_subscription_id != provider_subscription_ref
        ):
            raise SubscriptionNotFoundError(resolution.tenant_id, resolution.local_object_id)
        session.expunge(subscription)
        return subscription
