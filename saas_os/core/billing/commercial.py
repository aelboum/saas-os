"""The authorized commercial subscription entry points (Billing Foundation
v2 Phase 2 + Phase 3; docs/ADR/0029-commercial-parties-and-billing-
relationships.md).

`create_subscription()` creates a subscription with three explicitly
named parties:

    service tenant  -- `Subscription.tenant_id`: receives the service and
                       its entitlements; the subscription's RLS owner.
    payer           -- `(payer_tenant_id, billing_account_id)`: the
                       `BillingAccount` that is charged.
    payee           -- the plan's merchant (Catalog v2, Phase 5.3 step 3),
                       which must be the billing account's merchant;
                       recorded as `Subscription.merchant_account_id` and
                       guaranteed by a composite foreign key to be that
                       account's own merchant.

The plan is a Catalog v2 plan, addressed by id, and admitted only by the
single eligibility predicate (`saas_os/core/billing/catalog.py::
evaluate_plan_eligibility()`); knowing its id grants nothing.

**Dual authorization** (ADR-0029, invariant 6), both through
`saas_os.core.rbac.can(session=...)` (`saas_os/core/billing/authorization.py`):

    billing.account:charge        on the payer tenant
    billing.subscription:create   on the service tenant

The payer is never trusted because it was supplied: the caller must hold
`charge` on the payer tenant, and the billing account must actually belong
to that payer (it is read under the payer's own RLS scope). A denial is
the same `BillingNotAuthorizedError` whichever check failed.

**Authority and evidence (Phase 5.3 step 1; ADR-0031 amendment
2026-10-02).** Every entry point takes a `saas_os.core.authority` caller
(`UserCaller`, or `SystemCaller(BILLING_OPERATIONS)`; the deprecated
`BillingActor`/`trusted_system()` map onto those). Because a provider call
cannot join a database transaction, each one is shaped

    authorize (a transaction that persists nothing)
      -> provider operation (not transactional)
      -> final transaction: re-authorize -> re-check state -> persist -> audit

so the persisted change and its audit entry commit together, under an
authorization evaluated in that same transaction. If the final
transaction refuses, the provider's object is never deleted: it stays
reachable for reconciliation.

**Lifecycle safety (Phase 3; `saas_os/core/billing/lifecycle.py`).** Creation is

    authorize + Catalog v2 eligibility + payer account (_commercial_context)
      -> reserve idempotency
      -> provider customer for (payer, merchant), created once and reused
      -> provider creates (with a stable provider idempotency key and the
         merchant/payer context)
      -> provider reference registered
      -> final transaction: _commercial_context again, local row written as
         `pending`, audited (or, if refused, no row and a refusal audit)
      -> provider asked for its authoritative status -> transition (audited)

A subscription is `active` only when the provider positively confirms an
active state. Inserting the local row never activates anything: the row
is always written `pending`, and only `_apply_provider_state()` moves it,
through a validated transition, from a provider-confirmed state. If the
provider reports anything else, or cannot be asked, the row stays
`pending` (or moves to the confirmed non-active state) and the caller
receives that state -- the provider object is never deleted, and
`reconcile_subscription_status()` re-asks later.

**Provider idempotency.** The provider idempotency key and the local
subscription id are both derived from the `saas_os.core.idempotency` reservation
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

- The provider adapter must be the merchant's provider
  (`BillingProviderMismatchError`). The deployment's default Stripe adapter
  acts in the deployment's own Stripe account, so it is constructed only for
  a `"stripe"` merchant owned by the configured platform tenant; another
  merchant needs a supplied adapter that can act in its account (Stripe
  Connect is deferred).
- No provider-event ingestion: status changes are learned synchronously,
  on creation and on `reconcile_subscription_status()`.
- Legacy reconciliation (`reconcile_legacy_subscription()`) still records
  only the platform tenant's merchant for a legacy row: it was sold by the
  deployment's own provider account.
- The plan/merchant agreement is enforced in the final transaction under
  the plan's row lock, not by a database foreign key: verified Phase 2/3
  rows already record the platform merchant against unadopted legacy plans,
  which such a key would reject.

**`inherits_billing` is never used to decide a payer.** A service tenant
that inherits billing is refused (`require_service_tenant_owns_billing()`).
"""

from __future__ import annotations

import enum
import uuid
from collections.abc import Mapping
from dataclasses import dataclass

from saas_os.core.audit_log import AuditOutcome, record_in_transaction
from saas_os.core.audit_log import record as record_audit_event
from saas_os.core.billing.authorization import (
    BILLING_ACCOUNT,
    BILLING_MERCHANT,
    BILLING_SUBSCRIPTION,
    AuthorizedBillingCaller,
    audit_actor,
    authorize_billing,
    record_billing_audit,
    require_billing_caller,
)
from saas_os.core.billing.catalog import evaluate_plan_eligibility
from saas_os.core.billing.errors import (
    BillingAccountNotFoundError,
    BillingInheritanceMigrationError,
    BillingNotAuthorizedError,
    BillingProviderContractError,
    BillingProviderError,
    BillingProviderMismatchError,
    CommercialPartyNotActiveError,
    InheritedBillingSubscriptionError,
    LegacyReconciliationError,
    LiveSubscriptionExistsError,
    MerchantNotEligibleForPlanError,
    PlanNotEligibleError,
    ProviderReferenceMismatchError,
    ProviderRefNotFoundError,
    SubscriptionNotFoundError,
)
from saas_os.core.billing.lifecycle import (
    LIVE_STATUSES,
    SubscriptionStatus,
    VerificationState,
    is_transition_allowed,
    parse_status,
    set_subscription_status,
    target_status_for,
)
from saas_os.core.billing.models import BillingAccount, MerchantAccount, Plan, Subscription
from saas_os.core.billing.parties import (
    get_billing_account,
    get_merchant_account,
    require_active_billing_account,
    require_active_merchant_account,
)
from saas_os.core.billing.projections import announce_subscription_change
from saas_os.core.billing.provider import (
    BillingProvider,
    ProviderCommerceContext,
    ProviderSubscriptionState,
)
from saas_os.core.billing.provider_refs import (
    LocalObjectType,
    ProviderObjectType,
    find_provider_object_ref,
    register_provider_ref,
    resolve_provider_ref,
)
from saas_os.core.billing.service import (
    SubscribeResult,
    _default_provider,
    cancel_at_provider,
    provider_name,
    require_service_tenant_owns_billing,
)
from saas_os.core.idempotency import (
    IdempotencyStatus,
    begin_idempotent_operation,
    finalize_idempotent_operation,
)
from saas_os.core.tenancy import (
    Tenant,
    TenantClosedError,
    get_platform_tenant_id,
    lock_open_tenant,
    require_open_tenant,
)
from saas_os.infra.db import (
    IntegrityError,
    Session,
    bind_tenant_scope,
    select,
    tenant_session_scope,
    update,
)

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


def _resolve_legacy_merchant_context(
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_key: str,
    provider: BillingProvider | None,
) -> tuple[BillingAccount, MerchantAccount, BillingProvider]:
    """Legacy reconciliation only (`reconcile_legacy_subscription()`): a
    legacy row was sold by the deployment's own provider account, i.e. the
    configured platform tenant's merchant, so only such a merchant may be
    recorded for it. New subscriptions go through Catalog v2
    (`_commercial_context()`), where the plan names its merchant."""
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


def _authorize_initially(
    caller: object,
    checks: list[tuple[uuid.UUID, str, str]],
    *,
    operation: str,
    tenant_id: uuid.UUID,
) -> AuthorizedBillingCaller:
    """The first authorization of an operation that calls a provider: a
    transaction that persists nothing. It fails fast, before any provider
    call, but is never trusted on its own -- the final transaction that
    persists the result authorizes again (ADR-0031 amendment, "The
    provider-call boundary")."""
    with tenant_session_scope(tenant_id) as session:
        return authorize_billing(caller, checks, operation=operation, session=session)


def _apply_provider_state(
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    state: ProviderSubscriptionState,
    *,
    caller: object,
    checks: list[tuple[uuid.UUID, str, str]],
    operation: str,
) -> tuple[Subscription, str, bool]:
    """In one transaction: re-authorize `caller`, then move the row to the
    status the provider confirmed if that is an allowed transition, and
    audit the change. `not_found`/`unknown`, or a transition the lifecycle
    forbids (e.g. resurrecting `canceled`), change nothing and write no
    audit entry. Returns `(row, previous_status, changed)`."""
    target = target_status_for(state)
    with tenant_session_scope(service_tenant_id) as session:
        authorized = authorize_billing(caller, checks, operation=operation, session=session)
        row = session.get(Subscription, subscription_id, with_for_update=True)
        if row is None or row.tenant_id != service_tenant_id:
            raise SubscriptionNotFoundError(service_tenant_id, subscription_id)
        previous = row.status
        changed = False
        if target is not None and is_transition_allowed(parse_status(previous), target):
            changed = set_subscription_status(row, target)
            session.flush()
        if changed:
            announce_subscription_change(session, row)
            record_billing_audit(
                session,
                authorized,
                tenant_id=service_tenant_id,
                action="billing.subscription_status_changed",
                resource_type="billing_subscription",
                resource_id=str(subscription_id),
                metadata={
                    "previous_status": previous,
                    "status": row.status,
                    "provider_state": state.value,
                },
            )
            session.refresh(row)
        session.expunge(row)
    return row, previous, changed


@dataclass(frozen=True)
class _CommercialContext:
    """What one commercial creation was checked against, inside one
    transaction (detached copies of the rows)."""

    authorized: AuthorizedBillingCaller
    plan: Plan
    account: BillingAccount
    merchant: MerchantAccount


def _commercial_context(
    session: Session,
    caller: object,
    checks: list[tuple[uuid.UUID, str, str]],
    *,
    service_tenant_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_id: uuid.UUID,
    operation: str = _OPERATION,
    migrating_inheritance: bool = False,
) -> _CommercialContext:
    """Every check a commercial subscription depends on, made in `session`
    (scoped to the service tenant) -- used both before the provider call
    and, again, in the final transaction that persists the row, so the two
    can never drift apart:

    1. the caller holds `billing.account:charge` on the payer and
       `billing.subscription:create` on the service tenant (`can(session=)`);
    2. both tenants are open (their `core.tenants` rows `FOR SHARE`), and the
       service tenant owns its billing (no legacy inheritance);
    3. the plan exists (its row `FOR SHARE`, so a withdrawal waits);
    4. the billing account belongs to the payer -- read under the payer's
       own RLS scope, `FOR SHARE` -- and is active; the payer is never
       taken from input alone;
    5. the single Catalog v2 predicate admits the plan for this caller and
       service tenant **through this billing account's merchant**
       (`evaluate_plan_eligibility(..., merchant_account_id=...)`): adopted,
       active, merchant active, visibility/offer, and plan merchant ==
       billing-account merchant.

    A missing plan and an ineligible one raise the same
    `PlanNotEligibleError`.

    With `migrating_inheritance` (the sponsored migration, Phase 5.3 step 5)
    step 2 inverts: the service tenant must still inherit billing and have
    no live subscription of its own, so the migration can neither run twice
    nor create a duplicate (`BillingInheritanceMigrationError`)."""
    authorized = authorize_billing(caller, checks, operation=operation, session=session)
    service_tenant = lock_open_tenant(session, service_tenant_id)
    lock_open_tenant(session, payer_tenant_id)
    if migrating_inheritance:
        _require_migratable(session, service_tenant_id, inherits=service_tenant.inherits_billing)
    else:
        require_service_tenant_owns_billing(service_tenant)

    plan = session.execute(
        select(Plan).where(Plan.id == plan_id).with_for_update(read=True)
    ).scalar_one_or_none()
    if plan is None:
        raise PlanNotEligibleError(service_tenant_id, plan_id, "not_found")
    with bind_tenant_scope(session, payer_tenant_id):
        account = session.execute(
            select(BillingAccount)
            .where(
                BillingAccount.id == billing_account_id,
                BillingAccount.tenant_id == payer_tenant_id,
            )
            .with_for_update(read=True)
        ).scalar_one_or_none()
    if account is None:
        raise BillingAccountNotFoundError(payer_tenant_id, billing_account_id)
    require_active_billing_account(account)

    decision = evaluate_plan_eligibility(
        caller,
        service_tenant_id,
        plan,
        session=session,
        merchant_account_id=account.merchant_account_id,
    )
    if not decision.eligible:
        raise PlanNotEligibleError(service_tenant_id, plan_id, decision.reason.value)
    assert plan.owner_tenant_id is not None and plan.merchant_account_id is not None
    with bind_tenant_scope(session, plan.owner_tenant_id):
        merchant = session.get(MerchantAccount, plan.merchant_account_id)
    assert merchant is not None  # the predicate just read it FOR SHARE
    for row in (plan, account, merchant):
        session.expunge(row)
    return _CommercialContext(authorized, plan, account, merchant)


def _require_migratable(session: Session, service_tenant_id: uuid.UUID, *, inherits: bool) -> None:
    if not inherits:
        raise BillingInheritanceMigrationError(service_tenant_id, "it does not inherit billing")
    live = session.execute(
        select(Subscription.id).where(
            Subscription.tenant_id == service_tenant_id,
            Subscription.status.in_([s.value for s in LIVE_STATUSES]),
        )
    ).first()
    if live is not None:
        raise BillingInheritanceMigrationError(
            service_tenant_id, "it already has a live subscription of its own"
        )


def _adapter_for_merchant(
    merchant: MerchantAccount, provider: BillingProvider | None
) -> BillingProvider:
    """The adapter for `merchant`. An explicitly supplied adapter must be
    the merchant's provider. The deployment's own default Stripe adapter
    acts in the deployment's own Stripe account, so it is used only for a
    merchant owned by the configured platform tenant: any other merchant
    needs an adapter that can act in *its* account (a Connect-capable one,
    deferred), otherwise its customers would be charged into the
    deployment's account. The same holds for an explicitly supplied Stripe
    adapter: unless it declares `acts_in_merchant_accounts = True` (it
    acts in the merchant's own account from the commerce context), it is
    refused for a merchant the platform tenant does not own -- the
    deployment's `StripeBillingProvider` declares nothing and always acts
    in the deployment's account. Fails closed
    (`BillingProviderMismatchError`)."""
    if merchant.provider != _STRIPE or merchant.tenant_id == get_platform_tenant_id():
        return _adapter_for(merchant.provider, provider)
    if provider is None:
        raise BillingProviderMismatchError(merchant.provider, None)
    adapter = _adapter_for(merchant.provider, provider)
    if getattr(adapter, "acts_in_merchant_accounts", False) is not True:
        raise BillingProviderMismatchError(merchant.provider, provider_name(adapter))
    return adapter


def _ensure_provider_customer(
    active_provider: BillingProvider, account: BillingAccount, merchant: MerchantAccount
) -> str:
    """The provider customer for exactly this (payer, merchant) pair --
    `BillingAccount` is unique per (payer, merchant), so its
    `provider_customer_ref` is that pair's customer and is never reused
    for another merchant. Created once, with a stable idempotency key
    derived from the billing account; registered in the provider-reference
    index first (idempotent), then persisted under the payer's RLS scope
    (only if still unset). A crash between the two leaves the account
    without a customer, so the retry asks the provider again with the same
    key, gets the same customer, and completes both steps."""
    if account.provider_customer_ref is not None:
        return account.provider_customer_ref
    customer_ref = active_provider.ensure_customer(
        context=_provider_context(account, merchant, None),
        idempotency_key=f"saas-os:billing.customer:{account.id}",
    )
    register_provider_ref(
        provider=merchant.provider,
        provider_account_ref=merchant.provider_account_ref,
        object_type=ProviderObjectType.CUSTOMER,
        provider_object_ref=customer_ref,
        tenant_id=account.tenant_id,
        local_object_type=LocalObjectType.BILLING_ACCOUNT,
        local_object_id=account.id,
    )
    with tenant_session_scope(account.tenant_id) as session:
        session.execute(
            update(BillingAccount)
            .where(
                BillingAccount.id == account.id,
                BillingAccount.tenant_id == account.tenant_id,
                BillingAccount.provider_customer_ref.is_(None),
            )
            .values(provider_customer_ref=customer_ref)
        )
        stored = session.execute(
            select(BillingAccount.provider_customer_ref).where(BillingAccount.id == account.id)
        ).scalar_one()
    assert stored is not None
    return stored


def _provider_context(
    account: BillingAccount, merchant: MerchantAccount, customer_ref: str | None
) -> ProviderCommerceContext:
    return ProviderCommerceContext(
        merchant_account_id=merchant.id,
        merchant_provider_account_ref=merchant.provider_account_ref,
        payer_tenant_id=account.tenant_id,
        payer_billing_account_id=account.id,
        provider_customer_ref=customer_ref,
    )


# --- Creation ---------------------------------------------------------------


def create_subscription(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_id: uuid.UUID,
    idempotency_key: str,
    provider: BillingProvider | None = None,
) -> tuple[bool, SubscribeResult]:
    """Create a subscription to the Catalog v2 plan `plan_id` for
    `service_tenant_id`, paid through `payer_tenant_id`'s billing account
    `billing_account_id` (Phase 5.3 step 3). `caller` is a `saas_os.core.authority`
    `UserCaller` or `SystemCaller(BILLING_OPERATIONS)` (or a deprecated
    compatibility caller) -- never `None`. Returns `(is_replay, result)`
    where `result.status` is the provider-confirmed lifecycle status:
    `active` only on positive provider confirmation, otherwise `pending`
    (or the confirmed non-active status). A replay returns the row's
    *current* state, not a stale copy. See the module docstring.

    The parties are explicit and checked, never inferred: service tenant =
    `Subscription.tenant_id` (receives the entitlements), payer = the
    billing account's owner, merchant = the plan's merchant, which must be
    the billing account's merchant. `_commercial_context()` runs every
    check -- authority, tenants, billing-account ownership and the single
    Catalog v2 eligibility predicate -- before the provider is called, and
    **again** in the final transaction that writes the row and its audit
    entry. If anything changed while the provider was working (a
    withdrawal, an offer revocation, a merchant or billing account
    deactivated, authority revoked), the final transaction refuses: no
    local row is written, the provider subscription and its registered
    provider reference remain for reconciliation, and the refusal is
    audited (`billing.subscription_create_refused`)."""
    return _create_commercial_subscription(
        caller,
        service_tenant_id=service_tenant_id,
        payer_tenant_id=payer_tenant_id,
        billing_account_id=billing_account_id,
        plan_id=plan_id,
        idempotency_key=idempotency_key,
        provider=provider,
        operation=_OPERATION,
        migrating_inheritance=False,
    )


def _create_commercial_subscription(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_id: uuid.UUID,
    idempotency_key: str,
    provider: BillingProvider | None,
    operation: str,
    migrating_inheritance: bool,
) -> tuple[bool, SubscribeResult]:
    """`create_subscription()`, and -- with `migrating_inheritance` -- the
    sponsored migration of an inheriting tenant
    (`saas_os/core/billing/inheritance.py::migrate_inherited_tenant_to_sponsorship()`),
    which additionally needs `billing.subscription:change` on the service
    tenant and ends its inheritance in the same final transaction that
    writes the row."""
    require_billing_caller(caller)
    checks = [
        (payer_tenant_id, BILLING_ACCOUNT, "charge"),
        (service_tenant_id, BILLING_SUBSCRIPTION, "create"),
    ]
    if migrating_inheritance:
        checks.append((service_tenant_id, BILLING_SUBSCRIPTION, "change"))
    fingerprint = {
        "plan_id": str(plan_id),
        "payer_tenant_id": str(payer_tenant_id),
        "billing_account_id": str(billing_account_id),
    }
    try:
        with tenant_session_scope(service_tenant_id) as session:
            context = _commercial_context(
                session,
                caller,
                checks,
                service_tenant_id=service_tenant_id,
                payer_tenant_id=payer_tenant_id,
                billing_account_id=billing_account_id,
                plan_id=plan_id,
                operation=operation,
                migrating_inheritance=migrating_inheritance,
            )
    except BillingInheritanceMigrationError:
        # A completed migration has, by definition, ended the inheritance
        # its precondition requires -- so a retry of that same request
        # must be answered from its idempotency record. The caller was
        # authorized before this precondition was evaluated.
        replayed = _replay_completed(service_tenant_id, operation, idempotency_key, fingerprint)
        if replayed is None:
            raise
        return True, replayed
    plan, account, merchant = context.plan, context.account, context.merchant
    active_provider = _adapter_for_merchant(merchant, provider)
    if getattr(active_provider, "honors_idempotency_keys", False) is not True:
        raise BillingProviderContractError(provider_name(active_provider))

    reservation = begin_idempotent_operation(
        service_tenant_id, operation, idempotency_key, fingerprint
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
            if recorded is not None:
                provider_subscription_id = recorded
            else:
                customer_ref = _ensure_provider_customer(active_provider, account, merchant)
                provider_subscription_id = active_provider.create_subscription(
                    tenant_id=payer_tenant_id,
                    plan=plan,
                    idempotency_key=f"saas-os:{operation}:{operation_id}",
                    context=_provider_context(account, merchant, customer_ref),
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
            try:
                _insert_pending(
                    caller=caller,
                    checks=checks,
                    subscription_id=subscription_id,
                    service_tenant_id=service_tenant_id,
                    payer_tenant_id=payer_tenant_id,
                    billing_account_id=billing_account_id,
                    plan_id=plan_id,
                    provider_subscription_id=provider_subscription_id,
                    merchant=merchant,
                    operation=operation,
                    migrating_inheritance=migrating_inheritance,
                )
            except _FINAL_REFUSALS as exc:
                _audit_refused_creation(
                    caller,
                    service_tenant_id=service_tenant_id,
                    subscription_id=subscription_id,
                    plan_id=plan_id,
                    payer_tenant_id=payer_tenant_id,
                    merchant=merchant,
                    provider_subscription_id=provider_subscription_id,
                    refusal=exc,
                )
                raise
    except Exception:
        finalize_idempotent_operation(
            service_tenant_id, reservation.record_id, status=IdempotencyStatus.FAILED
        )
        raise

    # Confirmation: the only path from `pending` to anything else. A
    # provider that cannot be asked -- or a caller whose authority was
    # revoked in the meantime -- leaves the row `pending`, never active;
    # `reconcile_subscription_status()` re-asks later.
    try:
        state = active_provider.get_subscription_status(
            provider_subscription_id=provider_subscription_id
        )
    except BillingProviderError:
        state = None
    subscription: Subscription | None = None
    if state is not None:
        try:
            subscription, _, _ = _apply_provider_state(
                service_tenant_id,
                subscription_id,
                state,
                caller=caller,
                checks=checks,
                operation=operation,
            )
        except BillingNotAuthorizedError:
            subscription = None
    if subscription is None:
        subscription = _load(service_tenant_id, subscription_id)

    if payer_tenant_id != service_tenant_id:
        # The payer is charged for a subscription it does not hold -- it
        # gets its own audit record, under its own tenant. ADR-0029 keeps a
        # commercial operation's writes for different tenants in separate
        # transactions, so this secondary record is written after the
        # service tenant's transaction committed. (The payer's durable view
        # is its payer projection, Phase 5.3 step 4; that consumer writes no
        # audit evidence, so this record stays here -- deferred.)
        actor_type, actor_user_id, extra = audit_actor(require_billing_caller(caller))
        record_audit_event(
            tenant_id=payer_tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            action="billing.subscription_charged_to_account",
            resource_type="billing_account",
            resource_id=str(account.id),
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "plan_id": str(plan_id),
                "plan_key": plan.key,
                "service_tenant_id": str(service_tenant_id),
                "subscription_id": str(subscription.id),
                "merchant_account_id": str(merchant.id),
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


def _replay_completed(
    service_tenant_id: uuid.UUID,
    operation: str,
    idempotency_key: str,
    fingerprint: Mapping[str, object],
) -> SubscribeResult | None:
    """The current state of the subscription a completed request with this
    key created, or `None` -- in which case no reservation is left behind
    (a fresh one is released as failed)."""
    reservation = begin_idempotent_operation(
        service_tenant_id, operation, idempotency_key, fingerprint
    )
    if reservation.is_replay:
        assert reservation.result is not None
        stored = SubscribeResult.from_dict(reservation.result)
        return SubscribeResult.from_subscription(_load(service_tenant_id, stored.subscription_id))
    finalize_idempotent_operation(
        service_tenant_id, reservation.record_id, status=IdempotencyStatus.FAILED
    )
    return None


# What the final transaction may refuse with, after the provider already
# created its subscription: each leaves no local row, and is audited.
_FINAL_REFUSALS: tuple[type[Exception], ...] = (
    BillingNotAuthorizedError,
    PlanNotEligibleError,
    BillingAccountNotFoundError,
    CommercialPartyNotActiveError,
    TenantClosedError,
    InheritedBillingSubscriptionError,
    LiveSubscriptionExistsError,
    BillingInheritanceMigrationError,
)


def _find_by_id(service_tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> Subscription | None:
    try:
        return _load(service_tenant_id, subscription_id)
    except SubscriptionNotFoundError:
        return None


def _insert_pending(
    *,
    caller: object,
    checks: list[tuple[uuid.UUID, str, str]],
    subscription_id: uuid.UUID,
    service_tenant_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_id: uuid.UUID,
    provider_subscription_id: str,
    merchant: MerchantAccount,
    operation: str = _OPERATION,
    migrating_inheritance: bool = False,
) -> None:
    """The final transaction of creation: `_commercial_context()` again --
    authority, both tenants' lifecycles, billing-account ownership and
    status, and the Catalog v2 predicate, all re-evaluated now -- then the
    local row (always `pending`, never `active`) and its audit entry, at
    once. The merchant must still be the one the provider acted for.

    A unique violation rolls the whole transaction back, audit entry
    included: it is either the live-subscription index (a concurrent
    request won) or, after a crash, this same row already existing; the
    latter is re-read and accepted, the former is
    `LiveSubscriptionExistsError`.

    In the sponsored migration the service tenant's `core.tenants` row is
    locked `FOR UPDATE` first, and its `inherits_billing` is set to `false`
    in this same transaction as the new row and both audit entries -- the
    tenant is never without either its inheritance or its subscription."""
    try:
        with tenant_session_scope(service_tenant_id) as session:
            tenant_row = (
                session.get(Tenant, service_tenant_id, with_for_update=True)
                if migrating_inheritance
                else None
            )
            context = _commercial_context(
                session,
                caller,
                checks,
                service_tenant_id=service_tenant_id,
                payer_tenant_id=payer_tenant_id,
                billing_account_id=billing_account_id,
                plan_id=plan_id,
                operation=operation,
                migrating_inheritance=migrating_inheritance,
            )
            if context.merchant.id != merchant.id:
                raise PlanNotEligibleError(service_tenant_id, plan_id, "merchant_changed")
            row = Subscription(
                id=subscription_id,
                tenant_id=service_tenant_id,
                plan_id=plan_id,
                status=SubscriptionStatus.PENDING.value,
                provider_subscription_id=provider_subscription_id,
                payer_tenant_id=context.account.tenant_id,
                billing_account_id=context.account.id,
                merchant_account_id=context.merchant.id,
                provider=context.merchant.provider,
                verification=VerificationState.VERIFIED.value,
            )
            session.add(row)
            session.flush()
            announce_subscription_change(session, row, created=True)
            record_billing_audit(
                session,
                context.authorized,
                tenant_id=service_tenant_id,
                action="billing.subscription_created",
                resource_type="billing_subscription",
                resource_id=str(subscription_id),
                metadata={
                    "plan_id": str(plan_id),
                    "plan_key": context.plan.key,
                    "plan_owner_tenant_id": str(context.plan.owner_tenant_id),
                    "service_tenant_id": str(service_tenant_id),
                    "payer_tenant_id": str(context.account.tenant_id),
                    "billing_account_id": str(context.account.id),
                    "merchant_account_id": str(context.merchant.id),
                    "merchant_tenant_id": str(context.merchant.tenant_id),
                    "status": SubscriptionStatus.PENDING.value,
                },
            )
            if tenant_row is not None:
                tenant_row.inherits_billing = False
                session.flush()
                record_billing_audit(
                    session,
                    context.authorized,
                    tenant_id=service_tenant_id,
                    action="billing.inheritance_migrated",
                    resource_type="tenant",
                    resource_id=str(service_tenant_id),
                    metadata={
                        "previous_inherits_billing": True,
                        "inherits_billing": False,
                        "subscription_id": str(subscription_id),
                        "payer_tenant_id": str(context.account.tenant_id),
                        "billing_account_id": str(context.account.id),
                        "merchant_account_id": str(context.merchant.id),
                        "plan_id": str(plan_id),
                    },
                )
    except IntegrityError as exc:
        existing = _find_by_id(service_tenant_id, subscription_id)
        if existing is not None and existing.provider_subscription_id == provider_subscription_id:
            return
        if _violates_one_live_invariant(exc):
            raise LiveSubscriptionExistsError(service_tenant_id, merchant.id) from None
        raise


def _audit_refused_creation(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    plan_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    merchant: MerchantAccount,
    provider_subscription_id: str,
    refusal: Exception,
) -> None:
    """Evidence that the provider created a subscription the final
    transaction then refused to record -- `outcome=failure`, no local row.
    It names the provider object (an opaque reference, already in the
    provider-reference index pointing at the local id that was never
    written) so it can be reconciled; it is never a success record."""
    with tenant_session_scope(service_tenant_id) as session:
        record_in_transaction(
            session,
            caller=require_billing_caller(caller).caller,
            tenant_id=service_tenant_id,
            action="billing.subscription_create_refused",
            resource_type="billing_subscription",
            resource_id=str(subscription_id),
            outcome=AuditOutcome.FAILURE,
            metadata={
                "plan_id": str(plan_id),
                "payer_tenant_id": str(payer_tenant_id),
                "merchant_account_id": str(merchant.id),
                "provider": merchant.provider,
                "provider_subscription_id": provider_subscription_id,
                "refusal": type(refusal).__name__,
            },
        )


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
          -> applied only through an allowed transition, in a transaction
             that re-authorizes the caller and audits the change

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
    require_billing_caller(caller)
    operation = "billing.subscription.reconcile_status"
    checks = [(service_tenant_id, BILLING_SUBSCRIPTION, "read")]
    _authorize_initially(caller, checks, operation=operation, tenant_id=service_tenant_id)
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
    updated, previous, changed = _apply_provider_state(
        service_tenant_id,
        subscription_id,
        state,
        caller=caller,
        checks=checks,
        operation=operation,
    )
    return SubscriptionReconciliation(
        subscription_id=subscription_id,
        previous_status=previous,
        status=updated.status,
        provider_state=state,
        changed=changed,
    )


# --- Cancellation -------------------------------------------------------------


class CancellationCapacity(enum.StrEnum):
    """In which commercial capacity a caller cancels a subscription
    (ADR-0029 amendment, "Lifecycle and cancellation authority"). Each is
    checked against the subscription's own canonical row -- never inferred
    from the tenant hierarchy:

        service_tenant  `billing.subscription:cancel` on `Subscription.tenant_id`
        payer           `billing.account:charge` on the subscription's recorded payer
        merchant        `billing.merchant:manage` on the owner of the
                        subscription's merchant account
    """

    SERVICE_TENANT = "service_tenant"
    PAYER = "payer"
    MERCHANT = "merchant"


_CANCEL_OPERATION = "billing.subscription.cancel"


def _cancellation_authority(
    session: Session,
    caller: object,
    capacity: CancellationCapacity,
    *,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    lock: bool,
) -> tuple[AuthorizedBillingCaller, Subscription]:
    """Authorize `caller` to cancel one subscription in `capacity`, in
    `session` (scoped to the service tenant), and return the row.

    For the service tenant, authority is checked first and a missing row is
    `SubscriptionNotFoundError`, as before. For the payer or the merchant,
    the party is read from the canonical row (and, for the merchant, its
    billing account under the payer's own RLS scope) -- never from input --
    and a missing row, a row with no such party, and a denial are all the
    same `BillingNotAuthorizedError`, so no capacity can probe for another
    tenant's subscriptions. With `lock`, the row is held `FOR UPDATE`."""
    query = select(Subscription).where(
        Subscription.id == subscription_id, Subscription.tenant_id == service_tenant_id
    )
    if lock:
        query = query.with_for_update()
    if capacity is CancellationCapacity.SERVICE_TENANT:
        authorized = authorize_billing(
            caller,
            [(service_tenant_id, BILLING_SUBSCRIPTION, "cancel")],
            operation=_CANCEL_OPERATION,
            session=session,
        )
        row = session.execute(query).scalar_one_or_none()
        if row is None:
            raise SubscriptionNotFoundError(service_tenant_id, subscription_id)
        return authorized, row

    require_billing_caller(caller)
    row = session.execute(query).scalar_one_or_none()
    if row is None or row.payer_tenant_id is None or row.billing_account_id is None:
        raise BillingNotAuthorizedError(_CANCEL_OPERATION)
    if capacity is CancellationCapacity.PAYER:
        check = (row.payer_tenant_id, BILLING_ACCOUNT, "charge")
    else:
        with bind_tenant_scope(session, row.payer_tenant_id):
            account = session.execute(
                select(BillingAccount).where(
                    BillingAccount.id == row.billing_account_id,
                    BillingAccount.tenant_id == row.payer_tenant_id,
                )
            ).scalar_one_or_none()
        if account is None or account.merchant_account_id != row.merchant_account_id:
            raise BillingNotAuthorizedError(_CANCEL_OPERATION)
        check = (account.merchant_tenant_id, BILLING_MERCHANT, "manage")
    authorized = authorize_billing(caller, [check], operation=_CANCEL_OPERATION, session=session)
    return authorized, row


def cancel_commercial_subscription(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    provider: BillingProvider | None = None,
    acting_as: CancellationCapacity = CancellationCapacity.SERVICE_TENANT,
) -> SubscribeResult:
    """Immediately cancel a *verified* commercial subscription, as its
    service tenant (default), its payer or its merchant -- `acting_as`,
    authorized by `_cancellation_authority()` (Phase 5.3 step 5). An
    unrelated tenant and a support-access grant (which can satisfy none of
    the three mutation actions, ADR-0031 amendment) cannot cancel. Phase 3
    cancellation safety:

    - already `canceled` locally -> no provider call, returned unchanged
      (idempotent);
    - the provider reference is re-verified before the provider is
      touched (`ProviderReferenceMismatchError` otherwise);
    - authority is checked before the provider is touched; the provider is
      asked to cancel through `cancel_at_provider()`, which tolerates a
      provider that has *already* canceled -- confirmed by the provider's
      own `canceled` state, never assumed from `not_found` or an outage,
      both of which raise and leave the local row as it was;
    - only then, in a transaction that re-authorizes the caller in the same
      capacity against the locked row, is the local row moved to `canceled`
      (an allowed transition from every live state), the projection event
      appended and the cancellation audited (naming the capacity).

    If the provider cancels but the local write fails -- or the caller's
    authority is revoked between the provider call and the final
    transaction -- the row stays live locally; a retry of this function
    (the provider then confirms `canceled`) or
    `reconcile_subscription_status()` brings it to `canceled`.
    Cancel-at-period-end and reactivation are later phases."""
    require_billing_caller(caller)
    capacity = CancellationCapacity(acting_as)
    with tenant_session_scope(service_tenant_id) as session:
        _, row = _cancellation_authority(
            session,
            caller,
            capacity,
            service_tenant_id=service_tenant_id,
            subscription_id=subscription_id,
            lock=False,
        )
        session.expunge(row)
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
        authorized, locked = _cancellation_authority(
            session,
            caller,
            capacity,
            service_tenant_id=service_tenant_id,
            subscription_id=subscription_id,
            lock=True,
        )
        previous = locked.status
        changed = set_subscription_status(locked, SubscriptionStatus.CANCELED)
        session.flush()
        if changed:
            announce_subscription_change(session, locked)
            record_billing_audit(
                session,
                authorized,
                tenant_id=service_tenant_id,
                action="billing.subscription_canceled",
                resource_type="billing_subscription",
                resource_id=str(subscription_id),
                metadata={
                    "previous_status": previous,
                    "canceled_as": capacity.value,
                    "payer_tenant_id": str(locked.payer_tenant_id),
                    "merchant_account_id": str(locked.merchant_account_id),
                },
            )
        session.refresh(locked)
        session.expunge(locked)
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
    `billing.subscription:create` on the service tenant) -- first before
    the provider is asked, and again in the final transaction. Then, in
    order, failing closed with the row unchanged at every step:

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
    6. in one transaction: the caller is re-authorized, both tenants'
       lifecycles are fenced, payer, billing account, merchant and provider
       are recorded, the status is set from the provider state, the row
       becomes `verified`, and `billing.subscription_reconciled` is audited
       -- or, if that would give the service tenant a second live
       subscription at the merchant, `LiveSubscriptionExistsError` and
       nothing is written."""
    require_billing_caller(caller)
    operation = "billing.subscription.reconcile_legacy"
    checks = [
        (payer_tenant_id, BILLING_ACCOUNT, "charge"),
        (service_tenant_id, BILLING_SUBSCRIPTION, "create"),
    ]
    _authorize_initially(caller, checks, operation=operation, tenant_id=service_tenant_id)
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

    account, merchant, active_provider = _resolve_legacy_merchant_context(
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
            authorized = authorize_billing(caller, checks, operation=operation, session=session)
            lock_open_tenant(session, service_tenant_id)
            lock_open_tenant(session, payer_tenant_id)
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
            announce_subscription_change(session, locked)
            record_billing_audit(
                session,
                authorized,
                tenant_id=service_tenant_id,
                action="billing.subscription_reconciled",
                resource_type="billing_subscription",
                resource_id=str(subscription_id),
                metadata={
                    "payer_tenant_id": str(account.tenant_id),
                    "billing_account_id": str(account.id),
                    "merchant_account_id": str(merchant.id),
                    "previous_status": previous,
                    "status": locked.status,
                    "provider_state": state.value,
                },
            )
            session.refresh(locked)
            session.expunge(locked)
    except IntegrityError as exc:
        if _violates_one_live_invariant(exc):
            raise LiveSubscriptionExistsError(service_tenant_id, merchant.id) from None
        raise
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
