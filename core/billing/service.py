"""Plan/subscription management and entitlement lookup
(docs/IMPLEMENTATION-ROADMAP.md Phase 5.1).

`create_plan`/`get_plan`/`list_plans` operate on the global plan catalog
(`core.billing_plans`) via plain `infra.db.session_scope()` -- mirroring
how `core/feature_flags`'s `create_flag`/`get_flag`/`list_flags` read the
equally-global `core.feature_flags` table. A plan *definition* has no
tenant to attribute a change to, so -- again mirroring `core/feature_flags`'
own precedent -- these three functions do not write to `core.audit_log`.

`subscribe`/`upgrade_subscription`/`cancel_subscription` are the tenant-
scoped mutations (`core/billing/models.py`'s own docstring), so they take
an explicit `tenant_id`, use `infra.db.tenant_session_scope()`, and --
these are privileged, revenue-relevant lifecycle mutations, the same
"business-privileged" class of event `core/api_keys`' create/revoke
already establishes -- each writes one `core.audit_log` entry. Never
routine/high-volume (subscription lifecycle changes are inherently rare
per tenant), so none of the "should this be audited" ambiguity
`core/webhooks`/`core/notifications` had to resolve applies here.

Every mutation calls a `BillingProvider` (`core/billing/provider.py`)
first, and only updates Core's own `core.billing_subscriptions` row after
the provider confirms the operation succeeded -- if the provider call
raises, no local state changes, avoiding a Core record that claims a
subscription state the provider never actually applied.

`provider` is an explicit, optional parameter on every mutating function,
defaulting to a lazily-constructed `StripeBillingProvider`
(`core/billing/stripe_provider.py`) reading `STRIPE_API_KEY` through
`infra.secrets.get_secrets_provider()` -- never `os.environ` directly.
Tests substitute `core/billing/provider.py::FakeBillingProvider` instead,
proving the abstraction isn't leaky (docs/IMPLEMENTATION-ROADMAP.md Phase
5.1's own Tests requirement).

**Hierarchy-aware entitlement resolution (architecture research Phase H --
"Hierarchy-Aware Billing & Usage").** `resolve_billing_owner()` is the
one, explicit, deterministic function deciding whose `Subscription` a
billing operation should consult -- `get_entitlements()`,
`upgrade_subscription()`, and `cancel_subscription()` all resolve through
it (billing-owner consistency repair). For a flat tenant
(`inherits_billing=False`, the default) the owner is always the tenant
itself, so every one of these functions is byte-for-byte unchanged in
behavior for any tenant that never opts into inheritance.

`subscribe()` is the one exception: it does NOT redirect to the resolved
owner. Redirecting would mean mutating a tenant other than the one
literally supplied, with no explicit authorization for that in this
phase, so `subscribe()` fails closed (`InheritedBillingSubscriptionError`)
when called directly on a tenant with `inherits_billing=True`, rather
than silently creating an orphaned subscription on the child or an
unauthorized one on the parent. A caller that wants to subscribe the
resolved owner calls `resolve_billing_owner()` itself first, then
`subscribe(owner_id, ...)` -- which succeeds normally, since a resolved
owner never itself inherits.

Billing inheritance is never authorization inheritance: nothing in this
module is consulted by, or feeds into, `core/rbac/authorization.py::can()`.

**Legacy trusted path (Billing Foundation v2 Phase 2,
docs/ADR/0029-commercial-parties-and-billing-relationships.md).** The
subscription mutations in this module -- `subscribe()`,
`subscribe_idempotent()`, `upgrade_subscription()`,
`cancel_subscription()` -- predate the commercial party model and are kept
behavior-compatible for existing in-process callers. They perform **no
authorization of their own**: `actor_user_id` is audit attribution only
(`None` is audited as `ActorType.SYSTEM`), exactly as before. A consumer
exposing them to an end user must authorize first. They cannot name a
payer: a subscription they create records no payer
(`payer_tenant_id`/`billing_account_id` NULL -- the service tenant is
implicitly its own payer, as it always was) and so cannot be used to
charge another tenant. The authorized commercial entry point, which
records the payer and enforces dual authorization through
`core.rbac.can()`, is `core/billing/commercial.py::create_subscription()`.

**`inherits_billing` is frozen legacy behavior** (ADR-0029). It is
preserved here unchanged for existing callers, but no new billing logic
may use it to decide who pays: Phase 7 re-expresses "parent pays for
child" as a sponsored subscription (an explicit payer billing account
with the child as service tenant), never as "the child inherits the
parent's entire subscription and entitlement map".
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.billing.catalog import PlanStatus, validate_entitlements
from core.billing.errors import (
    BillingProviderError,
    DuplicatePlanKeyError,
    EntitlementDeniedError,
    InheritedBillingSubscriptionError,
    InvalidBillingHierarchyError,
    InvalidPlanKeyError,
    LegacyBillingPathError,
    PlanNotEligibleError,
    PlanNotFoundError,
    SubscriptionNotFoundError,
)
from core.billing.lifecycle import (
    ENTITLEMENT_GRANTING_STATUSES,
    SubscriptionStatus,
    VerificationState,
    set_subscription_status,
)
from core.billing.models import Plan, Subscription
from core.billing.projections import announce_subscription_change
from core.billing.provider import BillingProvider, ProviderSubscriptionState
from core.idempotency import (
    IdempotencyStatus,
    begin_idempotent_operation,
    finalize_idempotent_operation,
)
from core.tenancy import Tenant, get_ancestor_chain, get_tenant, require_open_tenant
from infra.db import IntegrityError, Session, select, session_scope, tenant_session_scope
from infra.secrets import get_secrets_provider

_MAX_KEY_LENGTH = 100


def _validate_key(key: str) -> None:
    if not key or not key.strip():
        raise InvalidPlanKeyError("key must be a non-empty string.")
    if len(key) > _MAX_KEY_LENGTH:
        raise InvalidPlanKeyError(f"key exceeds {_MAX_KEY_LENGTH} characters.")


def cancel_at_provider(provider: BillingProvider, provider_subscription_id: str) -> None:
    """Cancel at the provider, tolerating a provider that has *already*
    canceled (Billing Foundation v2 Phase 3 -- cancellation safety).

    If the provider's cancel call fails, the provider is asked for the
    subscription's authoritative state (`get_subscription_status()`): only a
    positively confirmed `canceled` state counts as "already done". Anything
    else -- `not_found` (ambiguous: never assumed canceled), `active`,
    `unknown`, or a provider that cannot be asked -- re-raises the original
    failure, so a local subscription is never marked canceled on
    uncertainty. A retry after a provider-side success whose local update
    failed therefore converges: the second cancel fails at the provider,
    the provider confirms `canceled`, and the caller proceeds to record it.
    """
    try:
        provider.cancel_subscription(provider_subscription_id=provider_subscription_id)
    except BillingProviderError:
        get_status = getattr(provider, "get_subscription_status", None)
        if get_status is None:
            raise
        try:
            state = get_status(provider_subscription_id=provider_subscription_id)
        except BillingProviderError:
            state = None
        if state != ProviderSubscriptionState.CANCELED:
            raise


def provider_name(provider: BillingProvider) -> str | None:
    """`provider.name` (`BillingProvider.name`), or `None` for an adapter
    that predates the attribute -- recorded as `Subscription.provider`."""
    name = getattr(provider, "name", None)
    return name if isinstance(name, str) and name else None


def require_service_tenant_owns_billing(tenant: Tenant) -> None:
    """Refuse to create a subscription for a service tenant that inherits
    billing: `get_entitlements()` would keep reading its resolved owner's
    plan, leaving the new row orphaned (`InheritedBillingSubscriptionError`).
    Used by both the legacy `subscribe()` path and
    `core/billing/commercial.py::create_subscription()` -- the frozen
    `inherits_billing` flag is read here only to *refuse*, never to decide
    a payer (ADR-0029)."""
    if tenant.inherits_billing:
        raise InheritedBillingSubscriptionError(tenant.id)


def _default_provider() -> BillingProvider:
    from core.billing.stripe_provider import StripeBillingProvider

    api_key = get_secrets_provider().get_required("STRIPE_API_KEY")
    return StripeBillingProvider(api_key=api_key)


# --- Plan catalog (global) ------------------------------------------------


def create_plan(
    key: str,
    name: str,
    *,
    entitlements: dict[str, object] | None = None,
    provider_price_id: str | None = None,
) -> Plan:
    """Create a **legacy** plan: no owner, no merchant, in the
    pre-Catalog-v2 key namespace (its key is unique among legacy plans).
    It works with the legacy key-addressed paths (`get_plan()`,
    `subscribe()`) and is never eligible in the Catalog v2 predicate until
    an operator adopts it (`core/billing/catalog.py::adopt_legacy_plan()`).
    New plans should be created with `catalog.create_owned_plan()`."""
    _validate_key(key)
    validated_entitlements = validate_entitlements(entitlements)
    try:
        with session_scope() as session:
            plan = Plan(
                key=key,
                name=name,
                provider_price_id=provider_price_id,
                entitlements=validated_entitlements,
                legacy=True,
            )
            session.add(plan)
            session.flush()
            session.refresh(plan)
            session.expunge(plan)
            return plan
    except IntegrityError as exc:
        raise DuplicatePlanKeyError(key) from exc


def get_plan(key: str) -> Plan:
    """Resolve a plan by key in the **legacy** key namespace -- the only
    namespace where a key alone is unambiguous (owned Catalog v2 plans are
    unique per owner, so two owners may share a key). Used by the legacy
    key-addressed paths. Catalog v2 listing is
    `core/billing/catalog.py::list_plans()`, which is eligibility-filtered;
    there is no unrestricted plan enumeration."""
    with session_scope() as session:
        plan = session.execute(
            select(Plan).where(Plan.key == key, Plan.legacy.is_(True))
        ).scalar_one_or_none()
        if plan is None:
            raise PlanNotFoundError(key)
        session.expunge(plan)
        return plan


# --- Subscriptions (tenant-owned) ------------------------------------------


def subscribe(
    tenant_id: uuid.UUID,
    plan_key: str,
    *,
    provider: BillingProvider | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> Subscription:
    """Create a subscription for `tenant_id` against the plan identified
    by `plan_key`. Calls the provider first; only persists a
    `Subscription` row once the provider confirms creation succeeded.

    **Fails closed for a tenant that inherits billing (architecture
    research Phase H billing-owner consistency repair)**: a tenant with
    `inherits_billing=True` does not own its own billing -- letting it
    create its own `Subscription` row here would produce exactly the
    "multiple billing owners" ambiguity `resolve_billing_owner()`'s own
    docstring forbids, since `get_entitlements()` would keep reading the
    resolved owner's plan regardless, leaving this row orphaned and
    never consulted. This function deliberately does NOT redirect and
    create a subscription for the resolved owner instead -- that would be
    a mutation on a tenant other than the one literally supplied, with no
    explicit authorization for it in this phase (`InheritedBillingSubscriptionError`'s
    own docstring). A caller that wants to subscribe the resolved owner
    calls `resolve_billing_owner(tenant_id)` itself first, then
    `subscribe(owner_id, ...)` -- which succeeds normally, since an owner
    returned by `resolve_billing_owner()` never itself inherits.

    **Legacy trusted path** (module docstring): no authorization is
    performed here; `actor_user_id` is audit attribution only. The created
    row records the adapter's `provider` name but no payer
    (`payer_tenant_id`/`billing_account_id` stay NULL).
    """
    tenant = require_open_tenant(tenant_id)
    require_service_tenant_owns_billing(tenant)

    plan = get_plan(plan_key)
    _refuse_withdrawn(tenant_id, plan)
    active_provider = provider or _default_provider()

    provider_subscription_id = active_provider.create_subscription(tenant_id=tenant_id, plan=plan)

    with tenant_session_scope(tenant_id) as session:
        _refuse_withdrawn(tenant_id, plan, session)
        subscription = Subscription(
            tenant_id=tenant_id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            provider_subscription_id=provider_subscription_id,
            provider=provider_name(active_provider),
            # Phase 3: the legacy path's `active` is an unconfirmed claim
            # (ADR-0029, Decision 0.5) -- explicitly marked as such.
            verification=VerificationState.LEGACY_UNVERIFIED.value,
        )
        session.add(subscription)
        session.flush()
        announce_subscription_change(session, subscription, created=True)
        session.refresh(subscription)
        session.expunge(subscription)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="billing.subscription_created",
        resource_type="billing_subscription",
        resource_id=str(subscription.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"plan_key": plan_key},
    )
    return subscription


@dataclass(frozen=True)
class SubscribeResult:
    """A small, JSON-serializable summary of `subscribe()`'s outcome --
    what `subscribe_idempotent()` stores and hands back on replay
    (P1.11). Never the full ORM `Subscription` object (not JSON-
    serializable, and reconstructing one from a stored dict would imply
    a second, parallel "load a Subscription" code path)."""

    subscription_id: uuid.UUID
    plan_id: uuid.UUID
    status: str
    provider_subscription_id: str
    # Billing Foundation v2 Phase 2 -- optional, so a result stored by an
    # earlier version (no such keys) still replays.
    payer_tenant_id: uuid.UUID | None = None
    billing_account_id: uuid.UUID | None = None
    provider: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "subscription_id": str(self.subscription_id),
            "plan_id": str(self.plan_id),
            "status": self.status,
            "provider_subscription_id": self.provider_subscription_id,
            "payer_tenant_id": _optional_str(self.payer_tenant_id),
            "billing_account_id": _optional_str(self.billing_account_id),
            "provider": self.provider,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SubscribeResult:
        return cls(
            subscription_id=uuid.UUID(str(data["subscription_id"])),
            plan_id=uuid.UUID(str(data["plan_id"])),
            status=str(data["status"]),
            provider_subscription_id=str(data["provider_subscription_id"]),
            payer_tenant_id=_optional_uuid(data.get("payer_tenant_id")),
            billing_account_id=_optional_uuid(data.get("billing_account_id")),
            provider=str(data["provider"]) if data.get("provider") is not None else None,
        )

    @classmethod
    def from_subscription(cls, subscription: Subscription) -> SubscribeResult:
        return cls(
            subscription_id=subscription.id,
            plan_id=subscription.plan_id,
            status=subscription.status,
            provider_subscription_id=subscription.provider_subscription_id,
            payer_tenant_id=subscription.payer_tenant_id,
            billing_account_id=subscription.billing_account_id,
            provider=subscription.provider,
        )


def _optional_str(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


def _optional_uuid(value: object) -> uuid.UUID | None:
    return uuid.UUID(str(value)) if value is not None else None


def subscribe_idempotent(
    tenant_id: uuid.UUID,
    plan_key: str,
    idempotency_key: str,
    *,
    provider: BillingProvider | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, SubscribeResult]:
    """P1.11: the idempotent counterpart to `subscribe()` -- real
    duplicate-side-effect risk, since `subscribe()` calls a
    `BillingProvider` (Stripe in production): a naive client retry after
    an ambiguous response (timeout, dropped connection) would otherwise
    create a second real subscription and double-bill the tenant.
    `core.billing_subscriptions` itself has no uniqueness constraint
    preventing this (`get_entitlements()`'s own docstring: "nothing in
    this schema enforces at most one active subscription per tenant").

    Uses `core.idempotency`'s two-step primitive
    (`begin_idempotent_operation()`/`finalize_idempotent_operation()`),
    never the fully-atomic `run_idempotent()` -- `subscribe()`'s external
    provider call cannot run inside the idempotency record's own
    database transaction. See `core/idempotency/service.py`'s own module
    docstring for the exact, documented limitation this implies (a crash
    between the provider call succeeding and this function's own
    `finalize_idempotent_operation()` call leaves the reservation
    `pending` until `IDEMPOTENCY_PENDING_TTL_SECONDS` elapses) and the
    guarantee it still holds (two *concurrent* callers can never both
    reach the provider for the same key).

    Fingerprint payload is `{"plan_key": plan_key}` -- the one input that
    actually determines what `subscribe()` would do; `actor_user_id`
    varies the audit trail, never the resulting subscription, so it is
    deliberately excluded (two audit-attribution-only-different retries
    of the same logical request are still the same request).

    Returns `(is_replay, result)`.

    **Billing-owner consistency repair (architecture research Phase H)**:
    `tenant_id` (never a resolved owner) is what the idempotency record
    itself is scoped and fingerprinted by -- deliberately unchanged, since
    `subscribe()` no longer redirects to any other tenant at all (it
    fails closed instead, `InheritedBillingSubscriptionError`, for a
    tenant that inherits billing). That failure propagates through the
    `except Exception` branch below exactly like any other `subscribe()`
    failure: finalized as `FAILED`, never cached as a success, so a later
    retry (e.g. after the tenant's `inherits_billing` flag is changed)
    re-evaluates fresh -- mirroring `consume_quota_idempotent()`'s own
    "a business-logic failure is never cached" discipline.
    """
    reservation = begin_idempotent_operation(
        tenant_id, "billing.subscribe", idempotency_key, {"plan_key": plan_key}
    )
    if reservation.is_replay:
        assert reservation.result is not None
        return True, SubscribeResult.from_dict(reservation.result)

    try:
        subscription = subscribe(
            tenant_id, plan_key, provider=provider, actor_user_id=actor_user_id
        )
    except Exception:
        finalize_idempotent_operation(
            tenant_id, reservation.record_id, status=IdempotencyStatus.FAILED
        )
        raise

    result = SubscribeResult.from_subscription(subscription)
    finalize_idempotent_operation(
        tenant_id,
        reservation.record_id,
        status=IdempotencyStatus.SUCCEEDED,
        result=result.to_dict(),
    )
    return False, result


def _refuse_commercial(subscription: Subscription) -> None:
    """The legacy trusted mutations act only on genuine legacy rows (Phase
    5.3 step 7): a subscription that is verified, or that records a
    commercial relationship (a billing account -- a Phase 2 sponsored row
    is `legacy_unverified` yet names its payer and merchant), carries
    payer and merchant invariants these unauthorized paths cannot uphold
    (`LegacyBillingPathError`); it changes only through the commercial API,
    after `reconcile_legacy_subscription()` where needed. Checked before
    the provider is called and again on the locked row in the writing
    transaction, since a concurrent `reconcile_legacy_subscription()` can
    verify a row."""
    if (
        subscription.verification == VerificationState.VERIFIED.value
        or subscription.billing_account_id is not None
    ):
        raise LegacyBillingPathError(subscription.id)


def _refuse_withdrawn(tenant_id: uuid.UUID, plan: Plan, session: Session | None = None) -> None:
    """A withdrawn plan accepts no new subscription and no plan change onto
    it (ADR-0029 amendment, "Lifecycle and cancellation authority"), on the
    legacy key-addressed paths too: an adopted legacy plan stays in the
    legacy key namespace and can be withdrawn. Checked before the provider
    is called and, given `session`, again in the writing transaction with
    the plan row read `FOR SHARE`, so a concurrent `withdraw_plan()` (which
    updates the row) is serialized with it (`PlanNotEligibleError`)."""
    status = plan.status
    if session is not None:
        status = session.execute(
            select(Plan.status).where(Plan.id == plan.id).with_for_update(read=True)
        ).scalar_one()
    if status == PlanStatus.WITHDRAWN.value:
        raise PlanNotEligibleError(tenant_id, plan.id, "withdrawn")


def upgrade_subscription(
    tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    new_plan_key: str,
    *,
    provider: BillingProvider | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> Subscription:
    """Change `subscription_id`'s plan to `new_plan_key`. Direction-
    agnostic (`core/billing/models.py`'s own docstring) -- "upgrade" is
    this operation's roadmap name, not a validated tier-ordering check.

    **Fails closed for a tenant that inherits billing** (Phase 5.3 step 5,
    `inherits_billing` retired forward): `InheritedBillingSubscriptionError`,
    before anything is read or changed -- the mutation is never redirected to
    an ancestor's subscription any more, and nothing about the tenant
    changes. Checking the flag outside the transaction is sound: it can only
    ever go from `true` to `false` (the database refuses a new `true`), so a
    tenant found not inheriting cannot start inheriting. For every other
    tenant the operation is unchanged: `subscription_id` must be its own.
    """
    tenant = require_open_tenant(tenant_id)
    if tenant.inherits_billing:
        raise InheritedBillingSubscriptionError(tenant_id)
    owner_tenant_id = tenant_id
    subscription = get_subscription(owner_tenant_id, subscription_id)
    _refuse_commercial(subscription)
    new_plan = get_plan(new_plan_key)
    _refuse_withdrawn(tenant_id, new_plan)
    active_provider = provider or _default_provider()

    active_provider.change_plan(
        provider_subscription_id=subscription.provider_subscription_id, plan=new_plan
    )

    with tenant_session_scope(owner_tenant_id) as session:
        row = session.get(Subscription, subscription_id, with_for_update=True)
        if row is None or row.tenant_id != owner_tenant_id:
            raise SubscriptionNotFoundError(owner_tenant_id, subscription_id)
        _refuse_commercial(row)
        _refuse_withdrawn(owner_tenant_id, new_plan, session)
        old_plan_id = row.plan_id
        row.plan_id = new_plan.id
        session.flush()
        announce_subscription_change(session, row)
        session.refresh(row)
        session.expunge(row)
        subscription = row

    metadata: dict[str, object] = {"old_plan_id": str(old_plan_id), "new_plan_key": new_plan_key}
    if owner_tenant_id != tenant_id:
        metadata["requested_tenant_id"] = str(tenant_id)

    record_audit_event(
        tenant_id=owner_tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="billing.subscription_upgraded",
        resource_type="billing_subscription",
        resource_id=str(subscription_id),
        outcome=AuditOutcome.SUCCESS,
        metadata=metadata,
    )
    return subscription


def cancel_subscription(
    tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    *,
    provider: BillingProvider | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> Subscription:
    """Cancel one of `tenant_id`'s own subscriptions (the legacy trusted
    path). Fails closed for a tenant that inherits billing, exactly like
    `upgrade_subscription()` -- `InheritedBillingSubscriptionError` before
    the provider is touched; an ancestor's subscription is never canceled
    through a child."""
    if get_tenant(tenant_id).inherits_billing:
        raise InheritedBillingSubscriptionError(tenant_id)
    owner_tenant_id = tenant_id
    subscription = get_subscription(owner_tenant_id, subscription_id)
    _refuse_commercial(subscription)
    active_provider = provider or _default_provider()

    cancel_at_provider(active_provider, subscription.provider_subscription_id)

    with tenant_session_scope(owner_tenant_id) as session:
        row = session.get(Subscription, subscription_id, with_for_update=True)
        if row is None or row.tenant_id != owner_tenant_id:
            raise SubscriptionNotFoundError(owner_tenant_id, subscription_id)
        _refuse_commercial(row)
        if set_subscription_status(row, SubscriptionStatus.CANCELED):
            session.flush()
            announce_subscription_change(session, row)
        session.refresh(row)
        session.expunge(row)
        subscription = row

    metadata: dict[str, object] | None = None
    if owner_tenant_id != tenant_id:
        metadata = {"requested_tenant_id": str(tenant_id)}

    record_audit_event(
        tenant_id=owner_tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="billing.subscription_canceled",
        resource_type="billing_subscription",
        resource_id=str(subscription_id),
        outcome=AuditOutcome.SUCCESS,
        metadata=metadata,
    )
    return subscription


def get_subscription(tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> Subscription:
    with tenant_session_scope(tenant_id) as session:
        subscription = session.get(Subscription, subscription_id)
        if subscription is None or subscription.tenant_id != tenant_id:
            raise SubscriptionNotFoundError(tenant_id, subscription_id)
        session.expunge(subscription)
        return subscription


def list_subscriptions(tenant_id: uuid.UUID) -> list[Subscription]:
    with tenant_session_scope(tenant_id) as session:
        subscriptions = (
            session.execute(select(Subscription).where(Subscription.tenant_id == tenant_id))
            .scalars()
            .all()
        )
        for subscription in subscriptions:
            session.expunge(subscription)
        return list(subscriptions)


# --- Hierarchy-aware billing ownership (architecture research Phase H --
# "Hierarchy-Aware Billing & Usage") -----------------------------------


def resolve_billing_owner(tenant_id: uuid.UUID) -> uuid.UUID:
    """The one explicit, deterministic billing-owner resolution function
    (architecture research Phase H section 6: "do not duplicate
    billing-owner resolution logic throughout the codebase"). Every
    entitlement read in this module (`get_entitlements()`) calls this
    first; no other function re-implements this walk.

    **Precedence rules** (evaluated in this exact order, terminating at
    the first match):

    1. `tenant_id` must exist (`core.tenancy.TenantNotFoundError`
       propagates unchanged) -- fail closed on an unknown tenant, never
       guess an owner for one.
    2. If `tenant_id`'s own `Tenant.inherits_billing` is `False` (the
       default -- every tenant that predates this phase, and every new
       tenant that does not explicitly opt in) -- `tenant_id` is its own
       billing owner. Terminal. This is the exact, unchanged behavior
       every pre-Phase-H caller of `get_entitlements()` already gets: a
       flat tenant's own `tenant_id` is returned, byte-for-byte the same
       value `get_entitlements()` used to query directly.
    3. Otherwise (`inherits_billing=True`), walk `tenant_id`'s STRICT
       ancestors nearest-first (`core.tenancy.get_ancestor_chain()` --
       one indexed query over the precomputed `core.tenant_ancestry`
       closure table, never a recursive one, and never able to name a
       sibling or an unrelated branch: a closure-table ancestor row is
       structurally always a true ancestor). Return the first ancestor
       whose OWN `inherits_billing` is `False` -- the nearest tenant in
       the chain that actually owns its own billing. This is what makes
       "resolve the nearest applicable ancestor" concrete while
       guaranteeing exactly one owner is ever returned: the walk stops
       at the first non-inheriting node, never continues past it, and an
       inheriting ancestor is transparently skipped (handling "parent
       itself inherits billing" -- the walk simply continues to the next
       ancestor; "multiple ancestors" -- bounded by
       `core.tenancy.TenancyConfig.max_hierarchy_depth`, default 6; and
       "nested tenants" generally).
    4. If no ancestor in the chain has `inherits_billing=False` (a root
       tenant with `inherits_billing=True` and therefore an empty
       ancestor chain, or every ancestor up to the root also inherits) --
       **fail closed**: raise `InvalidBillingHierarchyError` rather than
       falling back to `tenant_id` itself (which would silently
       reactivate billing for a tenant that explicitly opted out) or to
       an arbitrary ancestor (which could be an unrelated or ambiguous
       choice).

    **Never modifies historical billing records** -- this function is
    pure and read-only; it never touches `core.billing_subscriptions` or
    `core.usage_events`. **Never cached**: `core/tenancy`'s hierarchy
    (`Tenant.parent_id`/`core.tenant_ancestry`) can change independently
    at any time via `move_tenant()`, and `Tenant.inherits_billing` can
    only ever change from true to false (Phase 5.3 step 5) -- this
    function always re-evaluates both, fresh, against the live
    database, so a hierarchy move or a flag change takes effect on the
    very next call, with nothing to invalidate (architecture research
    Phase H section 13: "prefer deterministic database-backed
    resolution... avoid caching unless the existing architecture already
    has an appropriate cache/invalidation mechanism" -- it does not, so
    none is introduced).

    **Billing inheritance is NOT authorization inheritance**: this
    function's return value is consumed exclusively by
    `get_entitlements()` (and, transitively, `core/usage`'s quota
    functions) to decide whose `Subscription`/`Plan` to read. It is never
    passed to `core/rbac/authorization.py::can()`, never used to resolve
    a membership, and confers no access to the returned owner's data --
    a child tenant that inherits billing from a parent gains zero
    visibility into, or authority over, that parent's resources.
    """
    tenant = get_tenant(tenant_id)
    if not tenant.inherits_billing:
        return tenant_id

    for ancestor_id in get_ancestor_chain(tenant_id):
        ancestor = get_tenant(ancestor_id)
        if not ancestor.inherits_billing:
            return ancestor_id

    raise InvalidBillingHierarchyError(tenant_id)


# --- Entitlements ------------------------------------------------------


def combine_entitlements(entitlement_maps: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Combine several plans' entitlements, key by key (ADR-0029 amendment,
    "Entitlements across merchants"; Phase 5.3 step 6). `entitlement_maps`
    is ordered newest subscription first.

    - only the plans that define a key contribute to it: a plan that omits
      a key neither grants nor removes anything for it;
    - every value a boolean: `OR`;
    - any value a number (int, float or Decimal, never a bool): `MAX` of
      the numbers -- never a sum: there are no shared usage pools. A
      non-numeric value for the same key never erases a numeric limit
      (post-5.3 audit remediation R4): before it, a mix took the newest
      value, so a newest `true`, `null` or `"100"` read as "no configured
      limit" and made the quota unlimited;
    - otherwise, any value a boolean: `OR` of the booleans;
    - otherwise (only values plan validation now refuses -- possible only
      in plans persisted before it): the newest subscription's value,
      unchanged for compatibility; it is never a numeric limit.

    New plans can hold only booleans and finite non-negative numbers
    (`core.billing.catalog.validate_entitlements()`). Pure and
    deterministic."""
    combined: dict[str, object] = {}
    keys: list[str] = []
    for entitlements in entitlement_maps:
        for key in entitlements:
            if key not in keys:
                keys.append(key)
    for key in keys:
        values = [entitlements[key] for entitlements in entitlement_maps if key in entitlements]
        numbers = [
            value
            for value in values
            if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool)
        ]
        booleans = [value for value in values if isinstance(value, bool)]
        if numbers:
            combined[key] = max(numbers)  # type: ignore[type-var]
        elif booleans:
            combined[key] = any(booleans)
        else:
            combined[key] = values[0]
    return combined


def entitlement_maps_for(tenant_id: uuid.UUID) -> list[dict[str, object]]:
    """The entitlements of every entitlement-granting subscription
    `get_entitlements()` combines for `tenant_id`, newest first -- the
    resolved billing owner's (the tenant itself unless it still inherits,
    Phase 5.3 step 5)."""
    owner_tenant_id = resolve_billing_owner(tenant_id)
    with tenant_session_scope(owner_tenant_id) as session:
        plan_ids = list(
            session.execute(
                select(Subscription.plan_id)
                .where(
                    Subscription.tenant_id == owner_tenant_id,
                    Subscription.status.in_([s.value for s in ENTITLEMENT_GRANTING_STATUSES]),
                )
                .order_by(Subscription.created_at.desc(), Subscription.id)
            ).scalars()
        )
    if not plan_ids:
        return []
    with session_scope() as session:
        plans = {
            plan.id: dict(plan.entitlements)
            for plan in session.execute(select(Plan).where(Plan.id.in_(plan_ids))).scalars()
        }
    return [plans[plan_id] for plan_id in plan_ids if plan_id in plans]


def get_entitlements(tenant_id: uuid.UUID) -> dict[str, object]:
    """The product-agnostic "plan -> feature/limit" lookup
    (docs/ARCHITECTURE-DISCOVERY.md section 14) Product code queries --
    never a Stripe-specific shape. No active subscription -> `{}`, a
    documented, deterministic safe default (mirrors
    `core/feature_flags/service.py::evaluate_flag()`'s own
    safe-default-on-absence convention) rather than an error -- entitlement
    checks are expected to run on every gated action, so "no plan yet"
    must be a normal, cheap case to handle, not an exception path.

    **Every entitlement-granting subscription counts** (Phase 5.3 step 6):
    a service tenant may hold live subscriptions at several merchants
    (at most one per merchant), and its entitlements are their plans'
    entitlements combined by `combine_entitlements()` -- boolean `OR`,
    numeric `MAX`, only keys a plan defines. Before step 6 this read only
    the newest active subscription. Quota enforcement
    (`core.usage.check_quota()`/`consume_quota()`) and
    `require_entitlement()` read exactly this, and so do usage reports.

    **Legacy inheritance (read compatibility only)**: an existing tenant
    that still inherits billing reads `resolve_billing_owner(tenant_id)`'s
    subscriptions; every other tenant reads its own.
    """
    return combine_entitlements(entitlement_maps_for(tenant_id))


def has_entitlement(tenant_id: uuid.UUID, key: str) -> bool:
    """Boolean capability gate (P1.9; docs/ARCHITECTURE-DISCOVERY.md
    section 14): true only if `tenant_id`'s active plan's entitlements
    dict has `key` set to the literal boolean `True`.

    Deliberately distinct from a numeric quota metric
    (`core.usage.service.check_quota()`/`consume_quota()`) even though
    both live in the same `entitlements` dict -- a capability flag
    (`{"advanced_reports": true}`) answers "may this happen at all,"
    a numeric limit (`{"api_calls": 1000}`) answers "how much may
    happen." A missing key, or a non-`True` value (including a numeric
    one, or Python-truthy-but-not-`bool` values), is never treated as
    entitled -- no active subscription -> `{}` -> not entitled is the
    same safe-default-on-absence shape `get_entitlements()` already
    establishes, applied here as "absent means denied" rather than
    "absent means no limit."
    """
    return get_entitlements(tenant_id).get(key) is True


def require_entitlement(tenant_id: uuid.UUID, key: str) -> None:
    """Raise `EntitlementDeniedError` unless `has_entitlement()` is true.
    The raise-based counterpart callers that want a fail-closed gate
    (e.g. `api.dependencies`) use directly, mirroring
    `infra.db.role_guard.validate_application_role()`'s own
    "raise on the unsafe case, return nothing on the safe one" shape."""
    if not has_entitlement(tenant_id, key):
        raise EntitlementDeniedError(tenant_id, key)
