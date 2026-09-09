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
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.billing.errors import (
    DuplicatePlanKeyError,
    EntitlementDeniedError,
    InvalidPlanKeyError,
    PlanNotFoundError,
    SubscriptionNotFoundError,
)
from core.billing.models import Plan, Subscription
from core.billing.provider import BillingProvider
from core.idempotency import (
    IdempotencyStatus,
    begin_idempotent_operation,
    finalize_idempotent_operation,
)
from infra.db import IntegrityError, select, session_scope, tenant_session_scope
from infra.secrets import get_secrets_provider

_MAX_KEY_LENGTH = 100


def _validate_key(key: str) -> None:
    if not key or not key.strip():
        raise InvalidPlanKeyError("key must be a non-empty string.")
    if len(key) > _MAX_KEY_LENGTH:
        raise InvalidPlanKeyError(f"key exceeds {_MAX_KEY_LENGTH} characters.")


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
    _validate_key(key)
    try:
        with session_scope() as session:
            plan = Plan(
                key=key,
                name=name,
                provider_price_id=provider_price_id,
                entitlements=entitlements or {},
            )
            session.add(plan)
            session.flush()
            session.refresh(plan)
            session.expunge(plan)
            return plan
    except IntegrityError as exc:
        raise DuplicatePlanKeyError(key) from exc


def get_plan(key: str) -> Plan:
    with session_scope() as session:
        plan = session.execute(select(Plan).where(Plan.key == key)).scalar_one_or_none()
        if plan is None:
            raise PlanNotFoundError(key)
        session.expunge(plan)
        return plan


def list_plans() -> list[Plan]:
    with session_scope() as session:
        plans = session.execute(select(Plan)).scalars().all()
        for plan in plans:
            session.expunge(plan)
        return list(plans)


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
    `Subscription` row once the provider confirms creation succeeded."""
    plan = get_plan(plan_key)
    active_provider = provider or _default_provider()

    provider_subscription_id = active_provider.create_subscription(tenant_id=tenant_id, plan=plan)

    with tenant_session_scope(tenant_id) as session:
        subscription = Subscription(
            tenant_id=tenant_id,
            plan_id=plan.id,
            status="active",
            provider_subscription_id=provider_subscription_id,
        )
        session.add(subscription)
        session.flush()
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

    def to_dict(self) -> dict[str, object]:
        return {
            "subscription_id": str(self.subscription_id),
            "plan_id": str(self.plan_id),
            "status": self.status,
            "provider_subscription_id": self.provider_subscription_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SubscribeResult:
        return cls(
            subscription_id=uuid.UUID(str(data["subscription_id"])),
            plan_id=uuid.UUID(str(data["plan_id"])),
            status=str(data["status"]),
            provider_subscription_id=str(data["provider_subscription_id"]),
        )

    @classmethod
    def from_subscription(cls, subscription: Subscription) -> SubscribeResult:
        return cls(
            subscription_id=subscription.id,
            plan_id=subscription.plan_id,
            status=subscription.status,
            provider_subscription_id=subscription.provider_subscription_id,
        )


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
    this operation's roadmap name, not a validated tier-ordering check."""
    subscription = get_subscription(tenant_id, subscription_id)
    new_plan = get_plan(new_plan_key)
    active_provider = provider or _default_provider()

    active_provider.change_plan(
        provider_subscription_id=subscription.provider_subscription_id, plan=new_plan
    )

    with tenant_session_scope(tenant_id) as session:
        row = session.get(Subscription, subscription_id)
        if row is None or row.tenant_id != tenant_id:
            raise SubscriptionNotFoundError(tenant_id, subscription_id)
        old_plan_id = row.plan_id
        row.plan_id = new_plan.id
        session.flush()
        session.refresh(row)
        session.expunge(row)
        subscription = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="billing.subscription_upgraded",
        resource_type="billing_subscription",
        resource_id=str(subscription_id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"old_plan_id": str(old_plan_id), "new_plan_key": new_plan_key},
    )
    return subscription


def cancel_subscription(
    tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    *,
    provider: BillingProvider | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> Subscription:
    subscription = get_subscription(tenant_id, subscription_id)
    active_provider = provider or _default_provider()

    active_provider.cancel_subscription(
        provider_subscription_id=subscription.provider_subscription_id
    )

    with tenant_session_scope(tenant_id) as session:
        row = session.get(Subscription, subscription_id)
        if row is None or row.tenant_id != tenant_id:
            raise SubscriptionNotFoundError(tenant_id, subscription_id)
        row.status = "canceled"
        session.flush()
        session.refresh(row)
        session.expunge(row)
        subscription = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="billing.subscription_canceled",
        resource_type="billing_subscription",
        resource_id=str(subscription_id),
        outcome=AuditOutcome.SUCCESS,
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


# --- Entitlements ------------------------------------------------------


def get_entitlements(tenant_id: uuid.UUID) -> dict[str, object]:
    """The product-agnostic "plan -> feature/limit" lookup
    (docs/ARCHITECTURE-DISCOVERY.md section 14) Product code queries --
    never a Stripe-specific shape. No active subscription -> `{}`, a
    documented, deterministic safe default (mirrors
    `core/feature_flags/service.py::evaluate_flag()`'s own
    safe-default-on-absence convention) rather than an error -- entitlement
    checks are expected to run on every gated action, so "no plan yet"
    must be a normal, cheap case to handle, not an exception path.

    Nothing in this schema enforces at most one `"active"` subscription
    per tenant (no uniqueness constraint -- `core/billing/models.py`), so
    this deliberately orders by `created_at` descending and takes the
    most recent rather than `scalar_one_or_none()`, which would raise
    `MultipleResultsFound` if a caller ever created a second active
    subscription without canceling the first.
    """
    with tenant_session_scope(tenant_id) as session:
        subscription = session.execute(
            select(Subscription)
            .where(Subscription.tenant_id == tenant_id, Subscription.status == "active")
            .order_by(Subscription.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if subscription is None:
            return {}
        plan_id = subscription.plan_id

    with session_scope() as session:
        plan = session.get(Plan, plan_id)
        if plan is None:
            return {}
        return dict(plan.entitlements)


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
