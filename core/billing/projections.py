"""Seller and payer projections of commercial subscriptions (Phase 5.3
step 4; docs/ADR/0029-commercial-parties-and-billing-relationships.md,
"Seller and payer projections").

**The subscription is the source of truth.** `core.billing_subscriptions`
alone decides whether a subscription exists, its status, who pays, who
sells, and every entitlement. The two tables here are read models for
discovery only:

    core.billing_seller_subscriptions  owned (RLS) by the merchant's owner
                                       tenant -- "what was sold through my
                                       merchant account";
    core.billing_payer_subscriptions   owned (RLS) by the payer tenant --
                                       "what is charged to my billing
                                       account".

The service tenant reads its own subscription through the canonical row
(`core/billing/service.py::get_subscription()`); it has no access to
either projection unless it is also the seller or the payer. Neither
projection carries a provider reference or a provider customer.

**How they stay current** (transactional outbox, ADR-0032/0033; RE-5,
ADR-0036):

    canonical change (insert, status, plan, payer)  +  version = version + 1
      +  outbox event `billing.subscription_changed`   -- one transaction
      -> dispatcher -> `_project_subscription_job()`
      -> reads the CURRENT canonical row (never the event's claims)
      -> version-fenced upsert into the seller projection (merchant's scope)
      -> version-fenced upsert into the payer projection (payer's scope)
      -> records its RE-5 consumption

`announce_subscription_change()` is the only producer: every billing
function that changes a subscription calls it in the same transaction as
the change (pinned by a static test), so a rolled-back change leaves no
event, and a committed change always has one.

**Integrity of the consumer.**

- The event names only a subscription id and the version it announced, and
  the outbox row's tenant (set by the producer's own tenant-scoped
  transaction) is the service tenant. The consumer re-reads the
  subscription under that tenant's RLS scope; a subscription that does
  not exist there is a malformed event (dead-lettered). Seller, payer,
  merchant, plan and status all come from the canonical row and its
  billing account -- never from the event -- so an event cannot place a
  projection row in an arbitrary tenant.
- Every projection write is fenced by `source_version`: a newer canonical
  version is applied, the same or an older one is a no-op. Because the
  consumer projects the current canonical state, duplicate, retried,
  reordered or concurrent deliveries all converge on the newest version
  and can never regress it.
- RE-5 (`core.outbox.event_consumption_recorded()` / `record_event_
  consumption()`, consumer `billing.subscription_changed`) short-circuits a
  repeated delivery once completion is recorded. The projection writes are
  in the merchant's and payer's own transactions -- separate tenants, so
  never one transaction with the record (ADR-0029) -- which is safe
  precisely because they are version-fenced and idempotent.
- The consumer never calls a provider and never writes a canonical row. A
  projection owner whose tenant is closed is skipped.

**Eventual consistency.** A projection reflects a change after the
dispatcher has processed its event (`OUTBOX_POLL_SECONDS` plus queue time
when healthy; later under retries, never lost). Each view carries the
canonical `source_version` and `projected_at` it reflects. A commercial
subscription that existed before this step appears once it next changes;
a rebuild operation is deferred.

**Reads** take a billing caller and are authorized with `can(session=...)`
in the reading transaction, under the owner's RLS scope:

    list_seller_subscriptions / get_seller_subscription
        billing.merchant:manage  on the merchant's owner tenant
    list_payer_subscriptions / get_payer_subscription
        billing.account:read     on the payer tenant

`billing.merchant:manage` is a billing mutation action, so a support
grant -- which never satisfies one (ADR-0031 amendment) -- cannot read the
seller projection; `billing.account:read` is a read and follows the normal
support policy. Reads are not audited (not billing mutations).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from core.billing.authorization import (
    BILLING_ACCOUNT,
    BILLING_MERCHANT,
    authorize_billing,
    require_billing_caller,
)
from core.billing.errors import (
    MalformedProjectionEventError,
    ProjectionNotReadyError,
    SubscriptionProjectionNotFoundError,
)
from core.billing.lifecycle import SubscriptionStatus
from core.billing.models import (
    BillingAccount,
    PayerSubscription,
    SellerSubscription,
    Subscription,
)
from core.outbox import append_event, event_consumption_recorded, record_event_consumption
from core.tenancy import TenantClosedError, lock_open_tenant
from infra.db import IntegrityError, Session, bind_tenant_scope, select, tenant_session_scope
from infra.jobs import TenantJobContext, TenantJobPayload

logger = logging.getLogger(__name__)

SUBSCRIPTION_CHANGED_EVENT_TYPE = "billing.subscription_changed"
_AGGREGATE_TYPE = "billing_subscription"


# --- Producer ---------------------------------------------------------------------------


def announce_subscription_change(
    session: Session, subscription: Subscription, *, created: bool = False
) -> uuid.UUID | None:
    """Record, in `session` -- the transaction that changed `subscription`
    -- the new canonical version and the projection event announcing it.

    For an existing row (`created=False`) the version is incremented in SQL
    (`version = version + 1`), so two transactions changing one row can
    never compute the same version. A new row keeps version 1. The event
    is appended only for a commercial subscription (one with a payer and a
    merchant); a legacy row without them has nothing to project and gets
    only its version. Returns the outbox event id, if any."""
    if not created:
        subscription.version = Subscription.version + 1  # type: ignore[assignment]
    session.flush()
    session.refresh(subscription, ["version"])
    if subscription.billing_account_id is None or subscription.merchant_account_id is None:
        return None
    return append_event(
        session,
        tenant_id=subscription.tenant_id,
        event_type=SUBSCRIPTION_CHANGED_EVENT_TYPE,
        aggregate_type=_AGGREGATE_TYPE,
        aggregate_id=str(subscription.id),
        payload={"subscription_id": str(subscription.id), "version": subscription.version},
    )


# --- Consumer ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CanonicalSnapshot:
    subscription_id: uuid.UUID
    service_tenant_id: uuid.UUID
    payer_tenant_id: uuid.UUID
    billing_account_id: uuid.UUID
    merchant_tenant_id: uuid.UUID
    merchant_account_id: uuid.UUID
    plan_id: uuid.UUID
    status: str
    verification: str
    created_at: datetime
    updated_at: datetime
    version: int


def _parse_event(data: Mapping[str, object]) -> tuple[uuid.UUID, int]:
    try:
        subscription_id = uuid.UUID(str(data["subscription_id"]))
        version = data["version"]
    except (KeyError, ValueError) as exc:
        raise MalformedProjectionEventError(
            f"invalid subscription projection event ({type(exc).__name__})"
        ) from exc
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise MalformedProjectionEventError("invalid subscription projection event (version)")
    return subscription_id, version


def _canonical_snapshot(
    service_tenant_id: uuid.UUID, subscription_id: uuid.UUID
) -> _CanonicalSnapshot | None:
    """The subscription as it is now, read under the event tenant's own RLS
    scope, plus its billing account's merchant tenant (read under the
    payer's scope). `None` for a subscription with no payer/merchant
    (nothing to project). A subscription that is not in the event's tenant
    is a malformed event."""
    with tenant_session_scope(service_tenant_id) as session:
        row = session.get(Subscription, subscription_id)
        if row is None or row.tenant_id != service_tenant_id:
            raise MalformedProjectionEventError(
                "subscription projection event names no subscription of its tenant"
            )
        if (
            row.payer_tenant_id is None
            or row.billing_account_id is None
            or row.merchant_account_id is None
        ):
            return None
        with bind_tenant_scope(session, row.payer_tenant_id):
            account = session.execute(
                select(BillingAccount).where(
                    BillingAccount.id == row.billing_account_id,
                    BillingAccount.tenant_id == row.payer_tenant_id,
                )
            ).scalar_one_or_none()
        if account is None or account.merchant_account_id != row.merchant_account_id:
            # The composite foreign keys make this unreachable; refuse rather
            # than project an inconsistent relationship.
            raise MalformedProjectionEventError(
                "subscription projection event: inconsistent payer/merchant"
            )
        return _CanonicalSnapshot(
            subscription_id=row.id,
            service_tenant_id=row.tenant_id,
            payer_tenant_id=row.payer_tenant_id,
            billing_account_id=row.billing_account_id,
            merchant_tenant_id=account.merchant_tenant_id,
            merchant_account_id=row.merchant_account_id,
            plan_id=row.plan_id,
            status=row.status,
            verification=row.verification,
            created_at=row.created_at,
            updated_at=row.updated_at,
            version=row.version,
        )


def _apply_projection[Projection: (SellerSubscription, PayerSubscription)](
    model: type[Projection],
    owner_tenant_id: uuid.UUID,
    snapshot: _CanonicalSnapshot,
    values: dict[str, object],
    *,
    _retry: bool = True,
) -> str:
    """Version-fenced upsert of one projection row under its owner's RLS
    scope: insert if absent, update only if `snapshot.version` is newer
    than the stored `source_version`, otherwise a no-op. Returns
    `"inserted"`, `"updated"`, `"stale"` or `"owner_closed"`. A concurrent
    insert of the same row loses on the unique constraint and is retried
    once as an update -- which the version fence then decides."""
    try:
        with tenant_session_scope(owner_tenant_id) as session:
            try:
                lock_open_tenant(session, owner_tenant_id)
            except TenantClosedError:
                return "owner_closed"
            existing = session.execute(
                select(model)
                .where(
                    model.tenant_id == owner_tenant_id,
                    model.subscription_id == snapshot.subscription_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            fields = {
                **values,
                "service_tenant_id": snapshot.service_tenant_id,
                "merchant_account_id": snapshot.merchant_account_id,
                "plan_id": snapshot.plan_id,
                "status": snapshot.status,
                "verification": snapshot.verification,
                "subscription_created_at": snapshot.created_at,
                "subscription_updated_at": snapshot.updated_at,
                "source_version": snapshot.version,
                "projected_at": datetime.now(UTC),
            }
            if existing is None:
                session.add(
                    model(
                        tenant_id=owner_tenant_id,
                        subscription_id=snapshot.subscription_id,
                        **fields,
                    )
                )
                session.flush()
                return "inserted"
            if existing.source_version >= snapshot.version:
                return "stale"
            for name, value in fields.items():
                setattr(existing, name, value)
            session.flush()
            return "updated"
    except IntegrityError:
        if not _retry:
            raise
        return _apply_projection(model, owner_tenant_id, snapshot, values, _retry=False)


def project_subscription(service_tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> bool:
    """Bring both projections of one subscription up to its current
    canonical version. Returns whether there was anything to project.
    Idempotent and version-fenced; the consumer's whole effect."""
    snapshot = _canonical_snapshot(service_tenant_id, subscription_id)
    if snapshot is None:
        return False
    _apply_projection(
        SellerSubscription,
        snapshot.merchant_tenant_id,
        snapshot,
        {"payer_tenant_id": snapshot.payer_tenant_id},
    )
    _apply_projection(
        PayerSubscription,
        snapshot.payer_tenant_id,
        snapshot,
        {
            "billing_account_id": snapshot.billing_account_id,
            "merchant_tenant_id": snapshot.merchant_tenant_id,
        },
    )
    return True


async def _project_subscription_job(context: TenantJobContext, payload: TenantJobPayload) -> None:
    """The outbox consumer of `billing.subscription_changed` (module
    docstring). A malformed event or one naming no subscription of its
    tenant raises `MalformedProjectionEventError` (permanent: dead-lettered).
    A canonical row older than the announced version raises
    `ProjectionNotReadyError` (retried). Never calls a provider and never
    writes a canonical row."""
    service_tenant_id = context.tenant_id
    subscription_id, announced_version = _parse_event(payload.data)
    if context.event_id is not None:
        with tenant_session_scope(service_tenant_id) as session:
            if event_consumption_recorded(
                session,
                tenant_id=service_tenant_id,
                consumer=SUBSCRIPTION_CHANGED_EVENT_TYPE,
                event_id=context.event_id,
            ):
                logger.info("subscription_projection_duplicate_suppressed")
                return
    snapshot = _canonical_snapshot(service_tenant_id, subscription_id)
    if snapshot is not None and snapshot.version < announced_version:
        raise ProjectionNotReadyError(
            "the announced subscription version is not visible yet; retrying"
        )
    project_subscription(service_tenant_id, subscription_id)
    if context.event_id is not None:
        record_event_consumption(
            service_tenant_id, consumer=SUBSCRIPTION_CHANGED_EVENT_TYPE, event_id=context.event_id
        )


OUTBOX_EVENT_HANDLERS = {SUBSCRIPTION_CHANGED_EVENT_TYPE: _project_subscription_job}


# --- Reads ----------------------------------------------------------------------------


@dataclass(frozen=True)
class SellerSubscriptionView:
    """One subscription as its seller sees it (eventually consistent:
    `source_version`/`projected_at` say which canonical state it reflects)."""

    subscription_id: uuid.UUID
    merchant_tenant_id: uuid.UUID
    merchant_account_id: uuid.UUID
    service_tenant_id: uuid.UUID
    payer_tenant_id: uuid.UUID
    plan_id: uuid.UUID
    status: str
    verification: str
    subscription_created_at: datetime
    subscription_updated_at: datetime
    source_version: int
    projected_at: datetime


@dataclass(frozen=True)
class PayerSubscriptionView:
    """One subscription as its payer sees it (eventually consistent)."""

    subscription_id: uuid.UUID
    payer_tenant_id: uuid.UUID
    billing_account_id: uuid.UUID
    merchant_tenant_id: uuid.UUID
    merchant_account_id: uuid.UUID
    service_tenant_id: uuid.UUID
    plan_id: uuid.UUID
    status: str
    verification: str
    subscription_created_at: datetime
    subscription_updated_at: datetime
    source_version: int
    projected_at: datetime


def _seller_view(row: SellerSubscription) -> SellerSubscriptionView:
    return SellerSubscriptionView(
        subscription_id=row.subscription_id,
        merchant_tenant_id=row.tenant_id,
        merchant_account_id=row.merchant_account_id,
        service_tenant_id=row.service_tenant_id,
        payer_tenant_id=row.payer_tenant_id,
        plan_id=row.plan_id,
        status=row.status,
        verification=row.verification,
        subscription_created_at=row.subscription_created_at,
        subscription_updated_at=row.subscription_updated_at,
        source_version=row.source_version,
        projected_at=row.projected_at,
    )


def _payer_view(row: PayerSubscription) -> PayerSubscriptionView:
    return PayerSubscriptionView(
        subscription_id=row.subscription_id,
        payer_tenant_id=row.tenant_id,
        billing_account_id=row.billing_account_id,
        merchant_tenant_id=row.merchant_tenant_id,
        merchant_account_id=row.merchant_account_id,
        service_tenant_id=row.service_tenant_id,
        plan_id=row.plan_id,
        status=row.status,
        verification=row.verification,
        subscription_created_at=row.subscription_created_at,
        subscription_updated_at=row.subscription_updated_at,
        source_version=row.source_version,
        projected_at=row.projected_at,
    )


def _status_filter(status: SubscriptionStatus | str | None) -> str | None:
    return None if status is None else SubscriptionStatus(status).value


def list_seller_subscriptions(
    caller: object,
    merchant_tenant_id: uuid.UUID,
    *,
    merchant_account_id: uuid.UUID | None = None,
    status: SubscriptionStatus | str | None = None,
) -> list[SellerSubscriptionView]:
    """The subscriptions sold through `merchant_tenant_id`'s merchant
    accounts (`billing.merchant:manage` on that tenant), optionally for one
    merchant account or one status. Projection data only."""
    require_billing_caller(caller)
    status_value = _status_filter(status)
    with tenant_session_scope(merchant_tenant_id) as session:
        authorize_billing(
            caller,
            [(merchant_tenant_id, BILLING_MERCHANT, "manage")],
            operation="billing.seller_subscriptions.read",
            session=session,
        )
        query = select(SellerSubscription).where(SellerSubscription.tenant_id == merchant_tenant_id)
        if merchant_account_id is not None:
            query = query.where(SellerSubscription.merchant_account_id == merchant_account_id)
        if status_value is not None:
            query = query.where(SellerSubscription.status == status_value)
        rows = session.execute(
            query.order_by(SellerSubscription.subscription_created_at, SellerSubscription.id)
        ).scalars()
        return [_seller_view(row) for row in rows]


def get_seller_subscription(
    caller: object, merchant_tenant_id: uuid.UUID, subscription_id: uuid.UUID
) -> SellerSubscriptionView:
    """One sold subscription (`billing.merchant:manage`), or
    `SubscriptionProjectionNotFoundError`."""
    require_billing_caller(caller)
    with tenant_session_scope(merchant_tenant_id) as session:
        authorize_billing(
            caller,
            [(merchant_tenant_id, BILLING_MERCHANT, "manage")],
            operation="billing.seller_subscriptions.read",
            session=session,
        )
        row = session.execute(
            select(SellerSubscription).where(
                SellerSubscription.tenant_id == merchant_tenant_id,
                SellerSubscription.subscription_id == subscription_id,
            )
        ).scalar_one_or_none()
        if row is None:
            raise SubscriptionProjectionNotFoundError(merchant_tenant_id, subscription_id)
        return _seller_view(row)


def list_payer_subscriptions(
    caller: object,
    payer_tenant_id: uuid.UUID,
    *,
    billing_account_id: uuid.UUID | None = None,
    status: SubscriptionStatus | str | None = None,
) -> list[PayerSubscriptionView]:
    """The subscriptions charged to `payer_tenant_id`'s billing accounts
    (`billing.account:read` on that tenant), optionally for one billing
    account or one status. Projection data only."""
    require_billing_caller(caller)
    status_value = _status_filter(status)
    with tenant_session_scope(payer_tenant_id) as session:
        authorize_billing(
            caller,
            [(payer_tenant_id, BILLING_ACCOUNT, "read")],
            operation="billing.payer_subscriptions.read",
            session=session,
        )
        query = select(PayerSubscription).where(PayerSubscription.tenant_id == payer_tenant_id)
        if billing_account_id is not None:
            query = query.where(PayerSubscription.billing_account_id == billing_account_id)
        if status_value is not None:
            query = query.where(PayerSubscription.status == status_value)
        rows = session.execute(
            query.order_by(PayerSubscription.subscription_created_at, PayerSubscription.id)
        ).scalars()
        return [_payer_view(row) for row in rows]


def get_payer_subscription(
    caller: object, payer_tenant_id: uuid.UUID, subscription_id: uuid.UUID
) -> PayerSubscriptionView:
    """One paid subscription (`billing.account:read`), or
    `SubscriptionProjectionNotFoundError`."""
    require_billing_caller(caller)
    with tenant_session_scope(payer_tenant_id) as session:
        authorize_billing(
            caller,
            [(payer_tenant_id, BILLING_ACCOUNT, "read")],
            operation="billing.payer_subscriptions.read",
            session=session,
        )
        row = session.execute(
            select(PayerSubscription).where(
                PayerSubscription.tenant_id == payer_tenant_id,
                PayerSubscription.subscription_id == subscription_id,
            )
        ).scalar_one_or_none()
        if row is None:
            raise SubscriptionProjectionNotFoundError(payer_tenant_id, subscription_id)
        return _payer_view(row)
