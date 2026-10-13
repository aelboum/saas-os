"""The commercial overview: operational oversight of subscriptions across
tenants (docs/ADR/0045-installation-scoped-platform-authority.md sections
4, 8 and 9d).

This is the audited cross-tenant read path ADR-0002 commits to, for one
fixed projection. It is gated by `platform.billing:read` and by nothing
else: no tenant permission is consulted and none could grant it, `can()` is
never called, and support access is neither required nor conferred.

**The projection is fixed.** Per service tenant, at most
`MAX_SUBSCRIPTIONS_PER_TENANT` most recently updated subscriptions, each as
`status`, plan `key`, `payer_tenant_id`, `updated_at`. Never a provider
customer, subscription or price id, a billing or merchant account id, an
invoice or a payment detail. A subscription period end is not stored
anywhere and is not part of it. There is no function here that takes a
table name or a column list.

**The path, in two transactions, each opened with no tenant bound:**

1. *The attempt.* Authorize the caller and commit the attempt row
   (`platform.billing.read_attempt`: the actor, the cursor, the requested
   page size) in a transaction of its own. Nothing has been read yet; if
   the row cannot be committed, the call raises and nothing is read.
2. *The read.* In a second transaction, authorize the caller again -- the
   authority may have been revoked since -- and hold the decision's
   `FOR SHARE` locks to the end, so it cannot be revoked part-way through
   the page;
3. read one page of tenant ids from the global registry, by keyset,
   skipping purged tombstones;
4. for each tenant on the page, inside its own `bind_tenant_scope` block,
   run the one fixed query, with its own limit. The tenant policy filters
   every row and the query also carries the explicit `tenant_id`
   predicate. No statement spans tenants;
5. with no tenant bound again, write the completion row
   (`platform.billing.read`: the number of tenants returned and the
   attempt row's id);
6. commit, then return: the data leaves only after the completion row is
   durable.

A failure in any tenant's query, or of the completion row, aborts the
read transaction: no partial page is returned, the rollback clears the
tenant binding, the attempt row remains with no completion, and a
`failure` row is written separately. A caller whose authority was revoked
between the two transactions is refused, with a `denied` row.

**Request limits (decision D3).** At most `MAX_OVERVIEW_PAGE_SIZE` tenants
per call; a larger request is rejected, never clamped. Nothing iterates
beyond one page per call.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from saas_os.core.authority import ServiceAccountCaller, require_caller
from saas_os.core.billing.models import Plan, Subscription
from saas_os.core.platform_authority import (
    InvalidPlatformRequestError,
    OversightReadTimeoutError,
    PlatformAuditOutcome,
    PlatformNotAuthorizedError,
    PlatformRefusalError,
    authorize_platform_caller,
    get_oversight_read_config,
    oversight_read_timeout,
    platform_operation,
    record_oversight_attempt,
    record_platform_event_in_transaction,
    record_platform_refusal,
)
from saas_os.core.platform_authority.operations import BILLING_READ
from saas_os.core.tenancy import unpurged_tenant_ids_page
from saas_os.infra.db import Session, bind_tenant_scope, select, session_scope

DEFAULT_OVERVIEW_PAGE_SIZE = 25
MAX_OVERVIEW_PAGE_SIZE = 50
MAX_SUBSCRIPTIONS_PER_TENANT = 10

_TARGET = "billing_overview"


@dataclass(frozen=True)
class SubscriptionOverview:
    """The complete projection of one subscription."""

    status: str
    plan_key: str
    payer_tenant_id: uuid.UUID | None
    updated_at: datetime


@dataclass(frozen=True)
class TenantCommercialOverview:
    tenant_id: uuid.UUID
    subscriptions: tuple[SubscriptionOverview, ...]


@dataclass(frozen=True)
class CommercialOverviewPage:
    """`next_cursor` is the id to pass as `cursor` for the following page,
    or `None` when this page was not full."""

    tenants: tuple[TenantCommercialOverview, ...]
    next_cursor: uuid.UUID | None


def _tenant_subscriptions(
    session: Session, tenant_id: uuid.UUID
) -> tuple[SubscriptionOverview, ...]:
    with bind_tenant_scope(session, tenant_id):
        rows = session.execute(
            select(
                Subscription.status,
                Plan.key,
                Subscription.payer_tenant_id,
                Subscription.updated_at,
            )
            .join(Plan, Plan.id == Subscription.plan_id)
            .where(Subscription.tenant_id == tenant_id)
            .order_by(Subscription.updated_at.desc(), Subscription.id)
            .limit(MAX_SUBSCRIPTIONS_PER_TENANT)
        ).all()
    return tuple(
        SubscriptionOverview(
            status=row.status,
            plan_key=row.key,
            payer_tenant_id=row.payer_tenant_id,
            updated_at=row.updated_at,
        )
        for row in rows
    )


def commercial_overview(
    *, caller: object, cursor: uuid.UUID | None = None, limit: int = DEFAULT_OVERVIEW_PAGE_SIZE
) -> CommercialOverviewPage:
    """One page of the commercial overview. Authority:
    `platform.billing:read`. See the module docstring for the projection,
    the access path and the limits."""
    require_caller(BILLING_READ, caller)
    if isinstance(caller, ServiceAccountCaller):
        raise PlatformNotAuthorizedError(BILLING_READ)
    if cursor is not None and not isinstance(cursor, uuid.UUID):
        raise InvalidPlatformRequestError("cursor must be a uuid.UUID.")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise InvalidPlatformRequestError("limit must be a positive integer.")
    if limit > MAX_OVERVIEW_PAGE_SIZE:
        raise InvalidPlatformRequestError(
            f"limit exceeds the maximum of {MAX_OVERVIEW_PAGE_SIZE} tenants per call."
        )

    action = platform_operation(BILLING_READ).audit_action
    try:
        # Committed before anything is read; raises if it cannot be. Outside
        # the handler of the read below: an attempt that could not be
        # recorded leaves no row at all -- only a refusal is recorded.
        attempt_id = record_oversight_attempt(
            caller=caller,
            operation=BILLING_READ,
            target_type=_TARGET,
            metadata={"cursor": None if cursor is None else str(cursor), "page_size": limit},
            statement_timeout_ms=get_oversight_read_config().statement_timeout_ms,
        )
    except PlatformRefusalError as refusal:
        record_platform_refusal(
            caller=caller, action=action, target_type=_TARGET, code=refusal.code
        )
        raise
    try:
        with oversight_read_timeout(BILLING_READ) as bound, session_scope() as session:
            bound(session)  # statement timeout, this transaction only
            # Again: the authority may have been revoked since the attempt.
            authorize_platform_caller(caller, session=session, operation=BILLING_READ)
            tenant_ids = unpurged_tenant_ids_page(session, after=cursor, limit=limit)
            tenants = tuple(
                TenantCommercialOverview(
                    tenant_id=tenant_id, subscriptions=_tenant_subscriptions(session, tenant_id)
                )
                for tenant_id in tenant_ids
            )
            # Outside every bind block (ADR-0045 section 9c).
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=action,
                target_type=_TARGET,
                metadata={"attempt_id": str(attempt_id), "returned": len(tenant_ids)},
            )
    except PlatformRefusalError as refusal:
        record_platform_refusal(
            caller=caller, action=action, target_type=_TARGET, code=refusal.code
        )
        raise
    except OversightReadTimeoutError:
        record_platform_refusal(
            caller=caller,
            action=action,
            target_type=_TARGET,
            code="statement_timeout",
            outcome=PlatformAuditOutcome.FAILURE,
        )
        raise
    except Exception:
        record_platform_refusal(
            caller=caller,
            action=action,
            target_type=_TARGET,
            code="error",
            outcome=PlatformAuditOutcome.FAILURE,
        )
        raise
    # Committed: the completion row is durable before the page leaves.
    return CommercialOverviewPage(
        tenants=tenants,
        next_cursor=tenant_ids[-1] if len(tenant_ids) == limit else None,
    )
