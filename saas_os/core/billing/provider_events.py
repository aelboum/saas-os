"""Inbound billing-provider events (docs/ADR/0048-inbound-billing-provider-events.md;
ADR-0008 amendment, points 5, 6, 8 and 9; ADR-0022's `ProviderEvent`).

An adapter verifies a delivery and hands Core a provider-neutral
`ProviderEventNotice`. `process_provider_event()` then:

    1. records the event in `core.billing_provider_events`, keyed by
       `(provider, event_id)` -- an event already `processed` or `ignored`
       is not processed again;
    2. resolves the subscription it names through SaaS OS's own provider-
       reference index, for an account of a merchant the platform tenant
       owns -- never through provider metadata;
    3. calls `reconcile_subscription_status()` as
       `SystemCaller(SystemAuthority.BILLING_OPERATIONS)`, which reads the
       provider's *current* state and applies it through the lifecycle's
       allowed transitions, auditing any change;
    4. marks the event `processed`, `ignored` (with the reason in
       `outcome`), or `failed` (with the error's class name).

**A subscription not known yet is retried, for a while.** The provider
reference and the local row are written only after the provider has
created the subscription, so an event can arrive before SaaS OS knows the
subscription it names. Such an event is `failed` (`SubscriptionNotYetKnown`)
and answered with a retry, for `UNKNOWN_SUBSCRIPTION_GRACE` after it was
first received; after that it is `ignored` (`unknown_subscription`) -- a
subscription SaaS OS did not create is not retried for the provider's
whole redelivery period.

**An event is a notification, not a state** (ADR-0048, item 1). Nothing
in the event body is applied. Duplicate, late and out-of-order deliveries
therefore cannot move a subscription backwards: every processing run
converges on what the provider says now.

**No lock is held across the provider call** (ADR-0031's provider-call
boundary). Two concurrent deliveries of one event may both reconcile;
reconciliation is idempotent, so that is harmless. The first run to
finish an event decides its terminal status: no later mark overwrites a
`processed` or `ignored` row.

**Global by design.** The ledger is read and written with the untenanted
`session_scope()`: deduplication happens before the tenant is known
(ADR-0022). The subscription itself is read and changed only under its
own tenant's scope, by the functions this module calls. This module's
database functions are allowlisted in
`tests/architecture/test_tenant_session_boundary.py`.

**Retention.** `prune_provider_events()` deletes rows older than 90 days.
A provider's own redeliveries stop well before that (Stripe: three days),
and the signature's timestamp tolerance refuses older replays outright.
The scheduled job is in `saas_os/core/billing/provider_event_jobs.py`.
"""

from __future__ import annotations

import enum
import logging
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.billing.commercial import (
    get_subscription_by_provider_ref,
    reconcile_subscription_status,
)
from saas_os.core.billing.errors import (
    InvalidBillingPartyError,
    LegacyReconciliationError,
    ProviderEventProcessingError,
    ProviderRefNotFoundError,
    SubscriptionNotFoundError,
)
from saas_os.core.billing.models import ProviderEvent, Subscription
from saas_os.core.billing.parties import list_merchant_accounts
from saas_os.core.billing.provider import BillingProvider, ProviderEventNotice
from saas_os.core.tenancy import get_platform_tenant_id
from saas_os.infra.db import IntegrityError, delete, now, select, session_scope, update

logger = logging.getLogger(__name__)

PROVIDER_EVENT_RETENTION = timedelta(days=90)
UNKNOWN_SUBSCRIPTION_GRACE = timedelta(hours=1)

_MAX_PROVIDER = 50
_MAX_REF = 255
_MAX_EVENT_TYPE_INPUT = 10_000
_MAX_ERROR_CODE = 100
_PRUNE_BATCH_SIZE = 1000
_MAX_PRUNE_BATCHES = 10_000


class ProviderEventStatus(enum.StrEnum):
    RECEIVED = "received"
    PROCESSED = "processed"
    IGNORED = "ignored"
    FAILED = "failed"


class ProviderEventOutcome(enum.StrEnum):
    """Why an event ended as it did, recorded in the ledger's `outcome`."""

    CHANGED = "changed"
    UNCHANGED = "unchanged"
    NO_SUBSCRIPTION = "no_subscription"
    FOREIGN_ACCOUNT = "foreign_account"
    UNKNOWN_SUBSCRIPTION = "unknown_subscription"
    LEGACY_UNVERIFIED = "legacy_unverified"


_DONE = (ProviderEventStatus.PROCESSED.value, ProviderEventStatus.IGNORED.value)


class SubscriptionNotYetKnownError(LookupError):
    """The event names a subscription SaaS OS does not know yet, within
    `UNKNOWN_SUBSCRIPTION_GRACE` of its first receipt: retried (module
    docstring)."""

    def __init__(self) -> None:
        super().__init__("The subscription this event names is not known yet.")


@dataclass(frozen=True)
class ProviderEventResult:
    """What one processing run did. `duplicate` is true when the event had
    already been processed or ignored and nothing was done this time;
    `outcome` is then `None`."""

    status: ProviderEventStatus
    outcome: ProviderEventOutcome | None = None
    duplicate: bool = False


def _text(value: object, field: str, max_length: int, *, optional: bool = False) -> Any:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value.strip():
        raise InvalidBillingPartyError(f"{field} must be a non-empty string.")
    if len(value) > max_length:
        raise InvalidBillingPartyError(f"{field} exceeds {max_length} characters.")
    return value


def _validated(notice: ProviderEventNotice) -> ProviderEventNotice:
    if not isinstance(notice, ProviderEventNotice):
        raise InvalidBillingPartyError("notice must be a ProviderEventNotice.")
    return replace(
        notice,
        provider=_text(notice.provider, "provider", _MAX_PROVIDER),
        event_id=_text(notice.event_id, "event_id", _MAX_REF),
        # A provider may add event types of any name: keep the record
        # bounded rather than refuse the event.
        event_type=_text(notice.event_type, "event_type", _MAX_EVENT_TYPE_INPUT)[:_MAX_REF],
        provider_account_ref=_text(
            notice.provider_account_ref, "provider_account_ref", _MAX_REF, optional=True
        ),
        provider_subscription_ref=_text(
            notice.provider_subscription_ref, "provider_subscription_ref", _MAX_REF, optional=True
        ),
    )


def _this_event(notice: ProviderEventNotice) -> Any:
    return (ProviderEvent.provider == notice.provider) & (ProviderEvent.event_id == notice.event_id)


@dataclass(frozen=True)
class _Claim:
    done: str | None
    first_received: datetime


def _claim(notice: ProviderEventNotice) -> _Claim:
    """Record the event, or count another attempt at it. `done` is the
    terminal status when it is already `processed` or `ignored`, else
    `None` (process it); `first_received` is when the event was first
    recorded. A concurrent first delivery of the same event makes the
    insert wait on the unique index until it commits."""
    received_now = datetime.now(UTC)
    try:
        with session_scope() as session:
            session.add(
                ProviderEvent(
                    id=uuid.uuid4(),
                    provider=notice.provider,
                    event_id=notice.event_id,
                    event_type=notice.event_type,
                    provider_account_ref=notice.provider_account_ref,
                    status=ProviderEventStatus.RECEIVED.value,
                    attempts=1,
                )
            )
            session.flush()
        return _Claim(done=None, first_received=received_now)
    except IntegrityError:
        pass
    with session_scope() as session:
        row = session.execute(
            select(ProviderEvent).where(_this_event(notice)).with_for_update()
        ).scalar_one()
        if row.status in _DONE:
            return _Claim(done=row.status, first_received=row.created_at)
        row.attempts += 1
        return _Claim(done=None, first_received=row.created_at)


def _mark(
    notice: ProviderEventNotice, status: ProviderEventStatus, outcome: ProviderEventOutcome
) -> None:
    """The terminal mark, unless a concurrent delivery already finished
    the event: the first to finish decides."""
    with session_scope() as session:
        session.execute(
            update(ProviderEvent)
            .where(_this_event(notice), ProviderEvent.status.not_in(_DONE))
            .values(
                status=status.value,
                outcome=outcome.value,
                last_error_code=None,
                processed_at=now(),
            )
        )


def _mark_failed(notice: ProviderEventNotice, error_code: str) -> None:
    """`failed`, unless a concurrent delivery already finished the event."""
    with session_scope() as session:
        session.execute(
            update(ProviderEvent)
            .where(_this_event(notice), ProviderEvent.status.not_in(_DONE))
            .values(status=ProviderEventStatus.FAILED.value, last_error_code=error_code)
        )


def _platform_account_refs(provider: str) -> list[str]:
    """The provider accounts of the merchants the platform tenant owns:
    the only accounts whose events this deployment processes (ADR-0048,
    item 4; Stripe Connect is deferred)."""
    merchants = list_merchant_accounts(get_platform_tenant_id())
    return sorted({m.provider_account_ref for m in merchants if m.provider == provider})


def _resolve(notice: ProviderEventNotice) -> Subscription | ProviderEventOutcome:
    reference = notice.provider_subscription_ref
    if reference is None:
        return ProviderEventOutcome.NO_SUBSCRIPTION
    accounts = _platform_account_refs(notice.provider)
    if notice.provider_account_ref is not None:
        if notice.provider_account_ref not in accounts:
            return ProviderEventOutcome.FOREIGN_ACCOUNT
        accounts = [notice.provider_account_ref]
    for account in accounts:
        try:
            return get_subscription_by_provider_ref(
                provider=notice.provider,
                provider_account_ref=account,
                provider_subscription_ref=reference,
            )
        except (ProviderRefNotFoundError, SubscriptionNotFoundError):
            continue
    return ProviderEventOutcome.UNKNOWN_SUBSCRIPTION


def _reconcile(
    notice: ProviderEventNotice, provider: BillingProvider | None, first_received: datetime
) -> tuple[ProviderEventStatus, ProviderEventOutcome]:
    target = _resolve(notice)
    if (
        target is ProviderEventOutcome.UNKNOWN_SUBSCRIPTION
        and datetime.now(UTC) - first_received < UNKNOWN_SUBSCRIPTION_GRACE
    ):
        raise SubscriptionNotYetKnownError()
    if isinstance(target, ProviderEventOutcome):
        return ProviderEventStatus.IGNORED, target
    try:
        result = reconcile_subscription_status(
            SystemCaller(SystemAuthority.BILLING_OPERATIONS),
            service_tenant_id=target.tenant_id,
            subscription_id=target.id,
            provider=provider,
        )
    except LegacyReconciliationError:
        # A legacy row has no verified provider identity; it leaves that
        # state only through `reconcile_legacy_subscription()`.
        return ProviderEventStatus.IGNORED, ProviderEventOutcome.LEGACY_UNVERIFIED
    outcome = ProviderEventOutcome.CHANGED if result.changed else ProviderEventOutcome.UNCHANGED
    return ProviderEventStatus.PROCESSED, outcome


def process_provider_event(
    notice: ProviderEventNotice, *, provider: BillingProvider | None = None
) -> ProviderEventResult:
    """Record and process one verified provider event (module docstring).
    `provider` is the adapter reconciliation reads the subscription's state
    through; `None` means Core's default for the subscription's provider.

    Returns the result for an event processed, ignored, or already done.
    Raises `ProviderEventProcessingError` when processing failed --
    including an event whose subscription is not known yet, within
    `UNKNOWN_SUBSCRIPTION_GRACE`; the event is then `failed` in the ledger
    and a redelivery processes it again. Raises `InvalidBillingPartyError`
    for a malformed notice, before anything is recorded."""
    notice = _validated(notice)
    try:
        claim = _claim(notice)
    except Exception as exc:
        # Nothing to mark: the ledger itself could not be reached or the
        # row went away (pruned) between the conflict and the read.
        error_code = type(exc).__name__[:_MAX_ERROR_CODE]
        logger.warning(
            "billing_provider_event_claim_failed",
            extra={"provider": notice.provider, "error_type": error_code},
        )
        raise ProviderEventProcessingError(notice.provider, error_code) from exc
    if claim.done is not None:
        return ProviderEventResult(ProviderEventStatus(claim.done), duplicate=True)
    try:
        status, outcome = _reconcile(notice, provider, claim.first_received)
        _mark(notice, status, outcome)
    except Exception as exc:
        error_code = type(exc).__name__[:_MAX_ERROR_CODE]
        try:
            _mark_failed(notice, error_code)
        except Exception as mark_exc:  # noqa: BLE001 -- the original failure is what is raised
            logger.error(
                "billing_provider_event_mark_failed",
                extra={"provider": notice.provider, "error_type": type(mark_exc).__name__},
            )
        logger.warning(
            "billing_provider_event_failed",
            extra={"provider": notice.provider, "error_type": error_code},
        )
        raise ProviderEventProcessingError(notice.provider, error_code) from exc
    return ProviderEventResult(status, outcome)


def _delete_one_batch(cutoff: datetime, batch_size: int) -> int:
    candidates = (
        select(ProviderEvent.id)
        .where(ProviderEvent.created_at < cutoff)
        .order_by(ProviderEvent.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .cte("candidates")
        .prefix_with("MATERIALIZED")
    )
    with session_scope() as session:
        result: Any = session.execute(
            delete(ProviderEvent).where(ProviderEvent.id.in_(select(candidates.c.id)))
        )
        return int(result.rowcount or 0)


def prune_provider_events(
    *,
    retention: timedelta = PROVIDER_EVENT_RETENTION,
    current_time: datetime | None = None,
    batch_size: int = _PRUNE_BATCH_SIZE,
) -> int:
    """Delete ledger rows first received more than `retention` ago, in
    bounded batches. Returns the number deleted. Idempotent and safe to run
    concurrently (rows a concurrent run holds are skipped)."""
    if retention <= timedelta(0):
        raise ValueError("retention must be positive.")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1.")
    cutoff = (current_time if current_time is not None else datetime.now(UTC)) - retention
    deleted = 0
    for _ in range(_MAX_PRUNE_BATCHES):
        removed = _delete_one_batch(cutoff, batch_size)
        if removed == 0:
            break
        deleted += removed
    return deleted
