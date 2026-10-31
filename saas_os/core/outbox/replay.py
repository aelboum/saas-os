"""Operator replay of dead-lettered outbox events (outbox decision brief Q2,
option 2A; owner decision 2026-10-31; ADR-0045 amendment of 2026-10-31).

A dead-lettered event (`core.outbox_events.status = 'dead_lettered'`) keeps
its payload and its `last_error`; nothing else ever moves it again. This
module is the one way back: a platform operator, holding
`platform.outbox:replay`, names one tenant and either the events or a time
since which they were dead-lettered, and each matching event becomes
`pending` again -- attempts reset to 0, due now, its claim cleared, its
`last_error` kept so the history of why it failed stays readable. The
dispatcher then delivers it like any other pending event, at-least-once and
deduplicated by the consumer on the event's stable id (RE-5).

**Bounded.** One tenant per call, at most `MAX_REPLAY_EVENTS` events; a
selection that matches more is refused (`InvalidPlatformRequestError`) and
must be narrowed. Without `apply` nothing is written and nothing is locked:
the call only counts.

**Authorized and evidenced in one transaction** (ADR-0045 sections 9c and
8, dual evidence): `authorize_platform_caller` for `outbox.replay` -- a
person only, no system purpose -- then, with `apply`, one platform audit row
(`platform.outbox.replay`, the tenant as target, the count and the kind of
selection, never an event id or payload) and one `outbox.replay` row in the
tenant's own audit trail naming the operator. A refusal writes one `denied`
platform row after the rollback. A closed or unknown tenant is refused.

**Tenancy.** The events are read and changed under the tenant's own
row-level-security scope (`bind_tenant_scope`) with an explicit tenant
predicate; an event id of another tenant matches nothing. The tenant row is
held `FOR SHARE` (`lock_open_tenant`), so a concurrent closure either
committed first and is refused, or waits until the replay commits.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from saas_os.core.authority import UserCaller
from saas_os.core.outbox.models import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OutboxEvent,
)
from saas_os.core.tenancy import TenantClosedError, TenantNotFoundError, lock_open_tenant
from saas_os.infra.db import bind_tenant_scope, select

MAX_REPLAY_EVENTS = 1000

_TARGET_TENANT = "tenant"
_TENANT_AUDIT_ACTION = "outbox.replay"
_CODE_TENANT_CLOSED = "tenant_closed"
_CODE_TENANT_NOT_FOUND = "tenant_not_found"


@dataclass(frozen=True)
class OutboxReplayResult:
    """`matched`: dead-lettered events of the tenant the selection names.
    `replayed`: how many were moved back to `pending` -- 0 unless
    `applied`."""

    tenant_id: uuid.UUID
    matched: int
    replayed: int
    applied: bool


def _validated_selection(
    event_ids: Sequence[uuid.UUID] | None, dead_lettered_since: datetime | None
) -> tuple[tuple[uuid.UUID, ...] | None, datetime | None]:
    from saas_os.core.platform_authority import InvalidPlatformRequestError

    if (event_ids is None) == (dead_lettered_since is None):
        raise InvalidPlatformRequestError("give exactly one of event_ids and dead_lettered_since.")
    if event_ids is not None:
        ids = tuple(dict.fromkeys(event_ids))
        if not ids:
            raise InvalidPlatformRequestError("event_ids must not be empty.")
        if len(ids) > MAX_REPLAY_EVENTS:
            raise InvalidPlatformRequestError(f"at most {MAX_REPLAY_EVENTS} event ids.")
        if not all(isinstance(event_id, uuid.UUID) for event_id in ids):
            raise InvalidPlatformRequestError("every event id must be a uuid.UUID.")
        return ids, None
    if not isinstance(dead_lettered_since, datetime) or dead_lettered_since.tzinfo is None:
        raise InvalidPlatformRequestError("dead_lettered_since must be a timezone-aware datetime.")
    return None, dead_lettered_since


def replay_dead_lettered_events(
    tenant_id: uuid.UUID,
    *,
    caller: object,
    reason: str,
    event_ids: Sequence[uuid.UUID] | None = None,
    dead_lettered_since: datetime | None = None,
    apply: bool = False,
    now: datetime | None = None,
) -> OutboxReplayResult:
    """Count, or with `apply` replay, `tenant_id`'s dead-lettered outbox
    events named by `event_ids` or dead-lettered at or after
    `dead_lettered_since` (the row's last change: nothing changes a
    dead-lettered row afterwards). Exactly one of the two. See the module
    docstring for the authority, the evidence and the bounds."""
    from saas_os.core.audit_log import record_in_transaction
    from saas_os.core.platform_authority import (
        InvalidPlatformRequestError,
        authorize_platform_caller,
        platform_change_session,
        platform_operation,
        record_platform_event_in_transaction,
        record_platform_refusal,
        recording_platform_refusal,
        validate_reason,
    )
    from saas_os.core.platform_authority.operations import OUTBOX_REPLAY

    if not isinstance(tenant_id, uuid.UUID):
        raise InvalidPlatformRequestError("tenant_id must be a uuid.UUID.")
    ids, since = _validated_selection(event_ids, dead_lettered_since)
    reason = validate_reason(reason)
    at = now if now is not None else datetime.now(UTC)
    spec = platform_operation(OUTBOX_REPLAY)

    try:
        with (
            recording_platform_refusal(
                caller=caller,
                operation=OUTBOX_REPLAY,
                target_type=_TARGET_TENANT,
                target_id=str(tenant_id),
            ),
            platform_change_session(caller, OUTBOX_REPLAY) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=OUTBOX_REPLAY)
            assert isinstance(caller, UserCaller)  # the operation accepts no system purpose
            with bind_tenant_scope(session, tenant_id):
                lock_open_tenant(session, tenant_id)
                query = select(OutboxEvent).where(
                    OutboxEvent.tenant_id == tenant_id,
                    OutboxEvent.status == OUTBOX_STATUS_DEAD_LETTERED,
                )
                if ids is not None:
                    query = query.where(OutboxEvent.id.in_(ids))
                else:
                    query = query.where(OutboxEvent.updated_at >= since)
                query = query.order_by(OutboxEvent.id).limit(MAX_REPLAY_EVENTS + 1)
                if apply:
                    query = query.with_for_update()
                rows = session.execute(query).scalars().all()
                if len(rows) > MAX_REPLAY_EVENTS:
                    raise InvalidPlatformRequestError(
                        f"the selection matches more than {MAX_REPLAY_EVENTS} events; narrow it."
                    )
                if not apply:
                    return OutboxReplayResult(tenant_id, len(rows), 0, applied=False)
                for row in rows:
                    row.status = OUTBOX_STATUS_PENDING
                    row.attempts = 0
                    row.next_attempt_at = at
                    row.claim_token = None
                metadata: dict[str, object] = {
                    "events_replayed": len(rows),
                    "selection": "event_ids" if ids is not None else "dead_lettered_since",
                }
                record_in_transaction(
                    session,
                    caller=caller,
                    tenant_id=tenant_id,
                    action=_TENANT_AUDIT_ACTION,
                    resource_type=_TARGET_TENANT,
                    resource_id=str(tenant_id),
                    metadata={**metadata, "platform": True},
                )
            # ADR-0045 section 9c: the platform row is written with no tenant bound.
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=_TARGET_TENANT,
                target_id=str(tenant_id),
                target_tenant_id=tenant_id,
                reason=reason,
                metadata=metadata,
            )
            return OutboxReplayResult(tenant_id, len(rows), len(rows), applied=True)
    except (TenantClosedError, TenantNotFoundError) as refused:
        record_platform_refusal(
            caller=caller,
            action=spec.audit_action,
            target_type=_TARGET_TENANT,
            target_id=str(tenant_id),
            code=_CODE_TENANT_CLOSED
            if isinstance(refused, TenantClosedError)
            else _CODE_TENANT_NOT_FOUND,
        )
        raise
