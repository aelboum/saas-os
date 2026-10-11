"""Consumer idempotency for outbox events (Foundation Reliability & Events,
RE-5).

Delivery is at-least-once (RE-2): an event's consumer can run again -- most
often when it finished its work but its worker died before the dispatcher
recorded the outcome. This module lets a consumer durably recognize an
execution it already completed and skip the duplicate. It is not, and does
not claim to be, exactly-once.

**Identity.** `(tenant_id, consumer, event_id)`:

- `event_id` is the outbox event's own id (`TenantJobContext.event_id`):
  generated once when the event is recorded and the same on every attempt
  of that event, never derived from time, worker or attempt. A webhook
  occurrence is one outbox event *per subscription*, so two subscriptions
  never share an identity.
- `consumer` names the consuming operation (by convention its event type);
  two different consumers of one event never suppress each other.
- `tenant_id` scopes the identity -- and the row is tenant-owned and
  RLS-protected, so a tenant can neither read nor create another tenant's
  record, whatever ids it holds.

**Claim and completion.** `claim_event_consumption(session, ...)` inserts
the identity row inside the caller's own transaction (a savepoint, so a
conflict leaves that transaction usable):

- no row yet -> the insert succeeds and this execution proceeds. The row
  stays uncommitted -- the *claim* -- until the caller commits: that commit
  is the *completion*, atomic with whatever else the transaction wrote.
  If the transaction rolls back (the work failed, the worker died), the
  claim disappears with it and the event can run again;
- another execution holds the uncommitted claim -> PostgreSQL makes this
  insert wait for that transaction (no polling, no sleep), then: it
  committed -> False (completed, skip); it rolled back -> this execution
  proceeds;
- already committed -> False (completed, skip).

A database failure raises -- it is never read as "already consumed".

**The guarantee and its boundary.** For work done *in the same PostgreSQL
transaction* as the claim (a usage row, an in-app notification row), the
work happens at most once per identity, even under concurrent or repeated
execution. Work *outside* the database (an e-mail, an HTTP request) cannot
join that transaction: such a consumer checks `event_consumption_recorded()`
before acting and records the completion after (`record_event_consumption()`),
which suppresses re-execution once completion is recorded -- but a worker
that dies after the external effect and before that record, or two
executions overlapping before either records it, can still repeat the
effect. Those duplicates are inherent to at-least-once delivery; the stable
`event_id` the receiver sees is how it deduplicates.

**Retention.** Records are kept until the tenant is purged (the "outbox"
purge step). Deleting one while its event could still be executed would
allow a second execution, so no time-based cleanup exists.

Internal to trusted consumer execution: nothing outside a consumer running
under its tenant's scope writes these rows, and the identities are
server-generated outbox ids.
"""

from __future__ import annotations

import re
import uuid

from saas_os.core.outbox.errors import InvalidOutboxEventError
from saas_os.core.outbox.models import OutboxConsumption
from saas_os.infra.db import IntegrityError, Session, select, tenant_session_scope

_CONSUMER_NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_MAX_CONSUMER_LENGTH = 100


def _validate(tenant_id: object, consumer: object, event_id: object) -> None:
    if not isinstance(tenant_id, uuid.UUID):
        raise InvalidOutboxEventError("tenant_id", "must be a uuid.UUID")
    if (
        not isinstance(consumer, str)
        or len(consumer) > _MAX_CONSUMER_LENGTH
        or not _CONSUMER_NAME.match(consumer)
    ):
        raise InvalidOutboxEventError("consumer", "must be a dotted lowercase name")
    if not isinstance(event_id, uuid.UUID):
        raise InvalidOutboxEventError("event_id", "must be a uuid.UUID")


def event_consumption_recorded(
    session: Session, *, tenant_id: uuid.UUID, consumer: str, event_id: uuid.UUID
) -> bool:
    """Whether `consumer` already completed `event_id` (committed). For a
    consumer with an external effect, checked before acting."""
    _validate(tenant_id, consumer, event_id)
    return (
        session.execute(
            select(OutboxConsumption.event_id).where(
                OutboxConsumption.tenant_id == tenant_id,
                OutboxConsumption.consumer == consumer,
                OutboxConsumption.event_id == event_id,
            )
        ).first()
        is not None
    )


def claim_event_consumption(
    session: Session, *, tenant_id: uuid.UUID, consumer: str, event_id: uuid.UUID
) -> bool:
    """Claim `event_id` for `consumer` in `session`'s transaction: True to
    proceed (the claim commits with the caller's transaction, as the
    completion), False if it was already completed -- skip. Waits for a
    concurrent claim of the same identity to resolve (module docstring).
    Raises on any other database error, including a missing tenant; never
    returns False for a failure."""
    _validate(tenant_id, consumer, event_id)
    try:
        with session.begin_nested():
            session.add(
                OutboxConsumption(tenant_id=tenant_id, consumer=consumer, event_id=event_id)
            )
    except IntegrityError:
        # Only an existing completed record means "consumed"; any other
        # integrity failure (e.g. no such tenant) is re-raised.
        if event_consumption_recorded(
            session, tenant_id=tenant_id, consumer=consumer, event_id=event_id
        ):
            return False
        raise
    return True


def record_event_consumption(tenant_id: uuid.UUID, *, consumer: str, event_id: uuid.UUID) -> bool:
    """Record, in its own transaction, that `consumer` completed `event_id`
    -- for a consumer whose effect is outside the database, after that
    effect succeeded. Returns False if it was already recorded."""
    with tenant_session_scope(tenant_id) as session:
        return claim_event_consumption(
            session, tenant_id=tenant_id, consumer=consumer, event_id=event_id
        )


def purge_tenant_outbox_consumptions(session: Session, tenant_id: uuid.UUID) -> int:
    """Delete every consumption record of `tenant_id` in `session`'s
    transaction (tenant purge, called by `purge_tenant_outbox_events()`)."""
    rows = (
        session.execute(
            select(OutboxConsumption)
            .where(OutboxConsumption.tenant_id == tenant_id)
            .order_by(OutboxConsumption.consumer, OutboxConsumption.event_id)
            .with_for_update()
        )
        .scalars()
        .all()
    )
    for row in rows:
        session.delete(row)
    return len(rows)
