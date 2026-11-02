"""The transactional outbox API (Foundation Reliability & Events, RE-1).

`append_event()` is the one way to record an event. It takes the caller's
own SQLAlchemy session and writes the outbox row *in that session's
transaction*, alongside the business mutation that caused the event:

    caller's tenant_session_scope(tenant_id)
        -> the authorized mutation
        -> append_event(session, ...)        # add + flush, nothing else
        -> COMMIT (by the caller)

So the event commits exactly when the mutation commits, and a rollback
discards both. It never opens a session, never commits, never flushes
anything but its own row, and never touches Redis or `saas_os.infra.jobs`: once
the caller commits, the row is durable whether or not any queue is
reachable. Publishing it is the dispatcher's job (RE-2), not this module's.

**No caller argument.** Recording an event grants nothing and changes no
authority; it is the evidence of a mutation the caller has already
authorized (or, for a background job, already fenced). Authorization
therefore stays with that mutation -- this module never re-decides it and
introduces no ambient authority of its own.

**Tenant scope.** The row is tenant-owned and RLS-protected: the caller's
session must be scoped to `tenant_id` (`saas_os.infra.db.tenant_session_scope()`).
A session scoped to any other tenant (or to none) cannot insert it -- the
canonical policy rejects the row and the caller's transaction fails
closed.

**Identity and uniqueness.** The event id is generated here, once, and
returned; it is the row's primary key and the only uniqueness guarantee.
There is no business-level deduplication key: appending twice records two
events. Publication is at-least-once with that stable id -- consumers that
must not act twice dedupe on it (RE-5).

**Initiating actor (ADR 0061, owner decision C).** A producer may say who
or what originally requested the change (`initiated_by=`, a validated
`saas_os.core.authority.Initiator`, e.g. `Initiator.from_caller(caller)`).
It is stored with the event, in the existing `payload` column under the
reserved top-level key `INITIATED_BY_PAYLOAD_KEY` -- no schema change -- and
the dispatcher hands it to the consumer as `TenantJobContext.initiated_by`,
never as part of `payload.data`. Without it the consumer sees the initiator
as unavailable; the dispatching job is never substituted for it. It is
attribution only: it authorizes nothing.

**Erasing a user as initiator (owner decision of 2026-11-02).** User
erasure (`saas_os.core.identity.erasure.erase_user_identity()`) calls
`erase_user_initiator()` for each tenant it erases the user from: every
event of that tenant whose stored initiator is that user gets the stored
initiator replaced by `"unavailable"`, whatever its status -- see that
function for exactly what changes and what does not.
"""

from __future__ import annotations

import json
import re
import uuid

from saas_os.core.authority import INITIATOR_UNAVAILABLE, Initiator
from saas_os.core.outbox.consumption import purge_tenant_outbox_consumptions
from saas_os.core.outbox.errors import InvalidOutboxEventError
from saas_os.core.outbox.models import (
    INITIATED_BY_PAYLOAD_KEY,
    OUTBOX_STATUS_PENDING,
    OutboxEvent,
)
from saas_os.core.tenancy import require_purging_tenant
from saas_os.infra.db import (
    Session,
    json_with_key_replaced,
    select,
    tenant_session_scope,
    update,
)
from saas_os.infra.observability import get_correlation_context

_DOTTED_NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_SIMPLE_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_MAX_NAME_LENGTH = 100
_MAX_AGGREGATE_ID_LENGTH = 255
_MAX_CORRELATION_ID_LENGTH = 100


def _validate(
    tenant_id: object,
    event_type: object,
    aggregate_type: object,
    aggregate_id: object,
    payload: object,
) -> None:
    if not isinstance(tenant_id, uuid.UUID):
        raise InvalidOutboxEventError("tenant_id", "must be a uuid.UUID")
    if (
        not isinstance(event_type, str)
        or len(event_type) > _MAX_NAME_LENGTH
        or not _DOTTED_NAME.match(event_type)
    ):
        raise InvalidOutboxEventError("event_type", "must be a dotted lowercase name")
    if (
        not isinstance(aggregate_type, str)
        or len(aggregate_type) > _MAX_NAME_LENGTH
        or not _SIMPLE_NAME.match(aggregate_type)
    ):
        raise InvalidOutboxEventError("aggregate_type", "must be a lowercase identifier")
    if (
        not isinstance(aggregate_id, str)
        or not aggregate_id
        or len(aggregate_id) > _MAX_AGGREGATE_ID_LENGTH
    ):
        raise InvalidOutboxEventError("aggregate_id", "must be a non-empty string")
    if not isinstance(payload, dict):
        raise InvalidOutboxEventError("payload", "must be a JSON object")
    try:
        round_tripped = json.loads(json.dumps(payload, allow_nan=False))
    except (TypeError, ValueError):
        raise InvalidOutboxEventError("payload", "must be JSON-serializable") from None
    if round_tripped != payload:
        # e.g. non-string keys or tuples, which JSON would silently rewrite:
        # the stored event must be exactly what the producer recorded.
        raise InvalidOutboxEventError("payload", "must round-trip through JSON unchanged")
    if INITIATED_BY_PAYLOAD_KEY in payload:
        # Only `initiated_by=` (a validated `Initiator`) may set it.
        raise InvalidOutboxEventError("payload", "must not carry a reserved key")


def append_event(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    payload: dict[str, object],
    initiated_by: Initiator | None = None,
) -> uuid.UUID:
    """Record one event in `session`'s current transaction and return its
    id. The row is added and flushed -- never committed: it becomes durable
    exactly when the caller commits, and disappears if the caller rolls
    back (module docstring).

    `event_type` names what happened / which consumer handles it (a dotted
    lowercase name, e.g. `webhook.delivery`); `aggregate_type`/
    `aggregate_id` name the entity the event is about. `payload` must be a
    JSON object that round-trips unchanged -- it is stored durably, so a
    producer puts in it only what its consumer needs (never a credential).
    The ambient request correlation id, if any, is recorded with it.

    `initiated_by` (optional, attribution only) is who or what originally
    requested the change -- a `saas_os.core.authority.Initiator`, typically
    `Initiator.from_caller(caller)` for the caller the mutation authorized.
    It is stored with the event (module docstring) and reaches the consumer
    as `TenantJobContext.initiated_by`; `None` records nothing, and the
    consumer then sees the initiator as unavailable.

    Raises `InvalidOutboxEventError` before anything is written."""
    _validate(tenant_id, event_type, aggregate_type, aggregate_id, payload)
    if initiated_by is not None and type(initiated_by) is not Initiator:
        raise InvalidOutboxEventError("initiated_by", "must be an Initiator or None")
    correlation_id = get_correlation_context().request_id
    if correlation_id is not None and len(correlation_id) > _MAX_CORRELATION_ID_LENGTH:
        correlation_id = None
    event_id = uuid.uuid4()
    session.add(
        OutboxEvent(
            id=event_id,
            tenant_id=tenant_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            payload=payload
            if initiated_by is None
            else {**payload, INITIATED_BY_PAYLOAD_KEY: initiated_by.as_metadata()},
            correlation_id=correlation_id,
            status=OUTBOX_STATUS_PENDING,
            attempts=0,
        )
    )
    session.flush()
    return event_id


def delete_aggregate_events(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
) -> int:
    """Delete every `event_type` event about one aggregate in `session`'s
    transaction (rows locked `FOR UPDATE`) and return how many. Used by
    user erasure to remove events that carry a departing user's personal
    data before they are ever published."""
    rows = (
        session.execute(
            select(OutboxEvent)
            .where(
                OutboxEvent.tenant_id == tenant_id,
                OutboxEvent.event_type == event_type,
                OutboxEvent.aggregate_type == aggregate_type,
                OutboxEvent.aggregate_id == aggregate_id,
            )
            .order_by(OutboxEvent.id)
            .with_for_update()
        )
        .scalars()
        .all()
    )
    for row in rows:
        session.delete(row)
    session.flush()
    return len(rows)


def erase_user_initiator(session: Session, *, tenant_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """User erasure (owner decision of 2026-11-02, ADR 0061): in `session`'s
    transaction, replace the stored initiating actor of every one of
    `tenant_id`'s outbox events that names `user_id` as a user initiator
    (`{"type": "user", "user_id": <user_id>}` under `INITIATED_BY_PAYLOAD_KEY`)
    with the documented sentinel `"unavailable"`. Returns how many events
    changed; a repeat finds none and returns 0.

    One conditional `UPDATE` (no read-modify-write from Python). The row
    lock it takes serializes it with the dispatcher's own locked
    transitions; it changes the `payload` column only, so it never touches
    what those transitions decide on (status, attempts, `claim_token`,
    `next_attempt_at`, `last_error`, `published_at`, nor `updated_at`, on
    which the dead-letter replay selects by time) and every claim-token
    check still succeeds after it. The event id, and so the consumer's
    idempotency identity (RE-5), is unchanged. Every other payload key keeps
    its value; the rewritten row's stored JSON text is normalized (key
    order, whitespace), not its meaning.

    **Every status.** `pending` (claimed or not) and `dead_lettered` events
    can still run (a retry, an operator replay), so after erasure their
    consumer is told the initiator is unavailable. `published` events never
    run again, but they are kept until the tenant is purged and hold the same
    reference, so they are erased too: only the initiator key changes.
    A service-account, system or already-`"unavailable"` initiator, another
    user's events and other tenants' events are left exactly as they are.

    **What this cannot reach.** A dispatcher that read the event before this
    commits already holds the initiator in memory: that one attempt's
    consumer may still see the user id, and an audit row it commits records
    it -- a completed record, which this function never changes (retaining
    or erasing completed audit rows is a separate policy decision). An
    attempt that reads the row after this commits sees the initiator as
    unavailable.

    `session` must be `tenant_id`'s `tenant_session_scope()`: the statement
    names the tenant, and Row-Level Security confines it to that tenant
    whatever it names."""
    initiator = OutboxEvent.payload[INITIATED_BY_PAYLOAD_KEY]
    result = session.execute(
        update(OutboxEvent)
        .where(
            OutboxEvent.tenant_id == tenant_id,
            initiator["type"].as_string() == "user",
            initiator["user_id"].as_string() == str(user_id),
        )
        .values(
            payload=json_with_key_replaced(
                OutboxEvent.payload, INITIATED_BY_PAYLOAD_KEY, INITIATOR_UNAVAILABLE
            ),
            # Kept as it was: `updated_at` is when the dispatcher last moved
            # the event, and the replay's `--dead-lettered-since` selects on
            # it; an erasure must not pull an event into that selection.
            updated_at=OutboxEvent.updated_at,
        )
        .execution_options(synchronize_session=False)
    )
    # An `UPDATE` returns a `CursorResult`, which carries `rowcount`.
    return int(getattr(result, "rowcount", 0) or 0)


def purge_tenant_outbox_events(tenant_id: uuid.UUID) -> int:
    """Tenant purge step (`saas_os.core.tenancy.PURGE_STEPS` "outbox"): delete every
    outbox event of a `PURGING` tenant, whatever its dispatch state -- an
    event of a closed tenant is never published (its consumers fence on the
    lifecycle) and may carry tenant data -- and every consumer-idempotency
    record (RE-5). Returns how many rows were deleted in total. Idempotent;
    rows locked `FOR UPDATE`, matching every other purge step."""
    require_purging_tenant(tenant_id)
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        rows = (
            session.execute(
                select(OutboxEvent)
                .where(OutboxEvent.tenant_id == tenant_id)
                .order_by(OutboxEvent.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for row in rows:
            session.delete(row)
            deleted += 1
        deleted += purge_tenant_outbox_consumptions(session, tenant_id)
    return deleted
