"""Erasing a user as the stored initiator of outbox events (owner decision
of 2026-11-02 on ADR 0061, decision C).

An outbox event may store who initiated it, inside its JSON `payload`
under the reserved top-level key `INITIATED_BY_PAYLOAD_KEY`
(`saas_os.core.outbox.service.append_event(..., initiated_by=...)`). User
erasure (`saas_os.core.identity.erasure.erase_user_identity()`) calls
`erase_user_initiator()` for each tenant it erases the user from.

**Not part of the package's public API.** Like
`saas_os.core.identity.erasure`, this module is not exported from
`saas_os.core.outbox` and is fenced at the import boundary: no API route,
Product or AI Control Plane module may import it (`pyproject.toml`, the
"Individual identity erasure" import-linter contract). Its only caller is
user erasure.
"""

from __future__ import annotations

import json
import uuid

from saas_os.core.authority import INITIATOR_UNAVAILABLE
from saas_os.core.outbox.models import INITIATED_BY_PAYLOAD_KEY, OutboxEvent
from saas_os.infra.db import Session, Text, select, update

_USER = "user"


def _names_user(stored_user_id: object, user_id: uuid.UUID) -> bool:
    """Whether a stored initiator's `user_id` names `user_id`, in any
    spelling `uuid.UUID` reads (canonical, upper case, braces, `urn:uuid:`,
    no hyphens). `append_event()` only ever stores the canonical form and
    the dispatcher reads only that form (anything else is delivered as
    unavailable), but erasure must not miss a stored id because it is
    spelled differently."""
    if not isinstance(stored_user_id, str):
        return False
    try:
        return uuid.UUID(stored_user_id) == user_id
    except ValueError:
        return False


def _is_user_initiator(payload: object, user_id: uuid.UUID) -> bool:
    if not isinstance(payload, dict):
        return False
    stored = payload.get(INITIATED_BY_PAYLOAD_KEY)
    return (
        isinstance(stored, dict)
        and stored.get("type") == _USER
        and _names_user(stored.get("user_id"), user_id)
    )


def erase_user_initiator(session: Session, *, tenant_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """In `session`'s transaction, replace the stored initiating actor of
    every one of `tenant_id`'s outbox events that names `user_id` as a user
    initiator (`{"type": "user", "user_id": <user_id>}`) with the
    documented sentinel `"unavailable"`. Returns how many events changed; a
    repeat finds none and returns 0.

    How: no JSON is parsed in SQL. PostgreSQL's `json` operators fail on a
    document holding a `\\u0000` escape (which the `json` column accepts),
    so the candidates are narrowed on the stored text only -- it contains
    the reserved key and, in any letter case, the first eight hex digits of
    the user id (present in every spelling `uuid.UUID` reads) -- and locked
    `FOR UPDATE` in id order. Each locked row is then checked in Python and
    rewritten in Python: the payload is loaded, only the reserved key's
    value is replaced -- every other key keeps its value *and its position*,
    so a consumer (a webhook retried after erasure) gets exactly the body
    it would have got before; the reserved key itself is split off before
    any consumer sees the payload -- and written back. No `jsonb` conversion
    is involved, so such a payload is rewritten like any other.

    Only `payload` changes. Status, attempts, `claim_token`,
    `next_attempt_at`, `last_error`, `published_at` and `updated_at` (on
    which the dead-letter replay selects by time; pinned explicitly) are
    untouched, so every claim-token transition of the dispatcher still
    succeeds after it, and the event id -- the consumer's idempotency
    identity (RE-5) -- is unchanged. The row lock serializes it with the
    dispatcher's own locked transitions.

    **Every status.** `pending` (claimed or not) and `dead_lettered` events
    can still run (a retry, an operator replay), so after erasure their
    consumer is told the initiator is unavailable. `published` events never
    run again, but they are kept until the tenant is purged and hold the
    same reference, so they are erased too. A service-account, system or
    already-`"unavailable"` initiator, another user's events and other
    tenants' events are left exactly as they are.

    **What this cannot reach.** A dispatcher that read the event before this
    commits already holds the initiator in memory: that one attempt's
    consumer may still see the user id, and an audit row it commits records
    it -- a completed record, which this function never changes (retaining
    or erasing completed audit rows is a separate policy decision).

    `session` must be `tenant_id`'s `tenant_session_scope()`: every
    statement names the tenant, and Row-Level Security confines it to that
    tenant whatever it names."""
    stored_text = OutboxEvent.payload.cast(Text())
    locked = session.execute(
        select(OutboxEvent.id, OutboxEvent.payload)
        .where(
            OutboxEvent.tenant_id == tenant_id,
            stored_text.contains(json.dumps(INITIATED_BY_PAYLOAD_KEY), autoescape=True),
            stored_text.icontains(user_id.hex[:8], autoescape=True),
        )
        .order_by(OutboxEvent.id)
        .with_for_update()
    ).all()
    erased = 0
    for event_id, payload in locked:
        if not _is_user_initiator(payload, user_id):
            continue
        rewritten = dict(payload)
        rewritten[INITIATED_BY_PAYLOAD_KEY] = INITIATOR_UNAVAILABLE
        session.execute(
            update(OutboxEvent)
            .where(OutboxEvent.tenant_id == tenant_id, OutboxEvent.id == event_id)
            .values(payload=rewritten, updated_at=OutboxEvent.updated_at)
            .execution_options(synchronize_session=False)
        )
        erased += 1
    return erased
