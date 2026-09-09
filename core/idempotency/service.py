"""Generic idempotency primitives (P1.11).

**Not webhook replay protection** (`core/webhooks/service.py`'s own
`record_webhook_delivery()`, P1.10): that mechanism answers "has this
exact signed external event already been accepted," keyed by a
protocol-provided `event_id` and enforced purely as a reject-on-duplicate
ledger with no stored result. This module answers a different question --
"has this exact client operation already been performed, and if so, what
was the result" -- for a *caller-supplied* key, always paired with a
*result* the caller can be handed back on retry. The two are kept
structurally separate (different table, different error types, different
call sites): P1.10 never routes through this module, and this module
never becomes a generalized webhook ledger.

**Scope**: `(tenant_id, operation, idempotency_key)` -- see
`core/idempotency/models.py::IdempotencyRecord`'s own docstring for why
`operation` is part of the key, not an afterthought.

**Two composition primitives**, because not every idempotent operation
can be coupled to its idempotency record the same way:

- `run_idempotent()` -- full atomic coupling: the reservation insert, the
  business mutation, and the result finalize all happen inside *one*
  database transaction (`infra.db.tenant_session_scope()`). Only usable
  when the entire business operation is itself a database mutation with
  no external network call in the middle (this repository's own
  `core.usage.service.consume_quota_idempotent()` is the real consumer).
  Correctness: two concurrent callers racing the same key both attempt
  the reservation `INSERT`; PostgreSQL's own unique-index locking makes
  the second wait for the first's transaction to resolve, then either
  fail with `IntegrityError` (first committed -- the second re-reads and
  replays its result) or proceed cleanly (first rolled back -- nothing
  happened, the second's attempt is now the only one). A business-logic
  failure (e.g. `QuotaExceededError`) unwinds the *entire* transaction,
  including the reservation itself -- no row survives a failed attempt,
  so a retry is a clean, ordinary fresh attempt (this checkpoint's own
  "do not mark every attempted request as permanently completed").

- `begin_idempotent_operation()` / `finalize_idempotent_operation()` --
  the two-step primitive for an operation that must make an external,
  non-database call in between (this repository's own
  `core.billing.service.subscribe_idempotent()`, which calls a real
  `BillingProvider` -- Stripe in production -- between the two steps).
  **Documented limitation** (this checkpoint's own required disclosure):
  the reservation is committed *before* the external call runs, so a
  crash after the provider call succeeds but before
  `finalize_idempotent_operation()` runs leaves the record `pending`
  forever (until `IDEMPOTENCY_PENDING_TTL_SECONDS` elapses) with the
  external side effect already having happened. This module cannot
  close that window itself -- doing so would require the external
  provider's own idempotency-key support (Stripe has one; this
  repository's `BillingProvider` abstraction does not yet expose it,
  which is a real gap but strictly out of P1.11's scope: "do not
  redesign" the systems this phase integrates with). What this module
  *does* guarantee even for this weaker path: two *concurrent* callers
  can never both reach the external call for the same key (the second
  blocks/fails on the same reservation `INSERT` used by the atomic
  path), and a *sequential* retry after the pending TTL expires is a
  deliberate, bounded, documented policy choice -- never a silent,
  unbounded retry loop.

**Fingerprinting** (`compute_fingerprint()`): SHA-256 over deterministic
canonical JSON (`json.dumps(..., sort_keys=True, separators=(",", ":"))`)
-- stdlib only, no new dependency. Callers pass only the semantically
relevant request fields (module docstrings of each real caller show
exactly which) -- never an `Authorization` header, a session token, or
any other credential.

**Retention** (`purge_expired_idempotency_records()`): tenant-scoped
deletion of records past their `expires_at` (module docstring of
`core/idempotency/models.py`). Not wired into a recurring job in P1.11
(this checkpoint's own "do not build a generalized distributed cleanup
system") -- correctness never depends on cleanup running.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from core.idempotency.config import get_idempotency_config
from core.idempotency.errors import (
    IdempotencyInProgressError,
    IdempotencyKeyInvalidError,
    IdempotencyKeyReusedError,
)
from core.idempotency.models import IdempotencyRecord
from infra.db import IntegrityError, Session, select, tenant_session_scope

_MAX_KEY_LENGTH = 200
_SAFE_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{1,200}$")
_MAX_OPERATION_LENGTH = 100


class IdempotencyStatus(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


def validate_idempotency_key(idempotency_key: str) -> None:
    """Input validation, run before any database access. The key is
    treated as a fully opaque, caller-supplied token -- never parsed,
    never interpreted as a tenant id or any other meaningful value
    (this checkpoint's own "never interpreted as authorization" rule) --
    only its shape is constrained: bounded length, a restricted
    character set safe to embed in a unique index and a log line without
    escaping concerns (mirrors `api/middleware.py`'s own
    `_SAFE_ID_PATTERN` convention for `X-Request-ID`).
    """
    if not idempotency_key:
        raise IdempotencyKeyInvalidError("Idempotency key must not be empty.")
    if len(idempotency_key) > _MAX_KEY_LENGTH:
        raise IdempotencyKeyInvalidError(f"Idempotency key exceeds {_MAX_KEY_LENGTH} characters.")
    if not _SAFE_KEY_PATTERN.match(idempotency_key):
        raise IdempotencyKeyInvalidError(
            "Idempotency key contains characters outside the safe set "
            "(letters, digits, '.', '_', '~', '-')."
        )


def compute_fingerprint(payload: Mapping[str, object]) -> str:
    """Deterministic SHA-256 over canonical JSON. `payload` must contain
    only the semantically relevant, non-secret request fields a caller
    chooses to include -- this function has no opinion on what belongs
    in it beyond never being handed a credential (each real caller's own
    docstring documents its exact fingerprint payload)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_operation(operation: str) -> None:
    if not operation or len(operation) > _MAX_OPERATION_LENGTH:
        raise IdempotencyKeyInvalidError(
            f"operation must be a non-empty string of at most {_MAX_OPERATION_LENGTH} characters."
        )


def _expires_at(now: datetime) -> datetime:
    return now + timedelta(seconds=get_idempotency_config().retention_seconds)


# --- Atomic single-transaction coupling (DB-only business operations) -----


def run_idempotent(
    tenant_id: uuid.UUID,
    operation: str,
    idempotency_key: str,
    fingerprint_payload: Mapping[str, object],
    business_fn: Callable[[Session], Mapping[str, object]],
) -> tuple[bool, dict[str, object]]:
    """Execute `business_fn(session)` at most once for `(tenant_id,
    operation, idempotency_key)`, atomically coupled with the
    idempotency record in one transaction (module docstring). Returns
    `(is_replay, result)`.

    `business_fn` receives the *same* session the reservation was
    inserted through -- it must perform its mutation on this session,
    never open its own `tenant_session_scope()` (that would be a nested,
    separate transaction, defeating the atomicity this function exists
    to provide). It returns the small, JSON-serializable result dict to
    store and hand back on replay.

    Raises `IdempotencyKeyReusedError` if the same key was already used
    with a different `fingerprint_payload`. Raises `IdempotencyInProgressError`
    in the rare case a concurrent attempt's outcome cannot yet be
    determined. Any exception `business_fn` raises propagates unchanged,
    after the whole transaction (reservation included) rolls back.
    """
    _validate_operation(operation)
    validate_idempotency_key(idempotency_key)
    fingerprint = compute_fingerprint(fingerprint_payload)
    now = datetime.now(UTC)

    try:
        with tenant_session_scope(tenant_id) as session:
            record = IdempotencyRecord(
                tenant_id=tenant_id,
                operation=operation,
                idempotency_key=idempotency_key,
                fingerprint=fingerprint,
                status=IdempotencyStatus.PENDING.value,
                expires_at=_expires_at(now),
            )
            session.add(record)
            session.flush()  # wins the reservation race, or raises IntegrityError below

            result = dict(business_fn(session))

            record.status = IdempotencyStatus.SUCCEEDED.value
            record.result = result
            session.flush()
        return False, result
    except IntegrityError:
        pass  # a concurrent or earlier caller already holds this key -- resolved below

    return _resolve_existing(tenant_id, operation, idempotency_key, fingerprint)


def _resolve_existing(
    tenant_id: uuid.UUID, operation: str, idempotency_key: str, fingerprint: str
) -> tuple[bool, dict[str, object]]:
    with tenant_session_scope(tenant_id) as session:
        existing = session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.tenant_id == tenant_id,
                IdempotencyRecord.operation == operation,
                IdempotencyRecord.idempotency_key == idempotency_key,
            )
        ).scalar_one()
        session.expunge(existing)

    if existing.fingerprint != fingerprint:
        raise IdempotencyKeyReusedError(tenant_id, operation, idempotency_key)
    if existing.status == IdempotencyStatus.SUCCEEDED.value:
        return True, dict(existing.result or {})
    raise IdempotencyInProgressError(tenant_id, operation, idempotency_key)


# --- Two-step coupling (business operations with an external call) --------


class IdempotencyReservation:
    """Returned by `begin_idempotent_operation()`. `is_replay=True` means
    the caller must skip the business operation entirely and use
    `.result` directly; `is_replay=False` means the caller must perform
    the operation and call `finalize_idempotent_operation(record_id, ...)`
    when it resolves (module docstring: this is the two-step primitive's
    own contract, unlike `run_idempotent()`'s single-call shape)."""

    __slots__ = ("is_replay", "result", "record_id")

    def __init__(
        self, *, is_replay: bool, result: dict[str, object] | None, record_id: uuid.UUID
    ) -> None:
        self.is_replay = is_replay
        self.result = result
        self.record_id = record_id


def begin_idempotent_operation(
    tenant_id: uuid.UUID,
    operation: str,
    idempotency_key: str,
    fingerprint_payload: Mapping[str, object],
) -> IdempotencyReservation:
    """Reserve `(tenant_id, operation, idempotency_key)` for an operation
    that will make an external call before it can be finalized (module
    docstring's own documented limitation). Raises `IdempotencyKeyReusedError`
    for a fingerprint mismatch. Raises `IdempotencyInProgressError` if a
    `pending` reservation exists and is still within
    `IDEMPOTENCY_PENDING_TTL_SECONDS` of its last update -- otherwise
    (abandoned) or if the prior attempt `failed`, resets it to `pending`
    and lets this caller proceed (this checkpoint's own "do not mark
    every attempted request as permanently completed").
    """
    _validate_operation(operation)
    validate_idempotency_key(idempotency_key)
    fingerprint = compute_fingerprint(fingerprint_payload)
    now = datetime.now(UTC)

    try:
        with tenant_session_scope(tenant_id) as session:
            record = IdempotencyRecord(
                tenant_id=tenant_id,
                operation=operation,
                idempotency_key=idempotency_key,
                fingerprint=fingerprint,
                status=IdempotencyStatus.PENDING.value,
                expires_at=_expires_at(now),
            )
            session.add(record)
            session.flush()
            session.refresh(record)
            record_id = record.id
        return IdempotencyReservation(is_replay=False, result=None, record_id=record_id)
    except IntegrityError:
        pass

    with tenant_session_scope(tenant_id) as session:
        existing = session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.tenant_id == tenant_id,
                IdempotencyRecord.operation == operation,
                IdempotencyRecord.idempotency_key == idempotency_key,
            )
        ).scalar_one()
        session.expunge(existing)

    if existing.fingerprint != fingerprint:
        raise IdempotencyKeyReusedError(tenant_id, operation, idempotency_key)

    if existing.status == IdempotencyStatus.SUCCEEDED.value:
        return IdempotencyReservation(
            is_replay=True, result=dict(existing.result or {}), record_id=existing.id
        )

    if existing.status == IdempotencyStatus.PENDING.value:
        age_seconds = (now - existing.updated_at).total_seconds()
        if age_seconds < get_idempotency_config().pending_ttl_seconds:
            raise IdempotencyInProgressError(tenant_id, operation, idempotency_key)
        # Abandoned (crashed mid-flight past the TTL) -- a bounded,
        # documented policy allows one fresh attempt (module docstring).

    # PENDING-abandoned or FAILED: reset and let this caller retry.
    with tenant_session_scope(tenant_id) as session:
        row = session.get(IdempotencyRecord, existing.id)
        assert row is not None  # just read moments ago, within the same tenant scope
        row.status = IdempotencyStatus.PENDING.value
        row.expires_at = _expires_at(now)
        session.flush()
    return IdempotencyReservation(is_replay=False, result=None, record_id=existing.id)


def finalize_idempotent_operation(
    tenant_id: uuid.UUID,
    record_id: uuid.UUID,
    *,
    status: IdempotencyStatus,
    result: dict[str, object] | None = None,
) -> None:
    """Resolve a reservation from `begin_idempotent_operation()` to its
    real outcome. Must be called exactly once per reservation, after the
    external call/business operation actually resolves -- never before
    (this checkpoint's own "do not create a false success record before
    the business operation commits")."""
    with tenant_session_scope(tenant_id) as session:
        row = session.get(IdempotencyRecord, record_id)
        if row is None or row.tenant_id != tenant_id:
            return
        row.status = status.value
        row.result = result
        session.flush()


# --- Retention --------------------------------------------------------


def purge_expired_idempotency_records(tenant_id: uuid.UUID, now: datetime | None = None) -> int:
    """Delete `tenant_id`'s idempotency records past their `expires_at`.
    Tenant-scoped (never a global cross-tenant purge), so this runs
    through the ordinary restricted application role and
    `tenant_session_scope()` -- mirrors
    `core.webhooks.service.purge_expired_replay_records()`'s identical
    reasoning. Not wired into a recurring job in P1.11 (module docstring).
    """
    current_time = now if now is not None else datetime.now(UTC)
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        stale_records = (
            session.execute(
                select(IdempotencyRecord).where(
                    IdempotencyRecord.tenant_id == tenant_id,
                    IdempotencyRecord.expires_at < current_time,
                )
            )
            .scalars()
            .all()
        )
        for record in stale_records:
            session.delete(record)
            deleted += 1
    return deleted
