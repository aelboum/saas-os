"""RA-12-5 -- bounded physical cleanup of `core.sessions` (following
RA-12-4's read-only audit finding: expired/revoked session rows are
enforced as logically unusable at the authentication chokepoint
(`core.identity.sessions.validate_session()`) but are never physically
deleted, and no cleanup mechanism existed).

**This is an operational housekeeping policy, not a legal retention
requirement.** Nothing in this module claims compliance with any
particular legal regime -- see `core/identity/config.py`'s own docstring.

**What is deleted, and when** (`cleanup_expired_sessions()`):

- **Expired** (`expires_at < now()`): eligible immediately, regardless of
  whether the session was ever revoked. A session past its own expiry
  has never had any operational or security-investigation value it
  didn't already lose the instant `validate_session()` started rejecting
  it.
- **Revoked** (`revoked_at IS NOT NULL`): eligible only once `revoked_at`
  is older than `SessionRetentionConfig.revoked_grace_period_seconds`
  (`core/identity/config.py`) -- a short, explicit, configurable window
  so a just-revoked session's row remains available for operational or
  security investigation for a bounded time after the revocation itself
  already made it unusable.

Deleting a row here changes nothing about whether a session can
authenticate -- `validate_session()`'s expiry/revocation checks already
made both cases reject before this module ever runs (RA-12-4's own
finding: "logical expiration without physical deletion is not itself
evidence that retention is unsafe"). This module only bounds how long the
now-useless row stays in PostgreSQL.

**Not `purge_user_identity()` (RA-12-3), and does not replace it.**
Identity erasure deletes *all* of one specific user's sessions
*immediately*, regardless of expiry/revocation state, as one step of
erasing that person's identity entirely
(`core.identity.erasure.erase_user_identity()` ->
`core.identity.sessions.purge_user_sessions()`). This module deletes
*any* user's sessions that are merely old and already unusable, on a
schedule, and never touches a still-active session. Neither mechanism
weakens the other; they answer different questions ("erase this person"
vs. "stop storing rows nobody can use anymore").

**Global, not tenant-scoped.** `core.sessions` carries no `tenant_id`
(`core/identity/models.py`) -- this module never discovers, iterates, or
requires a tenant id, never opens a `tenant_session_scope()`, and is not
one of `core.tenancy.PURGE_STEPS`. It runs through the ordinary
restricted application role via `infra.db.session_scope()`, exactly like
every other function in `core/identity/sessions.py`.

**Bounded batches, database-side.** Each batch is a single
`WITH candidates AS MATERIALIZED (SELECT id ... LIMIT batch_size FOR
UPDATE SKIP LOCKED) DELETE ... WHERE id IN (SELECT id FROM candidates)`
-- SQLAlchemy Core constructs (`infra.db.delete`/`select`), never ORM
object loading (no `session.execute(select(Session)...).scalars()`
followed by a Python-side loop): PostgreSQL identifies and removes the
batch in one round trip, and no session row's content ever exists as a
Python object during cleanup.

**Why `MATERIALIZED`, not a bare `IN (subquery)`** (CI incident,
2026-09-17): a bare `DELETE ... WHERE id IN (SELECT ... LIMIT n FOR
UPDATE SKIP LOCKED)` -- the previous form here -- was empirically
observed in a live GitHub Actions run to delete 18 rows in one batch
against a configured `batch_size` of 10 (`test_batch_behavior_drains_a_
backlog_larger_than_one_batch`, `assert 2 >= 3`; diagnostic instrumentation
added and captured `candidate_count=18 deleted_count=18` for a single
`_delete_one_batch()` call, `limit=10`). It never reproduced locally
across 30+ isolated, repeated, and full-suite attempts against the same
PostgreSQL version (16.15, confirmed identical in both environments), the
same compiled SQL, and the same library versions -- consistent with a
real but environment/plan-dependent PostgreSQL behavior this repository
could not fully pin down from the client side. The `SELECT ... LIMIT n
FOR UPDATE SKIP LOCKED` subquery on its own is unambiguously bounded to
`n` rows by the SQL standard; what a bare (non-CTE) subquery referencing
the DELETE's own target table does *not* carry is an explicit guarantee
that PostgreSQL evaluates it exactly once, as a fixed, already-decided
row set, before the outer statement's own scan of the same table -- that
guarantee is exactly what the SQL-standard `MATERIALIZED` keyword makes
mandatory (PostgreSQL 12+, this repository requires 16+): the CTE's
result is computed once, treated as an opaque already-computed table for
the rest of the statement, and never subject to the kind of
planner-driven re-evaluation or merging with the outer query that an
inlined/inlinable subquery permits. This closes the entire class of
ambiguity the incident exposed, independent of whichever specific
PostgreSQL internal path produced the over-deletion.

`FOR UPDATE SKIP LOCKED` on the candidate CTE is what makes two
overlapping cleanup runs (two overlapping invocations of the same job, a
manual run overlapping the scheduled one) safe *without* a new
application-level lock: each run's batch simply skips whatever the other
run's batch already has locked, so both make independent forward
progress instead of blocking on each other, and never double-delete (a
row already deleted by the other run's committed batch is not found by a
later batch's SELECT). This is the same row-level locking primitive
(`FOR UPDATE`) already used throughout this codebase (e.g.
`core.identity.erasure`, `core.tenancy.service`), extended with the
standard, stock PostgreSQL `SKIP LOCKED` modifier for exactly this "many
independent workers, no coordinator" batch-deletion shape -- not a second
concurrency architecture.

**Defense in depth.** `_delete_one_batch()` additionally raises
`core.identity.errors.SessionRetentionBatchInvariantError` if a single
batch's reported row count ever exceeds `batch_size` regardless of cause
-- a loud, immediate failure rather than the silent undercount this
module returned before this fix. This does not replace the `MATERIALIZED`
fix above; it is a permanent, narrow correctness backstop for exactly the
one invariant the CI incident violated.

Each phase (expired, then revoked-past-grace) loops batch by batch until
a batch deletes zero rows, so one job invocation drains the *entire*
current backlog rather than leaving one batch's worth of progress per
scheduled run -- bounded per statement, not per invocation.
`_MAX_BATCHES_PER_PHASE` is a defensive internal cap (never a documented
tunable) against an unbounded loop if some future bug ever made the
candidate query never shrink; at the default batch size it allows
draining a very large backlog in one run while still guaranteeing the
loop terminates.

**Never logs or returns identifying data.** `SessionCleanupResult` is
counts only (`expired_deleted`, `revoked_deleted`, `batches`,
`duration_seconds`) -- never a session id, a token hash, or a user id.
The registered ARQ job logs the same bounded counts and nothing else
(`infra.jobs.register_job()`'s own `job_started`/`job_succeeded` log
lines already carry no payload content; this job's payload is always
`None`).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from arq.worker import Function

from core.identity.config import SessionRetentionConfig, get_session_retention_config
from core.identity.errors import SessionRetentionBatchInvariantError
from core.identity.models import Session
from infra.db import delete, select, session_scope
from infra.jobs import TenantJobPayload, register_job

logger = logging.getLogger(__name__)


# Defensive internal safety valve, not an exposed tunable (module
# docstring): bounds the number of batches one phase will run in a single
# invocation even if the candidate query somehow never shrank. At the
# default batch size (500) this allows draining up to 5,000,000 rows of
# backlog per phase per run before returning -- far beyond any backlog a
# job scheduled at the configured interval should ever accumulate.
_MAX_BATCHES_PER_PHASE = 10_000


@dataclass(frozen=True)
class SessionCleanupResult:
    """Outcome of one `cleanup_expired_sessions()` call. Bounded,
    non-identifying counts only -- never a session id, token hash, or
    user id (module docstring)."""

    expired_deleted: int
    revoked_deleted: int
    batches: int
    duration_seconds: float

    @property
    def total_deleted(self) -> int:
        return self.expired_deleted + self.revoked_deleted


def _delete_one_batch(condition: Any, batch_size: int) -> int:
    """One bounded, database-side batch: lock and delete at most
    `batch_size` rows matching `condition`, skipping rows a concurrent
    batch (this job or another overlapping run) already has locked.
    Returns the number of rows actually deleted -- 0 means either no
    candidates remain or every current candidate is locked elsewhere.

    The candidate set is computed in a `MATERIALIZED` CTE, not a bare
    subquery -- see this module's own docstring ("Why `MATERIALIZED`,
    not a bare `IN (subquery)`") for why the bare form is not sufficient
    here. Raises `SessionRetentionBatchInvariantError` (never silently
    continues) if the delete ever reports more rows than `batch_size`,
    as a permanent defense-in-depth backstop for that same invariant."""
    candidates = (
        select(Session.id)
        .where(condition)
        .order_by(Session.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .cte("candidates")
        .prefix_with("MATERIALIZED")
    )
    delete_stmt = delete(Session).where(Session.id.in_(select(candidates.c.id)))
    with session_scope() as session:
        result = session.execute(delete_stmt)
        # `Session.execute()`'s declared return type is the generic
        # `Result[Any]`; a `DELETE` always actually returns the more
        # specific `CursorResult`, which does carry `.rowcount` at
        # runtime -- `getattr` avoids re-exporting `CursorResult` from
        # `infra.db` for a single attribute read.
        removed = getattr(result, "rowcount", 0) or 0
    if removed > batch_size:
        raise SessionRetentionBatchInvariantError(
            f"one session-retention cleanup batch deleted {removed} rows, "
            f"exceeding its own configured batch_size={batch_size}"
        )
    return removed


def cleanup_expired_sessions(
    *,
    config: SessionRetentionConfig | None = None,
    now: datetime | None = None,
) -> SessionCleanupResult:
    """Delete every `core.sessions` row that is expired, plus every
    revoked row older than the configured grace period -- see this
    module's own docstring for the exact eligibility rules, batching, and
    concurrency behavior. Idempotent and safe to call repeatedly or
    concurrently: a second call (or an overlapping one) finds fewer or no
    candidates and returns correspondingly smaller (possibly all-zero)
    counts, never an error.
    """
    cfg = config or get_session_retention_config()
    current_time = now if now is not None else datetime.now(UTC)
    grace_cutoff = current_time - timedelta(seconds=cfg.revoked_grace_period_seconds)
    started = time.monotonic()

    expired_deleted = 0
    batches = 0
    for _ in range(_MAX_BATCHES_PER_PHASE):
        removed = _delete_one_batch(Session.expires_at < current_time, cfg.cleanup_batch_size)
        if removed == 0:
            break
        expired_deleted += removed
        batches += 1

    revoked_deleted = 0
    for _ in range(_MAX_BATCHES_PER_PHASE):
        removed = _delete_one_batch(
            (Session.revoked_at.is_not(None)) & (Session.revoked_at < grace_cutoff),
            cfg.cleanup_batch_size,
        )
        if removed == 0:
            break
        revoked_deleted += removed
        batches += 1

    return SessionCleanupResult(
        expired_deleted=expired_deleted,
        revoked_deleted=revoked_deleted,
        batches=batches,
        duration_seconds=time.monotonic() - started,
    )


async def _cleanup_expired_sessions_job(payload: TenantJobPayload | None) -> None:
    """The registered ARQ handler. `core.sessions` is global identity
    infrastructure (module docstring) -- this job requires no tenant id
    and is always enqueued with `payload=None`, exactly the
    "platform maintenance only" case `infra.jobs.payload.TenantJobPayload`'s
    own docstring anticipates. Returns nothing (arq's `keep_result=0`,
    set by `register_job()`, means no result is persisted regardless);
    the bounded counts are logged, never returned to a caller that could
    accumulate them into anything unbounded.
    """
    result = cleanup_expired_sessions()
    logger.info(
        "session_cleanup_completed",
        extra={
            "expired_deleted": result.expired_deleted,
            "revoked_deleted": result.revoked_deleted,
            "batches": result.batches,
            "duration_seconds": round(result.duration_seconds, 3),
        },
    )


SESSION_CLEANUP_JOB_FUNCTIONS: list[Function] = [register_job(_cleanup_expired_sessions_job)]

# The registered arq function name `infra.jobs.enqueue_job()` needs -- a
# named constant so the production scheduler's trigger (`api/session_cleanup_trigger.py`)
# never hardcodes a private function's own `__name__` as a duplicated
# string literal.
SESSION_CLEANUP_JOB_NAME: str = _cleanup_expired_sessions_job.__name__
