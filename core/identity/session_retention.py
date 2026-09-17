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
`DELETE ... WHERE id IN (SELECT id ... LIMIT batch_size FOR UPDATE SKIP
LOCKED)` -- SQLAlchemy Core constructs (`infra.db.delete`/`select`),
never ORM object loading (no `session.execute(select(Session)...).scalars()`
followed by a Python-side loop): PostgreSQL identifies and removes the
batch in one round trip, and no session row's content ever exists as a
Python object during cleanup. `FOR UPDATE SKIP LOCKED` on the candidate
subquery is what makes two overlapping cleanup runs (two overlapping
invocations of the same job, a manual run overlapping the scheduled one)
safe *without* a new application-level lock: each run's batch simply
skips whatever the other run's batch already has locked, so both make
independent forward progress instead of blocking on each other, and
never double-delete (a row already deleted by the other run's committed
batch is not found by a later batch's SELECT). This is the same
row-level locking primitive (`FOR UPDATE`) already used throughout this
codebase (e.g. `core.identity.erasure`, `core.tenancy.service`), extended
with the standard, stock PostgreSQL `SKIP LOCKED` modifier for exactly
this "many independent workers, no coordinator" batch-deletion shape --
not a second concurrency architecture.

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
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from arq.worker import Function

from core.identity.config import SessionRetentionConfig, get_session_retention_config
from core.identity.models import Session
from infra.db import delete, select, session_scope
from infra.jobs import TenantJobPayload, register_job

logger = logging.getLogger(__name__)


# TEMPORARY DIAGNOSTIC INSTRUMENTATION -- CI-only investigation of the
# `test_batch_behavior_drains_a_backlog_larger_than_one_batch` CI-only
# failure (`assert 2 >= 3`, `batches` fewer than expected for 25 seeded
# rows at batch size 10). Off by default; every line below guarded by
# this flag is inert when `SAAS_OS_SESSION_RETENTION_DIAGNOSTICS` is
# unset, so default production/test behavior (including the exact SQL
# text this module emits) is byte-for-byte unchanged. Logs only UUIDs,
# counts, phase names, batch/iteration numbers, and timestamps -- never a
# token hash, user id, or other identifying/secret value. Remove this
# entire block (and its call sites in `_delete_one_batch()` and
# `cleanup_expired_sessions()`) once the CI run this exists to produce
# evidence for has been captured and reviewed.
def _diagnostics_enabled() -> bool:
    return os.environ.get("SAAS_OS_SESSION_RETENTION_DIAGNOSTICS") == "1"


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


def _delete_one_batch(
    condition: Any,
    batch_size: int,
    *,
    _diag_phase: str = "",
    _diag_batch: int = 0,
    _diag_cutoff: datetime | None = None,
) -> int:
    """One bounded, database-side batch: lock and delete at most
    `batch_size` rows matching `condition`, skipping rows a concurrent
    batch (this job or another overlapping run) already has locked.
    Returns the number of rows actually deleted -- 0 means either no
    candidates remain or every current candidate is locked elsewhere.

    `_diag_*` keyword-only parameters exist solely for the temporary
    diagnostic instrumentation gated by `_diagnostics_enabled()` (module
    top) -- never populated by, or meaningful to, any real caller."""
    candidate_ids = (
        select(Session.id)
        .where(condition)
        .order_by(Session.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    )
    delete_stmt = delete(Session).where(Session.id.in_(candidate_ids))
    diagnostics_on = _diagnostics_enabled()
    if diagnostics_on:
        # `RETURNING` on this same, single atomic statement -- not a
        # second query -- so the rows it reports are exactly the rows
        # this statement itself deleted (the "candidate" and "deleted"
        # sets are definitionally identical here: there is no separate
        # SELECT step whose result could diverge from the DELETE's own).
        delete_stmt = delete_stmt.returning(Session.id)
    with session_scope() as session:
        result = session.execute(delete_stmt)
        if diagnostics_on:
            deleted_ids = [str(row[0]) for row in result.fetchall()]
            logger.warning(
                "SESSION_RETENTION_DIAGNOSTIC phase=%s batch=%s limit=%s cutoff=%s "
                "candidate_count=%s candidate_ids=%s deleted_count=%s deleted_ids=%s",
                _diag_phase,
                _diag_batch,
                batch_size,
                _diag_cutoff.isoformat() if _diag_cutoff is not None else "",
                len(deleted_ids),
                deleted_ids,
                len(deleted_ids),
                deleted_ids,
                extra={
                    "session_retention_diagnostic": True,
                    "phase": _diag_phase,
                    "batch": _diag_batch,
                    "limit": batch_size,
                    "candidate_count": len(deleted_ids),
                    "deleted_count": len(deleted_ids),
                },
            )
            return len(deleted_ids)
        # `Session.execute()`'s declared return type is the generic
        # `Result[Any]`; a `DELETE` always actually returns the more
        # specific `CursorResult`, which does carry `.rowcount` at
        # runtime -- `getattr` avoids re-exporting `CursorResult` from
        # `infra.db` for a single attribute read.
        return getattr(result, "rowcount", 0) or 0


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
    diagnostics_on = _diagnostics_enabled()
    if diagnostics_on:
        logger.warning(
            "SESSION_RETENTION_DIAGNOSTIC event=cleanup_start now_utc=%s "
            "expired_cutoff=%s grace_cutoff=%s batch_size=%s",
            datetime.now(UTC).isoformat(),
            current_time.isoformat(),
            grace_cutoff.isoformat(),
            cfg.cleanup_batch_size,
        )

    expired_deleted = 0
    batches = 0
    for iteration in range(_MAX_BATCHES_PER_PHASE):
        batches_before = batches
        removed = _delete_one_batch(
            Session.expires_at < current_time,
            cfg.cleanup_batch_size,
            _diag_phase="expired",
            _diag_batch=iteration + 1,
            _diag_cutoff=current_time,
        )
        if diagnostics_on:
            logger.warning(
                "SESSION_RETENTION_DIAGNOSTIC phase=expired iteration=%s returned=%s "
                "batches_before=%s batches_after=%s",
                iteration + 1,
                removed,
                batches_before,
                batches_before + (1 if removed else 0),
            )
        if removed == 0:
            break
        expired_deleted += removed
        batches += 1

    revoked_deleted = 0
    for iteration in range(_MAX_BATCHES_PER_PHASE):
        batches_before = batches
        removed = _delete_one_batch(
            (Session.revoked_at.is_not(None)) & (Session.revoked_at < grace_cutoff),
            cfg.cleanup_batch_size,
            _diag_phase="revoked",
            _diag_batch=iteration + 1,
            _diag_cutoff=grace_cutoff,
        )
        if diagnostics_on:
            logger.warning(
                "SESSION_RETENTION_DIAGNOSTIC phase=revoked iteration=%s returned=%s "
                "batches_before=%s batches_after=%s",
                iteration + 1,
                removed,
                batches_before,
                batches_before + (1 if removed else 0),
            )
        if removed == 0:
            break
        revoked_deleted += removed
        batches += 1

    if diagnostics_on:
        logger.warning(
            "SESSION_RETENTION_DIAGNOSTIC event=cleanup_end expired_deleted=%s "
            "revoked_deleted=%s batches=%s",
            expired_deleted,
            revoked_deleted,
            batches,
        )

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
