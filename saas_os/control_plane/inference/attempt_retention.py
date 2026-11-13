"""Age-based deletion of finished AI attempt rows (owner decision of
2026-11-13; GAP-REGISTER Stage 7 deferred rows "No retention purge of
attempts" and "The downgrade drops the rollup").

Opt-in and off by default. `purge_expired_ai_attempts()` deletes nothing
unless `AI_ATTEMPT_RETENTION_ENABLED=true`; then it deletes, tenant by
tenant, the rows of `control_plane.ai_inference_attempts` that

- are finished (`state` is not `started`; a `started` row is never deleted,
  however old),
- finished before the cutoff, `now - AI_ATTEMPT_RETENTION_DAYS` (default
  100 days; a value below 93 is refused, because the tenant usage read
  accepts windows reaching 93 days back and would otherwise be silently
  incomplete), and
- have no budget reservation: a reservation (`FINANCIAL_RETAIN`) holds a
  `NO ACTION` foreign key onto its attempt, so a budget-admitted attempt
  stays as long as its reservation does.

What survives: the monthly rollup (`control_plane.ai_usage_monthly`). Its
trigger fires on INSERT and UPDATE only, so deleting an attempt leaves its
month's totals unchanged; the monthly read and `GET .../ai/usage/monthly`
keep reporting it. The attempt-level read (`read_tenant_ai_usage`) only
covers the last 93 days, which the minimum keeps intact.

How: bounded, database-side batches (`WITH candidates AS MATERIALIZED
(SELECT id ... LIMIT n FOR UPDATE SKIP LOCKED) DELETE ...`, the shape of
`saas_os.core.identity.session_retention`), each in its own transaction
under the tenant's RLS scope (`tenant_session_scope`), as the application
role, which already holds DELETE on the table. Each batch that deletes
anything writes one `ai.attempts.purged` row into that tenant's audit
trail in the same transaction: the count, the cutoff and the retention
period, never an attempt id. Safe to run concurrently (skipped locks) and
idempotent.

The tenant-purge classification of the table is unchanged
(`DEFERRED_POLICY` in `saas_os.core.tenancy.retention`): this is
age-based housekeeping, not part of a tenant purge.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from saas_os.control_plane.inference.attempts import AIInferenceAttempt, AttemptState
from saas_os.control_plane.inference.budget_models import AIBudgetReservation
from saas_os.core.audit_log import record_system_action_in_transaction
from saas_os.core.authority import SystemActor, SystemCorrelation
from saas_os.core.tenancy import list_tenant_ids
from saas_os.infra.db import delete, select, tenant_session_scope

logger = logging.getLogger(__name__)

ENABLED_SETTING = "AI_ATTEMPT_RETENTION_ENABLED"
DAYS_SETTING = "AI_ATTEMPT_RETENTION_DAYS"
DEFAULT_RETENTION_DAYS = 100
# The tenant usage read (`tenant_usage.MAX_WINDOW`) reaches 93 days back.
MINIMUM_RETENTION_DAYS = 93
_MAXIMUM_RETENTION_DAYS = 36_500
BATCH_SIZE = 1000
# Bounds one tenant's batches in one run (10,000,000 rows at the default
# batch size); the next run continues.
_MAX_BATCHES_PER_TENANT = 10_000

AUDIT_ACTION = "ai.attempts.purged"
AUDIT_RESOURCE_TYPE = "ai_inference_attempt"


class AIAttemptRetentionConfigurationError(ValueError):
    """An invalid retention setting. `reason` names it; the value is never
    echoed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"AI attempt retention misconfigured: {reason}")


class AIAttemptRetentionBatchInvariantError(RuntimeError):
    """One batch reported more deleted rows than its limit; its transaction
    is rolled back and the run stops."""


@dataclass(frozen=True)
class AIAttemptRetentionSettings:
    enabled: bool
    retention_days: int


@dataclass(frozen=True)
class AIAttemptRetentionResult:
    """Counts only: never an attempt id."""

    enabled: bool
    cutoff: datetime | None
    tenants_scanned: int
    deleted: int
    batches: int
    duration_seconds: float


def ai_attempt_retention_settings(
    env: Mapping[str, str] | None = None,
) -> AIAttemptRetentionSettings:
    """Reads the two settings. `AI_ATTEMPT_RETENTION_ENABLED`: `true` or
    `false` (default `false`). `AI_ATTEMPT_RETENTION_DAYS`: an integer of at
    least 93 (default 100). Anything else fails closed."""
    source = os.environ if env is None else env
    raw_enabled = source.get(ENABLED_SETTING, "").strip().lower()
    if raw_enabled in ("", "false"):
        enabled = False
    elif raw_enabled == "true":
        enabled = True
    else:
        raise AIAttemptRetentionConfigurationError("invalid_ai_attempt_retention_enabled")
    raw_days = source.get(DAYS_SETTING, "").strip()
    if not raw_days:
        days = DEFAULT_RETENTION_DAYS
    else:
        try:
            days = int(raw_days, 10)
        except ValueError:
            raise AIAttemptRetentionConfigurationError(
                "invalid_ai_attempt_retention_days"
            ) from None
        if not MINIMUM_RETENTION_DAYS <= days <= _MAXIMUM_RETENTION_DAYS:
            raise AIAttemptRetentionConfigurationError("invalid_ai_attempt_retention_days")
    return AIAttemptRetentionSettings(enabled=enabled, retention_days=days)


def _tenant_ids() -> list[uuid.UUID]:
    # Every tenant, closed and purged ones included: a purged tenant's
    # attempts are kept by the purge (DEFERRED_POLICY) and age out here.
    return list_tenant_ids()


def _delete_one_batch(
    tenant_id: uuid.UUID,
    cutoff: datetime,
    batch_size: int,
    *,
    actor: SystemActor,
    correlation: SystemCorrelation | None,
    retention_days: int,
) -> int:
    attempt = AIInferenceAttempt
    reserved = select(AIBudgetReservation.id).where(AIBudgetReservation.attempt_id == attempt.id)
    candidates = (
        select(attempt.id)
        .where(
            attempt.tenant_id == tenant_id,
            attempt.state != AttemptState.STARTED.value,
            attempt.finished_at.is_not(None),
            attempt.finished_at < cutoff,
            # Implied by the line above (an attempt starts before it
            # finishes); it lets the (tenant_id, started_at) index bound
            # the scan. It can only exclude rows, never add one.
            attempt.started_at < cutoff,
            ~reserved.exists(),
        )
        .order_by(attempt.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .cte("candidates")
        .prefix_with("MATERIALIZED")
    )
    with tenant_session_scope(tenant_id) as session:
        result: Any = session.execute(
            delete(attempt).where(attempt.id.in_(select(candidates.c.id)))
        )
        removed = int(result.rowcount or 0)
        if removed > batch_size:
            # Raised inside the scope: the deletion rolls back.
            raise AIAttemptRetentionBatchInvariantError(
                f"one AI attempt retention batch deleted {removed} rows, "
                f"exceeding its batch_size={batch_size}"
            )
        if removed:
            record_system_action_in_transaction(
                session,
                tenant_id=tenant_id,
                actor=actor,
                action=AUDIT_ACTION,
                resource_type=AUDIT_RESOURCE_TYPE,
                metadata={
                    "deleted": removed,
                    "cutoff": cutoff.isoformat(),
                    "retention_days": retention_days,
                },
                correlation=correlation,
            )
    return removed


def purge_expired_ai_attempts(
    *,
    actor: SystemActor,
    correlation: SystemCorrelation | None = None,
    settings: AIAttemptRetentionSettings | None = None,
    now: datetime | None = None,
    batch_size: int = BATCH_SIZE,
) -> AIAttemptRetentionResult:
    """Deletes finished attempt rows past the retention period (module
    docstring). Disabled: deletes nothing and returns `enabled=False`.
    `actor` names the executing component in each audit row."""
    cfg = settings if settings is not None else ai_attempt_retention_settings()
    if not isinstance(actor, SystemActor):
        raise TypeError("actor must be a SystemActor.")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1.")
    started = time.monotonic()
    if not cfg.enabled:
        return AIAttemptRetentionResult(False, None, 0, 0, 0, time.monotonic() - started)
    if cfg.retention_days < MINIMUM_RETENTION_DAYS:
        raise AIAttemptRetentionConfigurationError("invalid_ai_attempt_retention_days")
    current = now if now is not None else datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware.")
    cutoff = current.astimezone(UTC) - timedelta(days=cfg.retention_days)

    tenants = _tenant_ids()
    deleted = 0
    batches = 0
    for tenant_id in tenants:
        for _ in range(_MAX_BATCHES_PER_TENANT):
            removed = _delete_one_batch(
                tenant_id,
                cutoff,
                batch_size,
                actor=actor,
                correlation=correlation,
                retention_days=cfg.retention_days,
            )
            if removed == 0:
                break
            deleted += removed
            batches += 1
    return AIAttemptRetentionResult(
        enabled=True,
        cutoff=cutoff,
        tenants_scanned=len(tenants),
        deleted=deleted,
        batches=batches,
        duration_seconds=time.monotonic() - started,
    )
