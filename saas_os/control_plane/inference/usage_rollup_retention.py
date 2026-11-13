"""Age-based expiry of monthly AI usage rollup rows (owner decisions of
2026-11-13; GAP-REGISTER Stage 7 deferred row "no expiry of the rollup").

Opt-in and off by default. `expire_ai_usage_rollups()` deletes nothing unless
`AI_USAGE_ROLLUP_RETENTION_ENABLED=true`; then it deletes, tenant by tenant,
the rows of `control_plane.ai_usage_monthly` whose `month_start` is before the
cutoff: the first instant of the current UTC month less
`AI_USAGE_ROLLUP_RETENTION_MONTHS` (default 24; a value below 24 is refused).
The current month and the months the setting keeps are never touched.

The database holds the minimum on its own (migration `e8a3c6f1d9b4`): a
`BEFORE DELETE` trigger refuses, for the application role, any row of the
current month or of the 24 whole months before it, by the database clock.
Each batch also reads the database clock (`now()`, the same value the trigger
sees in that transaction) and never asks for a row the trigger would refuse,
so a Python clock ahead of the database at a month boundary skips the row
instead of failing the run.

After expiry the monthly read (`read_tenant_ai_monthly_usage`,
`GET .../ai/usage/monthly`) returns nothing, or less, for the removed months;
it does not say so (owner decision: documented only). The read's own maximum
window is 24 months, so a window ending at the current month stays complete.

How: the attempt retention's pattern (`attempt_retention`): bounded batches
(`WITH candidates AS MATERIALIZED (SELECT id ... LIMIT n FOR UPDATE SKIP
LOCKED) DELETE ...`), each in its own transaction under the tenant's
`tenant_session_scope`, as the application role. Each batch that deletes
anything writes one `ai.usage_monthly.expired` row into that tenant's audit
trail in the same transaction: the count, the cutoff and the retention
period. Safe to run concurrently and idempotent. Run by the same job as the
attempt retention (`saas_os.inference.retention`), with its own switch.

A tenant purge keeps the rollup (`FINANCIAL_RETAIN`, unchanged); this is
age-based housekeeping beside it.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from saas_os.control_plane.inference.usage_rollup import AIUsageMonthly
from saas_os.core.audit_log import record_system_action_in_transaction
from saas_os.core.authority import SystemActor, SystemCorrelation
from saas_os.core.tenancy import list_tenant_ids
from saas_os.infra.db import delete, select, tenant_session_scope
from saas_os.infra.db import now as database_clock

ENABLED_SETTING = "AI_USAGE_ROLLUP_RETENTION_ENABLED"
MONTHS_SETTING = "AI_USAGE_ROLLUP_RETENTION_MONTHS"
DEFAULT_RETENTION_MONTHS = 24
# The floor of migration e8a3c6f1d9b4 and the monthly read's MAX_MONTHS.
MINIMUM_RETENTION_MONTHS = 24
_MAXIMUM_RETENTION_MONTHS = 1200
BATCH_SIZE = 1000
_MAX_BATCHES_PER_TENANT = 10_000

AUDIT_ACTION = "ai.usage_monthly.expired"
AUDIT_RESOURCE_TYPE = "ai_usage_monthly"


class AIUsageRollupRetentionConfigurationError(ValueError):
    """An invalid retention setting. `reason` names it; the value is never
    echoed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"AI usage rollup retention misconfigured: {reason}")


class AIUsageRollupRetentionBatchInvariantError(RuntimeError):
    """One batch reported more deleted rows than its limit; its transaction
    is rolled back and the run stops."""


@dataclass(frozen=True)
class AIUsageRollupRetentionSettings:
    enabled: bool
    retention_months: int


@dataclass(frozen=True)
class AIUsageRollupRetentionResult:
    """Counts only."""

    enabled: bool
    cutoff: datetime | None
    tenants_scanned: int
    deleted: int
    batches: int
    duration_seconds: float


def ai_usage_rollup_retention_settings(
    env: Mapping[str, str] | None = None,
) -> AIUsageRollupRetentionSettings:
    """Reads the two settings. `AI_USAGE_ROLLUP_RETENTION_ENABLED`: `true` or
    `false` (default `false`). `AI_USAGE_ROLLUP_RETENTION_MONTHS`: an integer
    of at least 24 (default 24). Anything else fails closed."""
    source = os.environ if env is None else env
    raw_enabled = source.get(ENABLED_SETTING, "").strip().lower()
    if raw_enabled in ("", "false"):
        enabled = False
    elif raw_enabled == "true":
        enabled = True
    else:
        raise AIUsageRollupRetentionConfigurationError("invalid_ai_usage_rollup_retention_enabled")
    raw_months = source.get(MONTHS_SETTING, "").strip()
    if not raw_months:
        months = DEFAULT_RETENTION_MONTHS
    else:
        try:
            months = int(raw_months, 10)
        except ValueError:
            raise AIUsageRollupRetentionConfigurationError(
                "invalid_ai_usage_rollup_retention_months"
            ) from None
        if not MINIMUM_RETENTION_MONTHS <= months <= _MAXIMUM_RETENTION_MONTHS:
            raise AIUsageRollupRetentionConfigurationError(
                "invalid_ai_usage_rollup_retention_months"
            )
    return AIUsageRollupRetentionSettings(enabled=enabled, retention_months=months)


def _tenant_ids() -> list[uuid.UUID]:
    # Every tenant, closed and purged ones included: a purge keeps the
    # rollup (FINANCIAL_RETAIN), and it ages out here.
    return list_tenant_ids()


def rollup_cutoff(at: datetime, months: int) -> datetime:
    """The first instant of `at`'s UTC month, less `months` months."""
    current = at.astimezone(UTC)
    index = current.year * 12 + current.month - 1 - months
    return datetime(index // 12, index % 12 + 1, 1, tzinfo=UTC)


def _delete_one_batch(
    tenant_id: uuid.UUID,
    cutoff: datetime,
    batch_size: int,
    *,
    actor: SystemActor,
    correlation: SystemCorrelation | None,
    retention_months: int,
) -> int:
    row = AIUsageMonthly
    with tenant_session_scope(tenant_id) as session:
        # The trigger's floor by the database clock of this transaction.
        database_now: datetime = session.execute(select(database_clock())).scalar_one()
        effective = min(cutoff, rollup_cutoff(database_now, MINIMUM_RETENTION_MONTHS))
        candidates = (
            select(row.id)
            .where(row.tenant_id == tenant_id, row.month_start < effective)
            .order_by(row.id)
            .limit(batch_size)
            .with_for_update(skip_locked=True)
            .cte("candidates")
            .prefix_with("MATERIALIZED")
        )
        result: Any = session.execute(delete(row).where(row.id.in_(select(candidates.c.id))))
        removed = int(result.rowcount or 0)
        if removed > batch_size:
            raise AIUsageRollupRetentionBatchInvariantError(
                f"one AI usage rollup retention batch deleted {removed} rows, "
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
                    "retention_months": retention_months,
                },
                correlation=correlation,
            )
    return removed


def expire_ai_usage_rollups(
    *,
    actor: SystemActor,
    correlation: SystemCorrelation | None = None,
    settings: AIUsageRollupRetentionSettings | None = None,
    now: datetime | None = None,
    batch_size: int = BATCH_SIZE,
) -> AIUsageRollupRetentionResult:
    """Deletes rollup rows of months before the cutoff (module docstring).
    Disabled: deletes nothing and returns `enabled=False`. `actor` names the
    executing component in each audit row."""
    cfg = settings if settings is not None else ai_usage_rollup_retention_settings()
    if not isinstance(actor, SystemActor):
        raise TypeError("actor must be a SystemActor.")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1.")
    started = time.monotonic()
    if not cfg.enabled:
        return AIUsageRollupRetentionResult(False, None, 0, 0, 0, time.monotonic() - started)
    if cfg.retention_months < MINIMUM_RETENTION_MONTHS:
        raise AIUsageRollupRetentionConfigurationError("invalid_ai_usage_rollup_retention_months")
    current = now if now is not None else datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware.")
    cutoff = rollup_cutoff(current, cfg.retention_months)

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
                retention_months=cfg.retention_months,
            )
            if removed == 0:
                break
            deleted += removed
            batches += 1
    return AIUsageRollupRetentionResult(
        enabled=True,
        cutoff=cutoff,
        tenants_scanned=len(tenants),
        deleted=deleted,
        batches=batches,
        duration_seconds=time.monotonic() - started,
    )
