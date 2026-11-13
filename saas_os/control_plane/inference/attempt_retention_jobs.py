"""The registered job for AI retention: the attempt retention
(`saas_os.control_plane.inference.attempt_retention`) and, with its own
switch, the monthly rollup expiry
(`saas_os.control_plane.inference.usage_rollup_retention`).

A separate module because registering a job reads the jobs configuration
(`REDIS_URL`) at import, and importing the inference package must not
require a queue (the same split as `saas_os.core.billing.provider_event_jobs`).
The platform worker does not import it: the HTTP and worker layer never
imports the AI Control Plane. A product opts in by adding
`AI_ATTEMPT_RETENTION_JOB_FUNCTIONS` to its worker's functions (through the
public `saas_os.inference.retention`) and enqueuing the job on a schedule;
the job still deletes nothing unless `AI_ATTEMPT_RETENTION_ENABLED=true`
(attempts) or `AI_USAGE_ROLLUP_RETENTION_ENABLED=true` (rollup rows). Both
settings are read before anything is deleted, so a malformed one fails the
run with nothing deleted.
"""

from __future__ import annotations

import logging

from arq.worker import Function

from saas_os.control_plane.inference.attempt_retention import (
    ai_attempt_retention_settings,
    purge_expired_ai_attempts,
)
from saas_os.control_plane.inference.usage_rollup_retention import (
    ai_usage_rollup_retention_settings,
    expire_ai_usage_rollups,
)
from saas_os.core.authority import SystemActor, SystemCorrelation
from saas_os.infra.jobs import SystemJobContext, register_system_job

logger = logging.getLogger(__name__)


async def _purge_expired_ai_attempts_job(context: SystemJobContext) -> None:
    """A system job (no payload): it walks every tenant itself, attempts
    first, then rollup rows. Logs counts only."""
    attempt_settings = ai_attempt_retention_settings()
    rollup_settings = ai_usage_rollup_retention_settings()
    actor = SystemActor.from_job_actor(context.system_actor)
    correlation = SystemCorrelation.from_job_context(context)
    result = purge_expired_ai_attempts(
        actor=actor, correlation=correlation, settings=attempt_settings
    )
    logger.info(
        "ai_attempt_retention_completed",
        extra={
            "enabled": result.enabled,
            "tenants_scanned": result.tenants_scanned,
            "deleted": result.deleted,
            "batches": result.batches,
            "duration_seconds": round(result.duration_seconds, 3),
        },
    )
    rollups = expire_ai_usage_rollups(
        actor=actor, correlation=correlation, settings=rollup_settings
    )
    logger.info(
        "ai_usage_rollup_retention_completed",
        extra={
            "enabled": rollups.enabled,
            "tenants_scanned": rollups.tenants_scanned,
            "deleted": rollups.deleted,
            "batches": rollups.batches,
            "duration_seconds": round(rollups.duration_seconds, 3),
        },
    )


AI_ATTEMPT_RETENTION_JOB_FUNCTIONS: list[Function] = [
    register_system_job(_purge_expired_ai_attempts_job)
]

# The registered name `saas_os.infra.jobs.enqueue_job()` needs.
AI_ATTEMPT_RETENTION_JOB_NAME: str = _purge_expired_ai_attempts_job.__name__
