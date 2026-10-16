"""The audit-digest schedule (docs/ADR/0053-audit-digests-in-external-logs.md):
a system job the production worker runs every minute
(`saas_os.api.worker.registered_cron_jobs`). Each run digests the windows
that have settled since the last one; most runs find none and do nothing."""

from __future__ import annotations

import logging

from arq.worker import Function

from saas_os.core.audit_digest.service import digest_settled_windows
from saas_os.infra.jobs import SystemJobContext, register_system_job

logger = logging.getLogger(__name__)


async def _audit_digest_cycle(context: SystemJobContext) -> None:
    run = digest_settled_windows()
    if run.records or run.stopped_by_concurrent_run:
        logger.info(
            "audit_digest_cycle_completed",
            extra={
                "windows": len(run.records),
                "stopped_by_concurrent_run": run.stopped_by_concurrent_run,
            },
        )


# Scheduled only (`system_cron`), never enqueued -- like the outbox dispatch cycle.
AUDIT_DIGEST_CYCLE: Function = register_system_job(_audit_digest_cycle)
