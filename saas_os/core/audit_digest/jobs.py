"""The audit-digest schedule (docs/ADR/0053-audit-digests-in-external-logs.md):
a system job the production worker runs every minute
(`saas_os.api.worker.registered_cron_jobs`). Each run digests the windows
that have settled since the last one; most runs find none and do nothing.

The digest is synchronous database work that reads every tenant in its own
transaction (`saas_os.core.audit_digest.service`), so it runs in a thread, one
run at a time per worker process (`saas_os.infra.jobs.single_flight`): on
the event loop, an installation with many tenants would stall every other
job of the worker for the length of the run. A run that starts while the
previous one is still in its thread is skipped and logged. Two worker
processes may still run at once; the second store of a window fails and
ends that run (ADR-0053 section 7)."""

from __future__ import annotations

import logging

from arq.worker import Function

from saas_os.core.audit_digest.service import digest_settled_windows
from saas_os.infra.jobs import SystemJobContext, register_system_job
from saas_os.infra.jobs.single_flight import run_in_thread_once

logger = logging.getLogger(__name__)


def _digest_once() -> None:
    run = digest_settled_windows()
    if run.records or run.stopped_by_concurrent_run:
        logger.info(
            "audit_digest_cycle_completed",
            extra={
                "windows": len(run.records),
                "stopped_by_concurrent_run": run.stopped_by_concurrent_run,
            },
        )


async def _audit_digest_cycle(context: SystemJobContext) -> None:
    if not await run_in_thread_once("audit_digest_cycle", _digest_once):
        logger.info("audit_digest_cycle_skipped", extra={"reason": "previous_run_in_progress"})


# Scheduled only (`system_cron`), never enqueued -- like the outbox dispatch cycle.
AUDIT_DIGEST_CYCLE: Function = register_system_job(_audit_digest_cycle)
