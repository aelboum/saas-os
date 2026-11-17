"""The audit-digest schedule (docs/ADR/0053-audit-digests-in-external-logs.md):
a system job the production worker runs every minute
(`saas_os.api.worker.registered_cron_jobs`). Each run digests the windows
that have settled since the last one; most runs find none and do nothing.

The digest is synchronous database work that reads every tenant in its own
transaction (`saas_os.core.audit_digest.service`), so it runs in a thread
(`asyncio.to_thread`, as the email consumer does): on the event loop, an
installation with many tenants would stall every other job of the worker
for the length of the run. One run at a time per worker process: a run that
starts while the previous one is still in its thread is skipped and logged,
so slow runs do not pile up threads in the shared executor, and a run the
handler timeout cancels keeps its thread to the end (no second run starts
beside it). Two worker processes may still run at once; the second store
of a window fails and ends that run (ADR-0053 section 7)."""

from __future__ import annotations

import asyncio
import logging

from arq.worker import Function

from saas_os.core.audit_digest.service import digest_settled_windows
from saas_os.infra.jobs import SystemJobContext, register_system_job

logger = logging.getLogger(__name__)

# The run in progress in this worker process, if any. A task, not a lock
# held across the thread: the job awaits it shielded, so a cancelled job
# (the handler timeout) leaves the thread to finish and the task to
# complete, and the next run sees it done.
_running: asyncio.Task[None] | None = None


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
    global _running
    loop = asyncio.get_running_loop()
    if _running is not None and not _running.done() and _running.get_loop() is loop:
        logger.info("audit_digest_cycle_skipped", extra={"reason": "previous_run_in_progress"})
        return
    _running = loop.create_task(asyncio.to_thread(_digest_once))
    await asyncio.shield(_running)


# Scheduled only (`system_cron`), never enqueued -- like the outbox dispatch cycle.
AUDIT_DIGEST_CYCLE: Function = register_system_job(_audit_digest_cycle)
