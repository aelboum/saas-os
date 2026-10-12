"""RA-12-5 -- the production scheduling entrypoint for `core.sessions`
housekeeping.

    python -m saas_os.api.session_cleanup_trigger

Enqueues exactly one `saas_os.core.identity.session_retention` cleanup job onto
the existing ARQ/Redis queue (`saas_os.infra.jobs.enqueue_job()`) and exits. The
job itself is executed by the already-running, already-registered
`saas_os.api.worker` process (`registered_job_functions()` includes
`saas_os.core.identity.SESSION_CLEANUP_JOB_FUNCTIONS`) -- this script never opens
a database connection or runs the cleanup logic itself, exactly the same
producer/worker split every other job in this repository already uses
(`saas_os.core.notifications.dispatch_notification()`, `saas_os.core.usage`'s ingestion
enqueue, etc. all enqueue and let the worker execute).

**Scheduling** (docs/MULTI-TENANCY.md section 6's RA-12-5 addendum): a host-level `systemd` timer
(`deploy/saas-os-session-cleanup.service` + `.timer`) invokes this script
periodically -- the same "host-level timer runs a small Python
entrypoint" mechanism `deploy/saas-os-backup.timer` already establishes
for the backup pipeline, reused here rather than inventing a second
scheduling mechanism (`saas_os/infra/jobs` ships no cron/periodic-trigger feature
of its own; nothing in this repository uses arq's own `cron_jobs` worker
option, so introducing it here would be a second, unprecedented
scheduling mechanism alongside the systemd-timer one this repository
already has). Unlike the backup pipeline, this script deliberately *does*
depend on `saas_os.api.worker` being up -- session cleanup is ordinary
application housekeeping, not a disaster-recovery path, so no circular-
recovery-dependency concern applies (contrast
`deploy/saas-os-backup.service`'s own docstring).

Idempotent to invoke repeatedly or concurrently: enqueuing the job twice
before the worker has picked either up simply queues it twice, and
`cleanup_expired_sessions()` itself is idempotent and safe against
overlapping execution (`saas_os/core/identity/session_retention.py`'s own
docstring) -- there is no harm in an occasional double-enqueue from timer
jitter or a manual run overlapping a scheduled one.

**Fail-closed startup, same discipline as `saas_os/api/worker.py`**: a missing or
malformed `REDIS_URL` raises before any enqueue attempt; any exception is
logged by type name (never by message, since a connection-string parser
could echo the DSN it failed on) and turned into a non-zero exit --
`systemd` then reports this as a failed unit, visible to `systemctl
status`/`journalctl`, exactly like a failed backup run.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from saas_os.core.identity import SESSION_CLEANUP_JOB_NAME
from saas_os.infra.jobs import JobsConfigurationError, enqueue_job
from saas_os.infra.observability import configure_logging

logger = logging.getLogger(__name__)

_EXIT_OK = 0
_EXIT_FAILURE = 1


async def trigger_session_cleanup() -> str:
    """Enqueue one session-cleanup job. Returns the arq job id."""
    return await enqueue_job(SESSION_CLEANUP_JOB_NAME, payload=None)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        logger.error(
            "session_cleanup_trigger_invalid_arguments", extra={"argument_count": len(args)}
        )
        return _EXIT_FAILURE

    configure_logging()
    try:
        job_id = asyncio.run(trigger_session_cleanup())
    except Exception as exc:  # noqa: BLE001 -- every startup/enqueue failure must exit non-zero
        detail = str(exc) if isinstance(exc, JobsConfigurationError) else None
        logger.error(
            "session_cleanup_trigger_failed",
            extra={"error_type": type(exc).__name__, "error_detail": detail},
        )
        return _EXIT_FAILURE

    logger.info("session_cleanup_triggered", extra={"job_id": job_id})
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
