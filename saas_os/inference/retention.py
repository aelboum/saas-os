"""`saas_os.inference.retention` -- the public, opt-in AI attempt retention
job (owner decision of 2026-11-13; `docs/CONSUMER-GUIDE.md`, "AI attempt
retention").

Deletes finished AI attempt rows older than `AI_ATTEMPT_RETENTION_DAYS`
(default 100, at least 93) that no budget reservation holds, tenant by
tenant, with one `ai.attempts.purged` audit row per batch in the tenant's
trail. The monthly usage rollup keeps their totals. It deletes nothing
unless `AI_ATTEMPT_RETENTION_ENABLED=true`.

The same job, with its own switch, expires monthly usage rollup rows older
than `AI_USAGE_ROLLUP_RETENTION_MONTHS` (default 24, at least 24; the current
month never counts), with one `ai.usage_monthly.expired` audit row per batch.
It deletes no rollup row unless `AI_USAGE_ROLLUP_RETENTION_ENABLED=true`.

A product opts in twice: it adds the job to its own worker entrypoint
(`saas_os.api.worker`, "Consumer jobs"),

    from saas_os.api.worker import main
    from saas_os.inference.retention import AI_ATTEMPT_RETENTION_JOB_FUNCTIONS

    sys.exit(main(extra_functions=[*my_jobs, *AI_ATTEMPT_RETENTION_JOB_FUNCTIONS]))

and enqueues it on a schedule, for example daily from a host timer:

    python -m saas_os.inference.retention

Importing this module registers the job, which reads `REDIS_URL`; that is
why it is not part of `saas_os.inference` itself.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from saas_os.control_plane.inference.attempt_retention_jobs import (
    AI_ATTEMPT_RETENTION_JOB_FUNCTIONS,
    AI_ATTEMPT_RETENTION_JOB_NAME,
)
from saas_os.infra.jobs import JobsConfigurationError, enqueue_job
from saas_os.infra.observability import configure_logging

logger = logging.getLogger(__name__)

_EXIT_OK = 0
_EXIT_FAILURE = 1


async def trigger_ai_attempt_retention() -> str:
    """Enqueue one retention job. Returns the arq job id."""
    return await enqueue_job(AI_ATTEMPT_RETENTION_JOB_NAME, payload=None)


def main(argv: list[str] | None = None) -> int:
    """`python -m saas_os.inference.retention`: enqueue one job and exit.
    Any failure is logged by type and exits non-zero."""
    args = sys.argv[1:] if argv is None else argv
    if args:
        logger.error(
            "ai_attempt_retention_trigger_invalid_arguments",
            extra={"argument_count": len(args)},
        )
        return _EXIT_FAILURE
    configure_logging()
    try:
        job_id = asyncio.run(trigger_ai_attempt_retention())
    except Exception as exc:  # noqa: BLE001 -- every enqueue failure must exit non-zero
        detail = str(exc) if isinstance(exc, JobsConfigurationError) else None
        logger.error(
            "ai_attempt_retention_trigger_failed",
            extra={"error_type": type(exc).__name__, "error_detail": detail},
        )
        return _EXIT_FAILURE
    logger.info("ai_attempt_retention_triggered", extra={"job_id": job_id})
    return _EXIT_OK


__all__ = [
    "AI_ATTEMPT_RETENTION_JOB_FUNCTIONS",
    "AI_ATTEMPT_RETENTION_JOB_NAME",
    "main",
    "trigger_ai_attempt_retention",
]


if __name__ == "__main__":
    sys.exit(main())
