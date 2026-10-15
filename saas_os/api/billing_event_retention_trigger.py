"""ADR-0048 -- the production scheduling entrypoint for pruning
`core.billing_provider_events`.

    python -m saas_os.api.billing_event_retention_trigger

Enqueues exactly one retention job
(`saas_os.core.billing.provider_event_jobs`) onto the existing ARQ/Redis
queue and exits; the running `saas_os.api.worker` executes it. The same
producer/worker split and host-level timer as
`saas_os/api/session_cleanup_trigger.py`: `deploy/saas-os-billing-event-retention.timer`
runs it daily. Enqueuing twice is harmless: pruning is idempotent and
safe against overlapping runs.

Fails closed like that trigger: a missing or malformed `REDIS_URL`, or
any other failure, is logged by type name and becomes a non-zero exit,
which `systemd` reports as a failed unit.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from saas_os.infra.jobs import JobsConfigurationError, enqueue_job
from saas_os.infra.observability import configure_logging

logger = logging.getLogger(__name__)

_EXIT_OK = 0
_EXIT_FAILURE = 1


async def trigger_billing_event_retention() -> str:
    """Enqueue one retention job. Returns the arq job id."""
    # Imported here: registering the job resolves `REDIS_URL`, and a
    # missing one must be the structured failure below, not a traceback.
    from saas_os.core.billing.provider_event_jobs import BILLING_EVENT_RETENTION_JOB_NAME

    return await enqueue_job(BILLING_EVENT_RETENTION_JOB_NAME, payload=None)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        logger.error(
            "billing_event_retention_trigger_invalid_arguments",
            extra={"argument_count": len(args)},
        )
        return _EXIT_FAILURE

    configure_logging()
    try:
        job_id = asyncio.run(trigger_billing_event_retention())
    except Exception as exc:  # noqa: BLE001 -- every startup/enqueue failure must exit non-zero
        detail = str(exc) if isinstance(exc, JobsConfigurationError) else None
        logger.error(
            "billing_event_retention_trigger_failed",
            extra={"error_type": type(exc).__name__, "error_detail": detail},
        )
        return _EXIT_FAILURE

    logger.info("billing_event_retention_triggered", extra={"job_id": job_id})
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
