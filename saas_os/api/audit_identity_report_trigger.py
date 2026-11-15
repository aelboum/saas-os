"""Audit identity phase P2 (owner decision D7) -- the scheduling entrypoint of
the audit identity expiry report job.

    python -m saas_os.api.audit_identity_report_trigger

Enqueues exactly one report job
(`saas_os.core.audit_identity.jobs`) onto the existing ARQ/Redis
queue and exits; the running `saas_os.api.worker` executes it. The same
producer/worker split and host-level timer as
`saas_os/api/session_cleanup_trigger.py`: `deploy/saas-os-audit-identity-report.timer`
runs it daily. Enqueuing twice is harmless: the job only reads and
logs; it deletes nothing.

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


async def trigger_audit_identity_report() -> str:
    """Enqueue one report job. Returns the arq job id."""
    # Imported here: registering the job resolves `REDIS_URL`, and a
    # missing one must be the structured failure below, not a traceback.
    from saas_os.core.audit_identity.jobs import AUDIT_IDENTITY_REPORT_JOB_NAME

    return await enqueue_job(AUDIT_IDENTITY_REPORT_JOB_NAME, payload=None)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        logger.error(
            "audit_identity_report_trigger_invalid_arguments",
            extra={"argument_count": len(args)},
        )
        return _EXIT_FAILURE

    configure_logging()
    try:
        job_id = asyncio.run(trigger_audit_identity_report())
    except Exception as exc:  # noqa: BLE001 -- every startup/enqueue failure must exit non-zero
        detail = str(exc) if isinstance(exc, JobsConfigurationError) else None
        logger.error(
            "audit_identity_report_trigger_failed",
            extra={"error_type": type(exc).__name__, "error_detail": detail},
        )
        return _EXIT_FAILURE

    logger.info("audit_identity_report_triggered", extra={"job_id": job_id})
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
