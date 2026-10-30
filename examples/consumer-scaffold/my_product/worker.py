"""This product's worker process.

    python -m my_product.worker            # long-running worker
    python -m my_product.worker --check    # container health probe

It is SaaS OS's own production worker (`saas_os.api.worker.main`) with this
product's jobs added: the same startup order, the same fail-closed
database-role guard, the same health probe, and every platform job
(webhook delivery, usage ingestion, notifications, session cleanup, the
outbox dispatcher) still running. Run this instead of `python -m
saas_os.api.worker`, not next to it.
"""

from __future__ import annotations

import logging
import sys

from saas_os.api.worker import main
from saas_os.infra.observability import configure_logging

logger = logging.getLogger(__name__)


def run(argv: list[str] | None = None) -> int:
    # Imported here: registering a job resolves REDIS_URL. A failure (for
    # example REDIS_URL unset) is logged like SaaS OS's own startup failures,
    # by error type only, never as a traceback, and exits 1.
    try:
        from my_product.jobs import JOB_FUNCTIONS
    except Exception as exc:  # noqa: BLE001 -- every startup failure must exit non-zero
        configure_logging()
        logger.error("worker_startup_failed", extra={"error_type": type(exc).__name__})
        return 1

    return main(argv, extra_functions=JOB_FUNCTIONS)


if __name__ == "__main__":
    sys.exit(run())
