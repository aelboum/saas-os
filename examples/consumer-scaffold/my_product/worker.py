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

import sys

from saas_os.api.worker import main


def run(argv: list[str] | None = None) -> int:
    # Imported here: registering a job resolves REDIS_URL.
    from my_product.jobs import JOB_FUNCTIONS

    return main(argv, extra_functions=JOB_FUNCTIONS)


if __name__ == "__main__":
    sys.exit(run())
