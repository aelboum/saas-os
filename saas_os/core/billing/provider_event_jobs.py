"""The scheduled retention job for `core.billing_provider_events`
(docs/ADR/0048-inbound-billing-provider-events.md).

A separate module from `provider_events.py` because registering a job
reads the jobs configuration (`REDIS_URL`) at import, and importing
`saas_os.core.billing` must not require a queue. The worker imports this
module (`saas_os/api/worker.py::registered_job_functions`), and
`python -m saas_os.api.billing_event_retention_trigger`, run by the host
timer `deploy/saas-os-billing-event-retention.timer`, enqueues the job.
"""

from __future__ import annotations

import logging

from arq.worker import Function

from saas_os.core.billing.provider_events import prune_provider_events
from saas_os.infra.jobs import SystemJobContext, register_system_job

logger = logging.getLogger(__name__)


async def _prune_billing_provider_events_job(context: SystemJobContext) -> None:
    """Prune ledger rows past the retention period. A system job: the
    ledger is global and the job takes no payload."""
    deleted = prune_provider_events()
    logger.info("billing_provider_events_pruned", extra={"deleted": deleted})


BILLING_EVENT_RETENTION_JOB_FUNCTIONS: list[Function] = [
    register_system_job(_prune_billing_provider_events_job)
]

# The registered name `saas_os.infra.jobs.enqueue_job()` needs, so the
# trigger never repeats a private function's name as a string literal.
BILLING_EVENT_RETENTION_JOB_NAME: str = _prune_billing_provider_events_job.__name__
