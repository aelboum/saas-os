"""The scheduled report job of audit identity expiry (owner decision D7:
"scheduled jobs may only report"; proposal section 4.10).

A separate module because registering a job reads the jobs configuration
(`REDIS_URL`) at import, and importing `saas_os.core.audit_identity` must
not require a queue. The platform worker imports it
(`saas_os/api/worker.py::registered_job_functions`), and
`python -m saas_os.api.audit_identity_report_trigger`, run by the host timer
`deploy/saas-os-audit-identity-report.timer`, enqueues it.

The job runs as the application role, which has no `DELETE` on the link,
marker or hold tables: it computes the platform scope's expiry plan
(`audit_identity_expiry_report`) and logs counts, digests and the oldest
eligible day. It deletes and writes nothing. While `--apply` is disabled
(owner decision O9) every eligible link it reports is kept beyond two years;
the report shows that backlog.
"""

from __future__ import annotations

import logging

from arq.worker import Function

from saas_os.core.audit_identity.plan import audit_identity_expiry_report
from saas_os.infra.jobs import SystemJobContext, register_system_job

logger = logging.getLogger(__name__)


async def _report_audit_identity_expiry_job(context: SystemJobContext) -> None:
    """A system job with no payload: report, never delete."""
    report = audit_identity_expiry_report()
    logger.info(
        "audit_identity_expiry_report",
        extra={
            "scope": report.scope,
            "eligible_links": report.eligible_links,
            "eligible_links_digest": report.eligible_links_digest,
            "links_to_unlink": report.links_to_unlink,
            "markers": report.markers,
            "active_holds": report.active_holds,
            "active_holds_digest": report.active_holds_digest,
            "oldest_eligible_day": (
                report.oldest_eligible_day.isoformat()
                if report.oldest_eligible_day is not None
                else None
            ),
        },
    )


AUDIT_IDENTITY_REPORT_JOB_FUNCTIONS: list[Function] = [
    register_system_job(_report_audit_identity_expiry_job)
]

# The registered name `saas_os.infra.jobs.enqueue_job()` needs.
AUDIT_IDENTITY_REPORT_JOB_NAME: str = _report_audit_identity_expiry_job.__name__
