"""`saas_os/infra/jobs` -- generic background job execution
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.4;
docs/ADR/0007-background-job-and-workflow-engine.md; docs/DATA-ARCHITECTURE.md
section 5).

A Redis-backed queue/worker runner (concretely: **ARQ**, per ADR-0007),
deliberately narrow: enqueue, execute, retry-on-failure, dead-letter --
nothing else. No multi-step or compensating-workflow semantics; a future
durable workflow engine (Phase 7+) is added alongside this module, not by
extending it (ADR-0007).

No business-logic job is registered here -- this phase ships the runner
only.

    job producer
        -> enqueue_job(function_name, payload)     # payload: TenantJobPayload | None
            -> Redis (arq queue)
                -> worker executes the registered handler
                    -> success, or
                    -> arq.Retry (attempts remain), or
                    -> dead-lettered (attempts exhausted; recorded via
                       saas_os.infra.jobs.dead_letter, never retried again)

`tenant_id` is required by `TenantJobPayload`'s own schema (a dataclass
field, validated at construction) for any job payload that carries
tenant-owned data (docs/MULTI-TENANCY.md section 4) -- a job with no
tenant-owned data passes `payload=None` instead.

`REDIS_URL` is sourced through `saas_os.infra.secrets`'s `SecretsProvider`
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.3) -- `saas_os/infra/jobs` does not read
it from `os.environ` directly. `saas_os/infra/jobs` does not import `core`,
`products`, or `control_plane`, and does not import any AI/LLM framework --
the same boundary rules as every other `infra` subpackage
(docs/ARCHITECTURE.md section 2).

A raw Redis connection (`saas_os.infra.jobs.queue.get_redis_pool`) is deliberately
*not* re-exported here -- the public surface is enqueue/execute/retry/
dead-letter only (ADR-0007's narrow interface), not a general-purpose
Redis client. `get_redis_pool` remains available to `saas_os/infra/jobs`'s own
internals (`build_worker`, `enqueue_job`) and to tests via
`saas_os.infra.jobs.queue`.
"""

from saas_os.infra.jobs.config import JobsConfig, get_jobs_config
from saas_os.infra.jobs.context import JobKind, SystemJobContext, TenantJobContext
from saas_os.infra.jobs.dead_letter import (
    DeadLetterEntry,
    count_dead_letters,
    list_dead_letters,
    purge_tenant_dead_letters_sync,
)
from saas_os.infra.jobs.errors import (
    InvalidJobPayloadError,
    JobContractViolationError,
    JobDeadLetteredError,
    JobsConfigurationError,
    MissingTenantIdError,
)
from saas_os.infra.jobs.payload import TenantJobPayload
from saas_os.infra.jobs.queue import (
    build_worker,
    enqueue_job,
    register_system_job,
    register_tenant_job,
    registered_job_kind,
)

__all__ = [
    "JobsConfig",
    "get_jobs_config",
    "TenantJobPayload",
    "MissingTenantIdError",
    "InvalidJobPayloadError",
    "JobsConfigurationError",
    "JobDeadLetteredError",
    "DeadLetterEntry",
    "count_dead_letters",
    "list_dead_letters",
    "purge_tenant_dead_letters_sync",
    "enqueue_job",
    "register_tenant_job",
    "register_system_job",
    "registered_job_kind",
    "JobKind",
    "TenantJobContext",
    "SystemJobContext",
    "JobContractViolationError",
    "build_worker",
]
