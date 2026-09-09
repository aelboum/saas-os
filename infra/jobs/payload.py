"""Job payload schema (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4,
docs/MULTI-TENANCY.md section 4: "every job payload carries tenant_id").

`TenantJobPayload` is how a job producer carries tenant-owned data through
`infra/jobs` -- `tenant_id` is a required field, so a job that acts on
tenant data cannot be enqueued without one; this is a schema-level check
(enforced by the dataclass itself at construction), not a runtime lookup
inside `enqueue_job()`. A job with no tenant-owned data (rare -- platform
maintenance only) passes `payload=None` to `enqueue_job()` instead of using
this type.

**P2.1 (worker runtime) -- two small, backwards-compatible additions:**

- `correlation_id` (optional, default `None`): the producer-side
  `request_id` (`infra.observability.context.CorrelationContext`) captured
  at enqueue time by `infra.jobs.queue.enqueue_job()` when one is ambient,
  so a job's own log lines can be correlated back to the HTTP request (or
  other unit of work) that enqueued it. Purely correlation metadata --
  never read to determine tenant, identity, or authorization (the same
  rule `api/middleware.py` already states for `X-Request-ID`).
- `data` is excluded from `repr()` (`field(repr=False)`): arq logs
  `repr()` of every job's arguments at INFO level when a job starts
  (`arq.worker.Worker.run_job` -> `args_to_string`), so with the default
  dataclass repr a running worker would print every payload's contents --
  a notification body, a recipient email address, a webhook event's data
  -- into the worker log on every execution. Only `tenant_id` and
  `correlation_id` (both plain identifiers, never sensitive content) ever
  appear in a repr; the payload's actual data is available to the job
  handler exactly as before, just never to a log line by accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from infra.jobs.errors import MissingTenantIdError


@dataclass(frozen=True)
class TenantJobPayload:
    tenant_id: str
    data: dict[str, Any] = field(default_factory=dict, repr=False)
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise MissingTenantIdError()
