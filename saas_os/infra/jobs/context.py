"""Typed job contexts (Foundation Enforcement, FE-5;
docs/ADR/0030-foundation-enforcement.md).

Every registered job declares its kind when it is registered:

    tenant  (`register_tenant_job`)  works on one tenant's data. The payload
            must be a `TenantJobPayload` whose `tenant_id` is a UUID in
            canonical `str(uuid)` form;
            the handler is called as `handler(TenantJobContext, payload)`.
    system  (`register_system_job`)  platform maintenance with no tenant.
            The payload must be `None` (decision D4: the existing `None`
            convention is kept, and the kind decides whether it is valid);
            the handler is called as `handler(SystemJobContext)`.

The worker builds the context from the validated payload before the
handler runs -- a handler never parses a tenant id itself and never sees a
payload that violates its kind. A violation is a permanent contract
failure (`JobContractViolationError`): dead-lettered at once, never
retried, and the handler is never executed.

These types are infrastructure: they carry no tenancy semantics beyond
"which tenant id this job is about". Lifecycle fencing (is the tenant still
open?) stays in Core (`saas_os.core.tenancy.tenant_job_session`, or a handler's own
documented fence) -- `infra` never imports Core.

Attribution (ADR 0061, owner decision C of 2026-11-01) is plain data here,
never authority and never a source of tenant id, in three distinct roles:

- `system_actor` -- the **executing** job: a `JobActor` the worker derives
  itself (kind `worker_job` for a queued job or `scheduled_job` for a
  `system_cron()` run, `name` the registered function name). Core turns it
  into a `saas_os.core.authority.SystemActor` with
  `SystemActor.from_job_actor(context.system_actor)`.
- `initiated_by` (tenant jobs) -- the **initiating** actor, a
  `JobInitiator`: set by the outbox dispatcher from what the event's
  producer recorded; `None` means unavailable (a direct job, or a producer
  that recorded none). Core turns it into an `Initiator` with
  `Initiator.from_job_initiator(context.initiated_by)`.
- `job_id` (the arq job id), `event_id` and `correlation_id` -- the
  **correlation** identity, never an actor.
  `SystemCorrelation.from_job_context(context)` collects them.

It stays plain data because `infra` does not import Core.
"""

from __future__ import annotations

import enum
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


class JobKind(enum.StrEnum):
    TENANT = "tenant"
    SYSTEM = "system"


@dataclass(frozen=True)
class JobActor:
    """The executing job's own attribution (ADR 0061): `kind` is
    `"worker_job"` or `"scheduled_job"`, `name` the registered function
    name. It names the executor only -- never the initiator, and it carries
    no job id (that is `job_id`, correlation). Unvalidated plain data;
    `saas_os.core.authority.SystemActor.from_job_actor()` validates it."""

    kind: str
    name: str


@dataclass(frozen=True)
class JobInitiator:
    """The initiating actor of an outbox event, as its producer recorded it
    (`saas_os.core.authority.Initiator.as_metadata()`), carried to the
    consumer as plain data: `type` is `"user"` (`user_id`),
    `"service_account"` (`service_account_id`) or `"system"` (`kind`,
    `name`, optionally `record_type`/`record_id`). Unvalidated here;
    `saas_os.core.authority.Initiator.from_job_initiator()` validates it."""

    type: str
    user_id: str | None = None
    service_account_id: str | None = None
    kind: str | None = None
    name: str | None = None
    record_type: str | None = None
    record_id: str | None = None


@dataclass(frozen=True)
class TenantJobContext:
    """`event_id` (Reliability & Events RE-5) is the stable identity of the
    durable outbox event this execution runs -- set by the outbox dispatcher
    on every attempt of that event, never regenerated per retry -- so a
    consumer can recognize a repeated execution of the same event. It is
    `None` only for a job enqueued directly rather than dispatched from the
    outbox (a job queued before the outbox existed).

    `system_actor`, `initiated_by` and `job_id` are attribution only (module
    docstring): the executing job, the initiating actor (`None`:
    unavailable) and the arq job id of this execution.

    `external_effect()` (crash recovery D4, option C1 of pull request #195;
    `docs/architecture/OUTBOX-STARTED-MARKER.md`): a consumer wraps the one
    external request whose repetition matters (an HTTP delivery, an e-mail
    send) in `with context.external_effect():`. On entry the outbox
    dispatcher's `start_external_effect` -- bound to this execution's event
    and claim -- commits a durable "started" marker before the block runs,
    or raises (`saas_os.core.outbox.ExternalEffectNotStartedError`) when
    the claim is no longer current, and then nothing must be sent. A crash
    after that point is treated as "the request may have been sent". With
    no starter (a job not dispatched from the outbox, or markers switched
    off) it does nothing and behaves as before. Nothing happens on exit:
    the dispatcher records the outcome."""

    tenant_id: uuid.UUID
    correlation_id: str | None = None
    event_id: uuid.UUID | None = None
    system_actor: JobActor | None = None
    initiated_by: JobInitiator | None = None
    job_id: str | None = None

    start_external_effect: Callable[[], object] | None = field(
        default=None, compare=False, repr=False
    )

    @contextmanager
    def external_effect(self) -> Iterator[None]:
        if self.start_external_effect is not None:
            self.start_external_effect()
        yield


@dataclass(frozen=True)
class SystemJobContext:
    correlation_id: str | None = None
    system_actor: JobActor | None = None
    job_id: str | None = None
