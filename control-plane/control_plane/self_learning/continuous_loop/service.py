"""The Continuous Improvement Loop: check the kill switch, find the most
recent terminal outcome, seed the next cycle (docs/IMPLEMENTATION-
ROADMAP.md Phase 9.9).

**This module performs zero mutations** -- it never proposes an
adaptation, never runs an experiment, never activates/promotes/rolls
anything back. It reuses every existing gate exactly as-is:

- **Kill switch**: `core.feature_flags.evaluate_flag(tenant_id,
  _KILL_SWITCH_FLAG_KEY, default=False)` -- reuses the existing
  feature-flag mechanism (docs/AI-CONTROL-PLANE.md section 9's own
  kill-switch design requirement) rather than inventing a second
  disable mechanism. `default=False` means the loop is **disabled by
  default** for any tenant that has never had the flag explicitly
  created/enabled for it -- default deny, the same discipline every
  other gate in this platform ships. Evaluated exactly once, at the very
  start of `run_continuous_learning_cycle()` -- there is nothing after
  that check for a flag flip to interrupt, because nothing after it
  mutates anything.
- **Tenant isolation**: every query below is issued through
  `infra.db.tenant_session_scope(tenant_id)`, the same RLS-scoped session
  every other phase's own service functions use -- there is no query
  path here that could return another tenant's `Adaptation`/`Canary` row,
  with or without a correctly-scoped `tenant_id` argument.
- **Data Authorization / Learning Authorization**: not re-evaluated here
  because nothing here reads *new* evidence -- this module only reads the
  identity/status/timestamp columns of already-authorized, already-persisted
  `Adaptation`/`Canary` rows (Phase 9.4/9.8's own gates already ran when
  those rows were created); it never reaches into `core.audit_log`'s or
  any other module's raw content, and never interprets a metric or log
  line as new, unauthorized evidence.

**Idempotency and concurrency, by construction**: because this module
never mutates a `self_learning.adaptations`/`self_learning.canaries` row
or creates a new one, invoking `run_continuous_learning_cycle()` twice --
concurrently, via a retried job delivery, or via a duplicate manual
trigger -- produces two independent, harmless read-only `LoopCycle`
summaries (and two `core.audit_log` entries), never a duplicate
adaptation, canary, promotion, or rollback. There is no idempotency key
to invent because there is no mutating side effect for a duplicate
delivery to double-apply.

**Only `Adaptation` and `Canary` can seed a cycle** -- see `models.py`'s
own docstring for why `SystemLearningProposal` (Phase 9.5) structurally
cannot: it is never persisted.

Recurring/scheduled execution reuses `infra.jobs` exactly as every other
scheduled operation in this codebase does (`core.webhooks._deliver_webhook`
is the model this module's own `_run_continuous_learning_cycle_job`/
`CONTINUOUS_LOOP_JOB_FUNCTIONS`/`trigger_continuous_learning_cycle` mirror)
-- `infra.jobs.register_job()`'s own retry-with-backoff-then-dead-letter
policy is this module's entire retry story; nothing here implements a
second one. Actually wiring a recurring cadence (e.g. "once per tenant
per hour") is deployment/operations configuration -- a periodic caller of
`trigger_continuous_learning_cycle()`, exactly as any other scheduled
operation on this platform would be wired -- never a new scheduler
built inside this module (`infra/jobs`'s own docstring: "no multi-step or
compensating-workflow semantics ... a future durable workflow engine is
added alongside this module, not by extending it").
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from arq.worker import Function

from control_plane.self_learning.adaptive.models import Adaptation, AdaptationStatus
from control_plane.self_learning.autonomous_improvement.models import Canary, CanaryStatus
from control_plane.self_learning.continuous_loop.models import (
    LoopCycle,
    LoopCycleOutcome,
    LoopObservationSeed,
    LoopObservationSourceKind,
    LoopTrigger,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.feature_flags import evaluate_flag
from infra.db import select, tenant_session_scope
from infra.jobs import TenantJobPayload, enqueue_job, register_job

_AUDIT_ACTION = "learning.continuous_loop_cycle_completed"
_AUDIT_RESOURCE_TYPE = "self_learning_continuous_loop_cycle"

_KILL_SWITCH_FLAG_KEY = "self_learning.continuous_loop_enabled"

_TERMINAL_ADAPTATION_STATUSES: frozenset[str] = frozenset(
    {AdaptationStatus.ACTIVE.value, AdaptationStatus.ROLLED_BACK.value}
)
_TERMINAL_CANARY_STATUSES: frozenset[str] = frozenset(
    {
        CanaryStatus.PROMOTED.value,
        CanaryStatus.ROLLED_BACK.value,
        CanaryStatus.ROLLBACK_FAILED.value,
    }
)


def _most_recent_terminal_seed(tenant_id: uuid.UUID) -> LoopObservationSeed | None:
    """Read-only: the single most recently updated terminal `Canary` or
    `Adaptation` row for `tenant_id`, whichever is newer -- never a write,
    never a cross-tenant query (see module docstring).

    Ordering is by `updated_at`, which Postgres's `now()` sets to
    *transaction*-start time, not statement time -- two rows updated in
    the same transaction (e.g. `rollback_adaptation()`'s own rolled-back
    row and its reactivated-previous row) can carry an identical
    `updated_at`. Which one this function returns in that exact tie is
    implementation-defined; both are equally real, equally terminal
    outcomes of the same event, so this is a benign ordering ambiguity,
    never a wrong-tenant or fabricated result."""
    with tenant_session_scope(tenant_id) as session:
        adaptation = session.execute(
            select(Adaptation)
            .where(
                Adaptation.tenant_id == tenant_id,
                Adaptation.status.in_(_TERMINAL_ADAPTATION_STATUSES),
            )
            .order_by(Adaptation.updated_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        canary = session.execute(
            select(Canary)
            .where(Canary.tenant_id == tenant_id, Canary.status.in_(_TERMINAL_CANARY_STATUSES))
            .order_by(Canary.updated_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        candidates: list[tuple[datetime, LoopObservationSeed]] = []
        if adaptation is not None:
            candidates.append(
                (
                    adaptation.updated_at,
                    LoopObservationSeed(
                        source_kind=LoopObservationSourceKind.ADAPTATION,
                        source_id=adaptation.id,
                        tenant_id=tenant_id,
                        outcome_summary=adaptation.status,
                    ),
                )
            )
        if canary is not None:
            candidates.append(
                (
                    canary.updated_at,
                    LoopObservationSeed(
                        source_kind=LoopObservationSourceKind.CANARY,
                        source_id=canary.id,
                        tenant_id=tenant_id,
                        outcome_summary=canary.status,
                    ),
                )
            )

    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0])
    return candidates[-1][1]


def run_continuous_learning_cycle(
    tenant_id: uuid.UUID,
    *,
    trigger: LoopTrigger,
    actor_user_id: uuid.UUID | None = None,
) -> LoopCycle:
    """Run exactly one cycle for `tenant_id`. See module docstring for
    why this never mutates anything and is therefore safe to run
    concurrently, repeatedly, or after a retry."""
    started_at = datetime.now(UTC)

    if not evaluate_flag(tenant_id, _KILL_SWITCH_FLAG_KEY, default=False):
        cycle = LoopCycle(
            tenant_id=tenant_id,
            trigger=trigger,
            outcome=LoopCycleOutcome.DISABLED,
            started_at=started_at,
            ended_at=datetime.now(UTC),
        )
        _audit(cycle, actor_user_id=actor_user_id, outcome=AuditOutcome.DENIED)
        return cycle

    seed = _most_recent_terminal_seed(tenant_id)
    if seed is None:
        cycle = LoopCycle(
            tenant_id=tenant_id,
            trigger=trigger,
            outcome=LoopCycleOutcome.NO_VIABLE_CANDIDATE,
            started_at=started_at,
            ended_at=datetime.now(UTC),
        )
        _audit(cycle, actor_user_id=actor_user_id, outcome=AuditOutcome.SUCCESS)
        return cycle

    cycle = LoopCycle(
        tenant_id=tenant_id,
        trigger=trigger,
        outcome=LoopCycleOutcome.COMPLETED,
        started_at=started_at,
        ended_at=datetime.now(UTC),
        seed=seed,
    )
    _audit(cycle, actor_user_id=actor_user_id, outcome=AuditOutcome.SUCCESS)
    return cycle


def _audit(cycle: LoopCycle, *, actor_user_id: uuid.UUID | None, outcome: AuditOutcome) -> None:
    metadata: dict[str, object] = {
        "trigger": cycle.trigger.value,
        "outcome": cycle.outcome.value,
    }
    if cycle.seed is not None:
        metadata["seed_source_kind"] = cycle.seed.source_kind.value
        metadata["seed_source_id"] = str(cycle.seed.source_id)
        metadata["seed_outcome_summary"] = cycle.seed.outcome_summary

    record_audit_event(
        tenant_id=cycle.tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action=_AUDIT_ACTION,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(cycle.cycle_id),
        outcome=outcome,
        metadata=metadata,
    )


# --- Recurring/scheduled execution (infra.jobs) -----------------------------


async def _run_continuous_learning_cycle_job(payload: TenantJobPayload | None) -> None:
    """The registered job handler -- re-derives everything from
    `payload.tenant_id` at execution time; carries no candidate content,
    no evaluation result, no policy decision in the payload itself (Phase
    9.9's own Audit/Secrets requirements, generalized to job payloads:
    "no credentials in job payloads ... no unrestricted candidate
    payloads"). A transient failure (e.g. a database error) raises and is
    retried with backoff, then dead-lettered on exhaustion by
    `infra.jobs.register_job()`'s own wrapper -- this handler implements
    no retry logic itself."""
    if payload is None:
        raise ValueError(
            "_run_continuous_learning_cycle_job requires a TenantJobPayload, got None."
        )
    tenant_id = uuid.UUID(payload.tenant_id)
    run_continuous_learning_cycle(tenant_id, trigger=LoopTrigger.SCHEDULED)


CONTINUOUS_LOOP_JOB_FUNCTIONS: list[Function] = [register_job(_run_continuous_learning_cycle_job)]


async def trigger_continuous_learning_cycle(
    tenant_id: uuid.UUID, *, queue_name: str | None = None
) -> str:
    """Enqueue one scheduled cycle for `tenant_id`. Returns the arq job
    ID. `queue_name` is a thin passthrough to `infra.jobs.enqueue_job()`'s
    own parameter of the same name, exactly like
    `core.webhooks.trigger_event()`'s own precedent."""
    return await enqueue_job(
        _run_continuous_learning_cycle_job.__name__,
        TenantJobPayload(tenant_id=str(tenant_id)),
        queue_name=queue_name,
    )
