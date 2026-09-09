"""Typed shapes for the Continuous Improvement Loop
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.9).

**What "closing the loop" means here, concretely**: Phase 9.9's own
Objective is "an Outcome from 9.8 (or a Level 1/2 adaptation/proposal)
becomes a new Observation" -- its own Scope is explicit that this is
"scheduling/orchestration of the existing pipeline ... not a new
learning mechanism." This package therefore never generates a candidate,
never proposes an adaptation, never runs an experiment, and never
activates, promotes, or rolls anything back itself -- it only *finds* the
most recent terminal outcome from an already-completed 9.4/9.8 lineage
and packages it as a pointer (`LoopObservationSeed`) for whatever
already-authorized process (a human operator, or a future, separately
triggered call into 9.4/9.6/9.7/9.8) decides to act on it next. Because
this package performs zero mutations, none of the "duplicate autonomous
mutation" hazards Phase 9.9's own Idempotency/Concurrency concerns name
can occur here by construction -- running the same cycle twice produces
two identical, harmless read-only summaries, never two adaptations,
canaries, or promotions.

**Why `LoopObservationSeed.source_kind` never includes
`system_learning_proposal`**: `control_plane.self_learning.system_learning
.models.SystemLearningProposal` is, by that phase's own deliberate
design, never persisted (its module docstring: "every shape below is a
plain in-memory dataclass"). A recurring, scheduled job has nothing to
query for an L2 proposal days or hours after it was produced -- there is
no row anywhere to find. This is not a gap this package works around by
inventing a new persistence layer for L2 (that would be a new capability
class, exactly what Phase 9.9's own Non-Goals forbid); it is a structural
consequence of Phase 9.5's own no-persistence discipline, which this
package must not weaken. Only `Adaptation` (Phase 9.4) and `Canary`
(Phase 9.8) -- both real, persisted, RLS-protected tables -- can ever be
rediscovered this way.

**No `stage` field**: `LoopCycle` has no multi-step "current stage"
tracker, unlike `Experiment`/`Canary`. There is nothing to track a stage
*through* -- one cycle execution is a single, synchronous read-and-summarize
operation (check the kill switch, query for the most recent terminal
outcome, write one audit entry), never a multi-step state machine a
process could crash partway through and need to resume. `LoopCycleOutcome`
alone is a complete description of what happened.

No database table, migration, or ORM model is defined here -- mirrors
`control_plane.self_learning.policy_gate`'s own no-persistence discipline
(Phase 9.7): `LoopCycle` is summarized through exactly one `core.audit_log`
entry (`service.py`'s own docstring), never given a second, competing
source of truth.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime


class LoopTrigger(enum.StrEnum):
    """How a cycle execution was initiated -- an audited fact, never a
    claim of authority: a `SCHEDULED` trigger carries no more standing
    authority than a `MANUAL` one (Phase 9.9's own Security Requirement,
    generalized: "a scheduled job is not inherently trusted merely
    because the scheduler triggered it")."""

    SCHEDULED = "scheduled"
    MANUAL = "manual"


class LoopCycleOutcome(enum.StrEnum):
    """Every outcome `service.run_continuous_learning_cycle()` can
    produce -- exhaustive by construction, mirroring every other
    decision/comparison enum in this package family.

    `DISABLED` -- the tenant's continuous-loop kill switch
    (`service._KILL_SWITCH_FLAG_KEY`) evaluated to `False`; no query, no
    seed, no autonomous work of any kind was performed (Phase 9.9's own
    Rollback Strategy: "the loop itself can be paused/disabled").
    `NO_VIABLE_CANDIDATE` -- the kill switch is on, but this tenant has no
    terminal `Adaptation`/`Canary` outcome yet to seed a next cycle from --
    a safe no-op, never a forced/degraded promotion (Phase 9.9's own Tests
    bullet, verbatim).
    `COMPLETED` -- a real terminal outcome was found and packaged as a
    `LoopObservationSeed`.
    """

    DISABLED = "disabled"
    NO_VIABLE_CANDIDATE = "no_viable_candidate"
    COMPLETED = "completed"


VALID_LOOP_CYCLE_OUTCOMES: frozenset[str] = frozenset(o.value for o in LoopCycleOutcome)


class LoopObservationSourceKind(enum.StrEnum):
    """The only two things a `LoopObservationSeed` may ever point at --
    see module docstring for why `system_learning_proposal` has no
    member here."""

    ADAPTATION = "adaptation"
    CANARY = "canary"


VALID_LOOP_OBSERVATION_SOURCE_KINDS: frozenset[str] = frozenset(
    k.value for k in LoopObservationSourceKind
)


@dataclass(frozen=True)
class LoopObservationSeed:
    """A pointer to the most recent terminal outcome this tenant
    produced -- never raw candidate content, never a live handle to
    mutate the referenced row (same "provenance column, not a live
    handle" discipline `control_plane.self_learning.experiments.models
    .Experiment`/`control_plane.self_learning.autonomous_improvement
    .models.Canary` already establish for their own provenance
    pointers). `outcome_summary` is a short, closed-vocabulary identifier
    (e.g. `"promoted"`, `"rolled_back"`, `"active"`) -- never a free-text
    description of *why*, which would risk carrying sensitive proposed
    content into an audit-adjacent structure."""

    source_kind: LoopObservationSourceKind
    source_id: uuid.UUID
    tenant_id: uuid.UUID
    outcome_summary: str


@dataclass(frozen=True)
class LoopCycle:
    """One cycle execution's complete, self-contained summary. Frozen and
    fully constructed by `service.run_continuous_learning_cycle()` in a
    single call -- there is no partial/in-progress `LoopCycle` a caller
    could observe or mutate mid-execution."""

    tenant_id: uuid.UUID
    trigger: LoopTrigger
    outcome: LoopCycleOutcome
    started_at: datetime
    ended_at: datetime
    seed: LoopObservationSeed | None = None
    failure_reason: str | None = None
    cycle_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        if self.outcome is LoopCycleOutcome.COMPLETED and self.seed is None:
            raise AssertionError("A COMPLETED cycle must carry a LoopObservationSeed.")
        if self.outcome is not LoopCycleOutcome.COMPLETED and self.seed is not None:
            raise AssertionError("Only a COMPLETED cycle may carry a LoopObservationSeed.")
        if self.seed is not None and self.seed.tenant_id != self.tenant_id:
            raise AssertionError(
                "A cycle's seed must belong to the same tenant as the cycle itself."
            )


__all__ = [
    "LoopTrigger",
    "LoopCycleOutcome",
    "VALID_LOOP_CYCLE_OUTCOMES",
    "LoopObservationSourceKind",
    "VALID_LOOP_OBSERVATION_SOURCE_KINDS",
    "LoopObservationSeed",
    "LoopCycle",
]
