"""`control_plane.self_learning.continuous_loop` -- the Continuous
Improvement Loop (docs/IMPLEMENTATION-ROADMAP.md Phase 9.9): closes the
loop by turning an Outcome from Phase 9.8 (or Phase 9.4's own L1
adaptation lifecycle) into a new Observation, seeding the next cycle.

**Scope**: scheduling/orchestration of the already-built Phase 9.1-9.8
pipeline on a recurring basis -- explicitly not a new learning mechanism
(Phase 9.9's own Scope, verbatim). This package never proposes,
evaluates, gates, activates, or promotes anything itself; it only reads
already-terminal, already-authorized `Adaptation`/`Canary` rows and
packages the most recent one as a `LoopObservationSeed` for a separately
triggered, independently authorized next action. See `models.py`'s own
docstring for why `SystemLearningProposal` (Phase 9.5, never persisted)
cannot be rediscovered this way, and `service.py`'s own docstring for why
this design makes every duplicate-delivery/concurrency/idempotency
concern moot by construction (zero mutations, ever).

**Autonomy tier: unchanged, still capped at 2, never 3** -- this package
introduces no new autonomy-tier behavior at all; it never calls into
`control_plane.self_learning.policy_gate`, `control_plane.self_learning
.adaptive.service.activate_adaptation()`, or `control_plane
.self_learning.autonomous_improvement.service.start_canary()`/
`promote_canary()`. "Learning Level 3" (bounded autonomous improvement,
`docs/AI-CONTROL-PLANE.md` section 12) is an axis this package may
observe outcomes *from*; "Autonomy Tier 3" (section 5, "not enabled for
anything") is untouched, unchanged, and unreachable from any code path
here.

**Kill switch**: `core.feature_flags.evaluate_flag()`, the existing
feature-flag mechanism -- not a second disable mechanism
(docs/AI-CONTROL-PLANE.md section 9's own kill-switch design requirement,
reused rather than reinvented). Default-deny: a tenant with no flag
override never runs a cycle.

Owns:
- `LoopCycle` / `LoopObservationSeed` and their typed enums (`LoopTrigger`,
  `LoopCycleOutcome`, `LoopObservationSourceKind`) (`models.py`) -- all
  plain in-memory dataclasses, no database table, migration, or ORM model
  (mirrors `control_plane.self_learning.policy_gate`'s own no-persistence
  discipline, Phase 9.7);
- `run_continuous_learning_cycle()` -- the pure-read, audited cycle
  function;
- `trigger_continuous_learning_cycle()` / `CONTINUOUS_LOOP_JOB_FUNCTIONS` --
  the `infra.jobs`-backed recurring-execution entrypoint (`service.py`).

Does NOT own: candidate generation, evaluation, the policy gate, canary
execution, or promotion/rollback (Phases 9.3/9.4/9.6/9.7/9.8, consumed
here only by reading their own already-persisted, already-terminal
outcome rows); a new scheduler (recurring cadence is deployment
configuration invoking `trigger_continuous_learning_cycle()`
periodically, exactly like any other scheduled operation on this
platform -- `infra/jobs` itself is not modified); a new kill-switch
mechanism, Tool Registry tool, or secrets-consuming call site (none
required by this phase's own Files/Modules Affected).
"""

from control_plane.self_learning.continuous_loop.models import (
    VALID_LOOP_CYCLE_OUTCOMES,
    VALID_LOOP_OBSERVATION_SOURCE_KINDS,
    LoopCycle,
    LoopCycleOutcome,
    LoopObservationSeed,
    LoopObservationSourceKind,
    LoopTrigger,
)
from control_plane.self_learning.continuous_loop.service import (
    CONTINUOUS_LOOP_JOB_FUNCTIONS,
    run_continuous_learning_cycle,
    trigger_continuous_learning_cycle,
)

__all__ = [
    "LoopTrigger",
    "LoopCycleOutcome",
    "VALID_LOOP_CYCLE_OUTCOMES",
    "LoopObservationSourceKind",
    "VALID_LOOP_OBSERVATION_SOURCE_KINDS",
    "LoopObservationSeed",
    "LoopCycle",
    "run_continuous_learning_cycle",
    "trigger_continuous_learning_cycle",
    "CONTINUOUS_LOOP_JOB_FUNCTIONS",
]
