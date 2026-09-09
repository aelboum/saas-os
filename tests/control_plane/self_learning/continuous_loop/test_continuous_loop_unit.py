"""Unit tests for `control_plane.self_learning.continuous_loop.models`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.9). No database required -- pure
structural invariants only. `service.run_continuous_learning_cycle()`
itself always reads through `core.feature_flags.evaluate_flag()` and
`infra.db.tenant_session_scope()`, so its full behavior (kill switch,
seed selection, audit) is covered by
`test_continuous_loop_integration.py` (marked `integration`).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from control_plane.self_learning.continuous_loop.models import (
    VALID_LOOP_CYCLE_OUTCOMES,
    VALID_LOOP_OBSERVATION_SOURCE_KINDS,
    LoopCycle,
    LoopCycleOutcome,
    LoopObservationSeed,
    LoopObservationSourceKind,
    LoopTrigger,
)

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()
NOW = datetime.now(UTC)


def test_valid_outcomes_and_source_kinds_are_closed() -> None:
    assert VALID_LOOP_CYCLE_OUTCOMES == {"disabled", "no_viable_candidate", "completed"}
    assert VALID_LOOP_OBSERVATION_SOURCE_KINDS == {"adaptation", "canary"}


def test_system_learning_proposal_is_not_a_constructible_source_kind() -> None:
    """Phase 9.5's own `SystemLearningProposal` is never persisted, so it
    can never be rediscovered by a recurring job -- structurally absent
    from the allowlist, not merely rejected at runtime."""
    with pytest.raises(ValueError):
        LoopObservationSourceKind("system_learning_proposal")


def test_completed_cycle_without_seed_is_rejected() -> None:
    with pytest.raises(AssertionError):
        LoopCycle(
            tenant_id=TENANT_A,
            trigger=LoopTrigger.MANUAL,
            outcome=LoopCycleOutcome.COMPLETED,
            started_at=NOW,
            ended_at=NOW,
            seed=None,
        )


def test_non_completed_cycle_with_seed_is_rejected() -> None:
    seed = LoopObservationSeed(
        source_kind=LoopObservationSourceKind.ADAPTATION,
        source_id=uuid.uuid4(),
        tenant_id=TENANT_A,
        outcome_summary="active",
    )
    with pytest.raises(AssertionError):
        LoopCycle(
            tenant_id=TENANT_A,
            trigger=LoopTrigger.MANUAL,
            outcome=LoopCycleOutcome.NO_VIABLE_CANDIDATE,
            started_at=NOW,
            ended_at=NOW,
            seed=seed,
        )


def test_cross_tenant_seed_on_a_cycle_is_rejected() -> None:
    """A confused-deputy-shaped construction: a cycle for Tenant A cannot
    carry a seed pointing at Tenant B's own outcome."""
    seed = LoopObservationSeed(
        source_kind=LoopObservationSourceKind.CANARY,
        source_id=uuid.uuid4(),
        tenant_id=TENANT_B,
        outcome_summary="promoted",
    )
    with pytest.raises(AssertionError):
        LoopCycle(
            tenant_id=TENANT_A,
            trigger=LoopTrigger.SCHEDULED,
            outcome=LoopCycleOutcome.COMPLETED,
            started_at=NOW,
            ended_at=NOW,
            seed=seed,
        )


def test_valid_completed_cycle_constructs() -> None:
    seed = LoopObservationSeed(
        source_kind=LoopObservationSourceKind.ADAPTATION,
        source_id=uuid.uuid4(),
        tenant_id=TENANT_A,
        outcome_summary="active",
    )
    cycle = LoopCycle(
        tenant_id=TENANT_A,
        trigger=LoopTrigger.MANUAL,
        outcome=LoopCycleOutcome.COMPLETED,
        started_at=NOW,
        ended_at=NOW,
        seed=seed,
    )
    assert cycle.seed is seed
    assert cycle.cycle_id is not None


def test_model_claim_has_no_authority_field() -> None:
    """`LoopCycle`/`LoopObservationSeed` have no `authorized=`/
    `approved=`/`autonomy_tier=` field a caller could smuggle a claim
    of authority into -- structural, not a runtime check."""
    with pytest.raises(TypeError):
        LoopCycle(  # type: ignore[call-arg]
            tenant_id=TENANT_A,
            trigger=LoopTrigger.MANUAL,
            outcome=LoopCycleOutcome.NO_VIABLE_CANDIDATE,
            started_at=NOW,
            ended_at=NOW,
            autonomy_tier=3,  # type: ignore[call-arg]
        )
