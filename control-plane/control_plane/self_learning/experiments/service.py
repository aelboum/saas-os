"""Experimentation: configure -> execute -> record result, or cancel
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.6).

Four operations, mirroring `control_plane.self_learning.adaptive.service`'s
own "propose -> evaluate -> activate -> rollback" discipline (Phase 9.4),
adapted to Phase 9.6's own three named audit actions plus its own
Rollback Strategy:

- `create_experiment()` -- creates a `CONFIGURED` row referencing exactly
  one already-authorized candidate: an `Adaptation` (Phase 9.4) or a
  `SystemLearningProposal` (Phase 9.5), never a raw/unauthorized value
  (Phase 9.6's own Objective, verbatim: "an authorized adaptation
  candidate (9.4) or system-learning proposal (9.5)"). Requires an
  already-ALLOW `LearningAuthorizationDecision` for the same tenant
  (Phase 9.2's gate, never bypassed -- Phase 9.6's own Data-Authorization
  Requirement). Audited `learning.experiment_created`.
- `execute_experiment()` -- `CONFIGURED` -> `RUNNING`. Audited
  `learning.experiment_executed`. Has no evaluative effect itself -- it
  only marks that execution has begun; the actual baseline-vs-candidate
  comparison is Phase 9.3's own `evaluate_candidate()`/`run_evaluation()`,
  never re-implemented here (this task's own instruction: "reuse the
  existing Phase 9.3 Evaluation foundation... do not create a second
  evaluation system").
- `record_experiment_result()` -- `RUNNING` -> `COMPLETED` (a conclusive
  PASS/FAIL/REGRESSION `EvaluationComparison`) or `FAILED` (an `INVALID`
  comparison -- "a failed/inconclusive experiment never silently proceeds
  to promotion," Phase 9.6's own Tests requirement). Rejects a comparison
  whose own `baseline_version`/`candidate_version` does not match this
  experiment's recorded values (`ExperimentResultMismatchError` --
  defends against forged/mismatched result recording). Audited
  `learning.experiment_result_recorded`.
- `cancel_experiment()` -- `CONFIGURED`/`RUNNING` -> `CANCELLED`. This
  *is* Phase 9.6's own Rollback Strategy: "an experiment has no
  production effect by construction; 'rollback' means marking the
  experiment record terminated." Audited `learning.experiment_cancelled`.

None of these four functions is a Tool Registry tool, and none is gated
behind `control_plane.approvals` -- unlike `activate_adaptation()`/
`rollback_adaptation()` (Phase 9.4), which are Tier 1 because they *do*
have a production effect, every operation here is Tier 0 by construction:
an experiment can never reach a state that activates, deploys, or
promotes anything (`Experiment.is_reversible` is always `True`; no status
in `ExperimentStatus` resembles activation -- see `models.py`).

This module never mutates the `Adaptation` or `SystemLearningProposal` it
references -- it only reads their `tenant_id`/`id`/`version` fields to
populate its own row's provenance columns (this task's own instruction:
"proposal -> experiment does NOT imply experiment -> activation... keep
the experiment read/evaluate-only").

Every one of the four roadmap-named/task-required audit events
(`learning.experiment_created` / `.executed` / `.result_recorded` /
`.cancelled`) is written through `core.audit_log`'s existing interface --
this module has no second audit mechanism, and no path that writes to
`core.*`, mutates RBAC, touches `infra.secrets`, or deploys anything --
the only persistence this module ever writes to is its own
`self_learning.experiments` table.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from control_plane.self_learning.adaptive.models import Adaptation
from control_plane.self_learning.evaluation.models import EvaluationComparison, EvaluationOutcome
from control_plane.self_learning.experiments.errors import (
    ExperimentAlreadyTerminalError,
    ExperimentNotConfiguredError,
    ExperimentNotFoundError,
    ExperimentNotRunningError,
    ExperimentResultMismatchError,
    InvalidCandidateSourceError,
    UnauthorizedExperimentEvidenceError,
)
from control_plane.self_learning.experiments.models import (
    TERMINAL_EXPERIMENT_STATUSES,
    Experiment,
    ExperimentCandidateSourceKind,
    ExperimentStatus,
)
from control_plane.self_learning.models import (
    VALID_EVIDENCE_TYPES,
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)
from control_plane.self_learning.system_learning.models import SystemLearningProposal
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from infra.db import tenant_session_scope

_AUDIT_RESOURCE_TYPE = "self_learning_experiment"


def _audit(
    *,
    tenant_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    action: str,
    experiment_id: uuid.UUID,
    metadata: dict[str, object],
) -> None:
    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(experiment_id),
        outcome=AuditOutcome.SUCCESS,
        metadata=metadata,
    )


def create_experiment(
    *,
    tenant_id: uuid.UUID,
    baseline_version: str,
    learning_authorization_decision: LearningAuthorizationDecision,
    evidence_type: str,
    evidence_source_reference: str,
    created_by_user_id: uuid.UUID,
    adaptation: Adaptation | None = None,
    system_learning_proposal: SystemLearningProposal | None = None,
) -> Experiment:
    """Create one `CONFIGURED` experiment referencing exactly one
    already-authorized candidate. Raises rather than silently downgrading
    evidence or candidate source -- default deny, matching every other
    gate this platform ships."""
    if (adaptation is None) == (system_learning_proposal is None):
        raise InvalidCandidateSourceError(
            "create_experiment() requires exactly one of adaptation= or system_learning_proposal=."
        )

    if adaptation is not None:
        if adaptation.tenant_id != tenant_id:
            raise InvalidCandidateSourceError(
                f"Adaptation {adaptation.id} belongs to tenant {adaptation.tenant_id}, not "
                f"the experimenting tenant {tenant_id}."
            )
        candidate_source_kind = ExperimentCandidateSourceKind.ADAPTATION
        candidate_source_id = adaptation.id
        candidate_version = str(adaptation.version)
    else:
        assert system_learning_proposal is not None  # exactly-one check above
        if system_learning_proposal.tenant_id != tenant_id:
            raise InvalidCandidateSourceError(
                f"SystemLearningProposal {system_learning_proposal.proposal_id} belongs to "
                f"tenant {system_learning_proposal.tenant_id}, not the experimenting tenant "
                f"{tenant_id}."
            )
        candidate_source_kind = ExperimentCandidateSourceKind.SYSTEM_LEARNING_PROPOSAL
        candidate_source_id = system_learning_proposal.proposal_id
        candidate_version = str(system_learning_proposal.version)

    if (
        learning_authorization_decision.outcome is not LearningAuthorizationOutcome.ALLOW
        or learning_authorization_decision.tenant_id != tenant_id
    ):
        raise UnauthorizedExperimentEvidenceError(
            "Learning Authorization for this tenant must be ALLOW before configuring an experiment."
        )

    if (
        not evidence_type
        or evidence_type not in VALID_EVIDENCE_TYPES
        or not evidence_source_reference
    ):
        raise UnauthorizedExperimentEvidenceError(
            f"{evidence_type!r} is not permitted learning evidence "
            "(docs/IMPLEMENTATION-ROADMAP.md Phase 9.2's VALID_EVIDENCE_TYPES)."
        )

    with tenant_session_scope(tenant_id) as session:
        experiment = Experiment(
            tenant_id=tenant_id,
            status=ExperimentStatus.CONFIGURED.value,
            candidate_source_kind=candidate_source_kind.value,
            candidate_source_id=candidate_source_id,
            candidate_version=candidate_version,
            baseline_version=baseline_version,
            learning_authorization_decision_id=learning_authorization_decision.decision_id,
            evidence_type=evidence_type,
            evidence_source_reference=evidence_source_reference,
            created_by_user_id=created_by_user_id,
        )
        session.add(experiment)
        session.flush()
        session.refresh(experiment)
        session.expunge(experiment)

    _audit(
        tenant_id=tenant_id,
        actor_user_id=created_by_user_id,
        action="learning.experiment_created",
        experiment_id=experiment.id,
        metadata={
            "candidate_source_kind": candidate_source_kind.value,
            "candidate_source_id": str(candidate_source_id),
            "candidate_version": candidate_version,
            "baseline_version": baseline_version,
            "evidence_type": evidence_type,
        },
    )
    return experiment


def get_experiment(tenant_id: uuid.UUID, experiment_id: uuid.UUID) -> Experiment:
    with tenant_session_scope(tenant_id) as session:
        experiment = session.get(Experiment, experiment_id)
        if experiment is None or experiment.tenant_id != tenant_id:
            raise ExperimentNotFoundError(tenant_id, experiment_id)
        session.expunge(experiment)
        return experiment


def execute_experiment(
    tenant_id: uuid.UUID, experiment_id: uuid.UUID, *, executed_by_user_id: uuid.UUID
) -> Experiment:
    """`CONFIGURED` -> `RUNNING`. Marks that execution has begun; the
    actual comparison happens via Phase 9.3's own evaluator, then is
    recorded through `record_experiment_result()`."""
    with tenant_session_scope(tenant_id) as session:
        row = session.get(Experiment, experiment_id)
        if row is None or row.tenant_id != tenant_id:
            raise ExperimentNotFoundError(tenant_id, experiment_id)
        if row.status != ExperimentStatus.CONFIGURED.value:
            raise ExperimentNotConfiguredError(experiment_id, row.status)

        row.status = ExperimentStatus.RUNNING.value
        row.executed_by_user_id = executed_by_user_id
        row.executed_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        experiment = row

    _audit(
        tenant_id=tenant_id,
        actor_user_id=executed_by_user_id,
        action="learning.experiment_executed",
        experiment_id=experiment.id,
        metadata={
            "candidate_source_kind": experiment.candidate_source_kind,
            "candidate_version": experiment.candidate_version,
            "baseline_version": experiment.baseline_version,
        },
    )
    return experiment


def record_experiment_result(
    tenant_id: uuid.UUID,
    experiment_id: uuid.UUID,
    comparison: EvaluationComparison,
    *,
    recorded_by_user_id: uuid.UUID,
) -> Experiment:
    """`RUNNING` -> `COMPLETED` (a conclusive PASS/FAIL/REGRESSION) or
    `FAILED` (an `INVALID` comparison -- never silently treated as a
    conclusive result). Rejects a `comparison` whose own
    `baseline_version`/`candidate_version` does not match this
    experiment's recorded values (`ExperimentResultMismatchError`)."""
    with tenant_session_scope(tenant_id) as session:
        row = session.get(Experiment, experiment_id)
        if row is None or row.tenant_id != tenant_id:
            raise ExperimentNotFoundError(tenant_id, experiment_id)
        if row.status != ExperimentStatus.RUNNING.value:
            raise ExperimentNotRunningError(experiment_id, row.status)
        if (
            comparison.baseline_version != row.baseline_version
            or comparison.candidate_version != row.candidate_version
        ):
            raise ExperimentResultMismatchError(experiment_id)

        new_status = (
            ExperimentStatus.FAILED
            if comparison.outcome is EvaluationOutcome.INVALID
            else ExperimentStatus.COMPLETED
        )
        row.status = new_status.value
        row.evaluation_comparison_id = comparison.decision_id
        row.evaluation_outcome = comparison.outcome.value
        row.completed_by_user_id = recorded_by_user_id
        row.completed_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        experiment = row

    metadata: dict[str, object] = {
        "evaluation_outcome": comparison.outcome.value,
        "evaluation_comparison_id": str(comparison.decision_id),
        "new_status": new_status.value,
    }
    if comparison.invalid_reason is not None:
        metadata["invalid_reason"] = comparison.invalid_reason.value
    if comparison.failed_metrics:
        metadata["failed_metric_count"] = len(comparison.failed_metrics)
    if comparison.regressed_metrics:
        metadata["regressed_metric_count"] = len(comparison.regressed_metrics)

    _audit(
        tenant_id=tenant_id,
        actor_user_id=recorded_by_user_id,
        action="learning.experiment_result_recorded",
        experiment_id=experiment.id,
        metadata=metadata,
    )
    return experiment


def cancel_experiment(
    tenant_id: uuid.UUID,
    experiment_id: uuid.UUID,
    *,
    cancelled_by_user_id: uuid.UUID,
    reason: str | None = None,
) -> Experiment:
    """`CONFIGURED`/`RUNNING` -> `CANCELLED` -- Phase 9.6's own Rollback
    Strategy, verbatim: "an experiment has no production effect by
    construction; 'rollback' means marking the experiment record
    terminated." A terminal experiment cannot be cancelled again."""
    with tenant_session_scope(tenant_id) as session:
        row = session.get(Experiment, experiment_id)
        if row is None or row.tenant_id != tenant_id:
            raise ExperimentNotFoundError(tenant_id, experiment_id)
        if row.status in TERMINAL_EXPERIMENT_STATUSES:
            raise ExperimentAlreadyTerminalError(experiment_id, row.status)

        previous_status = row.status
        row.status = ExperimentStatus.CANCELLED.value
        row.cancelled_by_user_id = cancelled_by_user_id
        row.cancelled_at = datetime.now(UTC)
        row.cancellation_reason = reason
        session.flush()
        session.refresh(row)
        session.expunge(row)
        experiment = row

    _audit(
        tenant_id=tenant_id,
        actor_user_id=cancelled_by_user_id,
        action="learning.experiment_cancelled",
        experiment_id=experiment.id,
        metadata={
            "previous_status": previous_status,
            "new_status": ExperimentStatus.CANCELLED.value,
        },
    )
    return experiment
