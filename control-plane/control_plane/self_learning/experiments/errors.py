"""Typed errors for `control_plane.self_learning.experiments`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.6)."""

from __future__ import annotations

import uuid


class InvalidCandidateSourceError(ValueError):
    """Raised when `create_experiment()` is given neither or both of
    `adaptation`/`system_learning_proposal` (exactly one is required --
    Phase 9.6's own Objective: "an authorized adaptation candidate (9.4)
    or system-learning proposal (9.5)"), or when the given candidate's own
    `tenant_id` does not match the experiment's `tenant_id`."""


class UnauthorizedExperimentEvidenceError(PermissionError):
    """Raised when an experiment's `LearningAuthorizationDecision` is not
    an ALLOW for the experimenting tenant, or when its evidence type is
    not a member of `control_plane.self_learning.models.VALID_EVIDENCE_TYPES`
    (Phase 9.2's gate, never bypassed -- Phase 9.6's own Data-Authorization
    Requirement: "reuses 9.2's gate for any data the experiment consumes")."""


class ExperimentNotFoundError(LookupError):
    def __init__(self, tenant_id: uuid.UUID, experiment_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.experiment_id = experiment_id
        super().__init__(f"Experiment {experiment_id} not found in tenant {tenant_id}.")


class ExperimentNotConfiguredError(ValueError):
    """Raised by `execute_experiment()` when the target row is not
    `ExperimentStatus.CONFIGURED` -- an experiment may be executed exactly
    once from that status."""

    def __init__(self, experiment_id: uuid.UUID, status: str) -> None:
        self.experiment_id = experiment_id
        self.status = status
        super().__init__(f"Experiment {experiment_id} is not configured (status={status!r}).")


class ExperimentNotRunningError(ValueError):
    """Raised by `record_experiment_result()` when the target row is not
    `ExperimentStatus.RUNNING` -- a result may be recorded only for a
    running experiment."""

    def __init__(self, experiment_id: uuid.UUID, status: str) -> None:
        self.experiment_id = experiment_id
        self.status = status
        super().__init__(f"Experiment {experiment_id} is not running (status={status!r}).")


class ExperimentResultMismatchError(ValueError):
    """docs/IMPLEMENTATION-ROADMAP.md Phase 9.6's own threat model:
    forged experiment identity/result tampering. Raised when a supplied
    `EvaluationComparison`'s `baseline_version`/`candidate_version` does
    not match the experiment's own recorded `baseline_version`/
    `candidate_version` -- an unrelated comparison can never be recorded
    as this experiment's result."""

    def __init__(self, experiment_id: uuid.UUID) -> None:
        self.experiment_id = experiment_id
        super().__init__(
            f"Experiment {experiment_id}: the supplied EvaluationComparison's "
            "baseline_version/candidate_version does not match this experiment's own."
        )


class ExperimentAlreadyTerminalError(ValueError):
    """Raised by `cancel_experiment()` when the target row is already in
    a terminal status (`completed`/`failed`/`cancelled`) -- a terminal
    experiment cannot be cancelled or otherwise transitioned again."""

    def __init__(self, experiment_id: uuid.UUID, status: str) -> None:
        self.experiment_id = experiment_id
        self.status = status
        super().__init__(
            f"Experiment {experiment_id} is already terminal (status={status!r}) and cannot "
            "be cancelled."
        )
