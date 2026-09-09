"""Typed errors for `control_plane.self_learning.autonomous_improvement`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.8)."""

from __future__ import annotations

import uuid


class InvalidCanaryCandidateError(ValueError):
    """Raised by `create_canary()` when the supplied `Experiment`/
    `Adaptation` pair does not name one coherent, already-authorized
    candidate: a tenant mismatch between the canary/experiment/adaptation,
    an `Experiment.candidate_source_id` that does not name the given
    `Adaptation`, or a `candidate_source_kind` other than `ADAPTATION`
    (Phase 9.5's own binding Non-Goal -- see `models.py`'s own
    docstring)."""


class ExperimentNotEvaluatedForCanaryError(PermissionError):
    """Raised when the supplied `Experiment` is not `COMPLETED` with a
    `PASS` evaluation outcome -- Phase 9.8's own Tests bullet, made
    non-vacuous: "a deliberately-failed regression suite is proven to
    block promotion." A `REGRESSION`/`FAIL`/`INVALID` outcome, or an
    experiment that never reached `COMPLETED`, refuses canary creation
    entirely."""


class AdaptationNotCandidateForCanaryError(PermissionError):
    """Raised when the supplied `Adaptation` is not itself still
    `CANDIDATE` with a `PASS` evaluation outcome -- defends against
    creating a canary for an adaptation that has already been activated,
    superseded, or rolled back outside this canary's own lifecycle."""


class UnauthorizedCanaryPolicyDecisionError(PermissionError):
    """Raised when the supplied `PolicyGateDecision` is not an ALLOW, is
    not for the canary's own tenant, is not for the
    `RequestedAction.ACTIVATE_ADAPTATION` action, or does not carry
    `requested_autonomy_tier == 2` -- Phase 9.8's own Non-Goal: "canary +
    monitoring + promote/rollback is tier 2 at most" -- tier 0, 1, and 3
    are all refused here, tier 3 redundantly (the gate itself,
    `control_plane.self_learning.policy_gate`, already refuses tier 3
    unconditionally; this is defense in depth against a forged/stale
    `PolicyGateDecision` object)."""


class CanaryNotFoundError(LookupError):
    def __init__(self, tenant_id: uuid.UUID, canary_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.canary_id = canary_id
        super().__init__(f"Canary {canary_id} not found in tenant {tenant_id}.")


class CanaryNotConfiguredError(ValueError):
    def __init__(self, canary_id: uuid.UUID, status: str) -> None:
        self.canary_id = canary_id
        self.status = status
        super().__init__(f"Canary {canary_id} is not configured (status={status!r}).")


class CanaryNotRunningError(ValueError):
    def __init__(self, canary_id: uuid.UUID, status: str) -> None:
        self.canary_id = canary_id
        self.status = status
        super().__init__(f"Canary {canary_id} is not running (status={status!r}).")


class CanaryNotSucceededError(ValueError):
    def __init__(self, canary_id: uuid.UUID, status: str) -> None:
        self.canary_id = canary_id
        self.status = status
        super().__init__(f"Canary {canary_id} has not succeeded (status={status!r}).")


class CanaryAlreadyTerminalError(ValueError):
    def __init__(self, canary_id: uuid.UUID, status: str) -> None:
        self.canary_id = canary_id
        self.status = status
        super().__init__(f"Canary {canary_id} is already terminal (status={status!r}).")


class CanaryRollbackFailedError(RuntimeError):
    """Raised after a rollback attempt's own underlying
    `rollback_adaptation()` call itself failed (e.g. no previous version
    to revert to). The canary is left in the real, audited
    `CanaryStatus.ROLLBACK_FAILED` terminal state before this is raised --
    docs/IMPLEMENTATION-ROADMAP.md Phase 9.8's own Rollback Strategy: "a
    *failed* rollback itself produces an audit/operational event, never a
    silent failure." Never caught and discarded by this package -- a
    caller must observe it."""

    def __init__(self, canary_id: uuid.UUID, cause: Exception) -> None:
        self.canary_id = canary_id
        self.cause = cause
        super().__init__(
            f"Canary {canary_id}: automatic rollback failed ({type(cause).__name__}: {cause})."
        )
