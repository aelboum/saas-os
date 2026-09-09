"""L2/L1 Experimentation: the `Experiment` entity and its typed
allowlists (docs/IMPLEMENTATION-ROADMAP.md Phase 9.6).

`Experiment` runs an already-authorized adaptation candidate (Phase 9.4)
or system-learning proposal (Phase 9.5) as an **isolated experiment,
evaluated (Phase 9.3) against a baseline, with zero production-binding
effect** (Phase 9.6's own Objective, verbatim). This module never
duplicates `Adaptation`, `SystemLearningProposal`, `Benchmark`,
`EvaluationMetrics`, or `EvaluationComparison` -- it only stores
provenance pointers (`candidate_source_kind`/`candidate_source_id`,
`evaluation_comparison_id`) to those already-authoritative shapes, the
same discipline `control_plane.self_learning.adaptive.models.Adaptation`
already established for `learning_authorization_decision_id`/
`evaluation_comparison_id` (Phase 9.4).

`ExperimentCandidateSourceKind` is the **closed, typed allowlist** of
what an experiment may reference as its candidate -- exactly the two
sources Phase 9.6's own Objective names ("an authorized adaptation
candidate (9.4) or system-learning proposal (9.5)"), nothing else. There
is no member for a raw/unauthorized model output, an arbitrary
configuration blob, or a production system directly -- an experiment
that is not "about" an already-authorized 9.4/9.5 candidate is not
merely rejected by a runtime check, it is *impossible to construct*.

`ExperimentStatus` has no member for `promoted`/`deployed`/
`production_active`/`canary_promoted` -- Phase 9.6's own Non-Goals
("no canary deployment, no autonomous promotion, no production traffic
exposure") and Scope ("no canary, no autonomous deployment (9.8)") made
structural: an experiment can reach `completed`/`failed`/`cancelled`,
never anything resembling activation.

`Experiment` is tenant-owned and RLS-protected (`self_learning` schema,
the same namespace `Adaptation` already uses -- Phase 9.6's own
Tenant-Isolation Requirement: "experiment records/results are
RLS-protected exactly like every other tenant-owned table"). Rows are
mutable state (`status` transitions `configured` -> `running` ->
`completed`/`failed`, or `configured`/`running` -> `cancelled`), not an
immutable audit record -- `core.audit_log` (Phase 3.4) remains the
platform's one append-only security/audit trail; `service.py`'s own
functions *additionally* write to it for every creation/execution/
result/cancellation, exactly as `control_plane.self_learning.adaptive
.service` already does for `Adaptation`.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from infra.db import Base as _Base
from infra.db import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Mapped,
    String,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class ExperimentCandidateSourceKind(enum.StrEnum):
    """The only two things an experiment may ever reference as its
    candidate -- Phase 9.6's own Objective, verbatim: "an authorized
    adaptation candidate (9.4) or system-learning proposal (9.5)". No
    other member exists -- an experiment about anything else is
    structurally impossible to construct."""

    ADAPTATION = "adaptation"
    SYSTEM_LEARNING_PROPOSAL = "system_learning_proposal"


VALID_CANDIDATE_SOURCE_KINDS: frozenset[str] = frozenset(
    k.value for k in ExperimentCandidateSourceKind
)


class ExperimentStatus(enum.StrEnum):
    """`configured` (freshly created, fully specified -- there is no
    partial/draft state since `service.create_experiment()` always
    receives a complete candidate/baseline/evidence specification in one
    call) -> `running` (via `service.execute_experiment()`) -> `completed`
    (a conclusive -- PASS, FAIL, or REGRESSION -- Phase 9.3
    `EvaluationComparison` was recorded) or `failed` (the evaluation
    itself could not be validly performed -- an `INVALID` comparison,
    Phase 9.6's own Tests requirement: "a failed/inconclusive experiment
    never silently proceeds to promotion"), or `cancelled` from
    `configured`/`running` (Phase 9.6's own Rollback Strategy: "rollback
    means marking the experiment record terminated"). No member here
    resembles activation/deployment/promotion -- see module docstring."""

    CONFIGURED = "configured"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


VALID_EXPERIMENT_STATUSES: frozenset[str] = frozenset(s.value for s in ExperimentStatus)

TERMINAL_EXPERIMENT_STATUSES: frozenset[str] = frozenset(
    {
        ExperimentStatus.COMPLETED.value,
        ExperimentStatus.FAILED.value,
        ExperimentStatus.CANCELLED.value,
    }
)

Base = _Base


class Experiment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "experiments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('configured', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_experiments_status",
        ),
        CheckConstraint(
            "candidate_source_kind IN ('adaptation', 'system_learning_proposal')",
            name="ck_experiments_candidate_source_kind",
        ),
        CheckConstraint(
            "evidence_type IN ('user_feedback', 'operator_feedback', 'tool_output', "
            "'external_content', 'model_generated_content', 'imported_learning_material', "
            "'evaluation_input')",
            name="ck_experiments_evidence_type",
        ),
        CheckConstraint(
            "evaluation_outcome IS NULL OR evaluation_outcome IN "
            "('pass', 'fail', 'regression', 'invalid')",
            name="ck_experiments_evaluation_outcome",
        ),
        Index(
            "ix_experiments_tenant_candidate",
            "tenant_id",
            "candidate_source_kind",
            "candidate_source_id",
        ),
        Index("ix_experiments_tenant_status", "tenant_id", "status"),
        {"schema": "self_learning"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)

    candidate_source_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    candidate_source_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    candidate_version: Mapped[str] = mapped_column(String(100), nullable=False)
    baseline_version: Mapped[str] = mapped_column(String(100), nullable=False)

    # Provenance only -- neither a `LearningAuthorizationDecision` (Phase
    # 9.2) nor an `EvaluationComparison` (Phase 9.3) is itself persisted;
    # these columns record the *fact* that a specific decision/comparison
    # authorized/evaluated this row, never a live handle to mutate either
    # (same discipline as `control_plane.self_learning.adaptive.models
    # .Adaptation`).
    learning_authorization_decision_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(30), nullable=False)
    evidence_source_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    evaluation_comparison_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    evaluation_outcome: Mapped[str | None] = mapped_column(String(20), nullable=True)

    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.users.id"), nullable=False
    )
    executed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    completed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    cancelled_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )

    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancellation_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    @property
    def is_reversible(self) -> bool:
        """An experiment never mutates production state (Phase 9.6's own
        Rollback Strategy: "an experiment has no production effect by
        construction"). Not a constructor field -- a computed property
        (mirroring `control_plane.self_learning.system_learning.models
        .SystemLearningProposal.is_reversible`, Phase 9.5) means there is
        no argument through which a caller could ever set it to `False`."""
        return True
