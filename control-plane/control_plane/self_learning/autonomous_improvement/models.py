"""Typed shapes for L3 Autonomous Improvement's Canary entity
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.8).

**What a "canary" is, concretely, on this platform**: `Adaptation`
(Phase 9.4) is already tenant-scoped -- one row per tenant per
`(surface, lineage_key)` -- so "a scoped, monitored, reversible partial
rollout" (Phase 9.8's own Scope, verbatim) is realized here as *exactly
one tenant's* `Adaptation` row being activated, monitored, and either
concluded (`PROMOTED`) or automatically reverted (`ROLLED_BACK`) --
never a platform-wide or multi-tenant fan-out, which no phase through 9.8
implements a mechanism for. This is the literal, structural enforcement
of this phase's own Non-Goal: "no cross-tenant autonomous action without
explicit separate authorization" -- there is no cross-tenant *path* here
at all, not merely a guarded one. `Canary.tenant_id` is a real, FK'd,
RLS-scoped column, never a set of tenants.

**Reuse, not a second taxonomy**: `monitoring_rules` is a plain
`control_plane.self_learning.evaluation.models.EvaluationRules` (the same
typed `MetricThreshold`/`MetricDirection` shapes Phase 9.3 already
defines) -- this module invents no parallel metric vocabulary
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.8's own instruction, generalized
from Phase 9.3's "the metric names mirror ... verbatim ... not a new
taxonomy"). A canary observation is a plain
`control_plane.self_learning.evaluation.models.EvaluationMetrics` snapshot,
checked against `monitoring_rules`' absolute bars only -- there is no live
baseline during monitoring to regress against, so `maximum_regression`
thresholds are never evaluated here (`service.py`'s own docstring).

**Candidate source is structurally restricted to `Adaptation`**: Phase
9.5's own binding Non-Goal is "no automatic application of a
[`SystemLearningProposal`] to production ... output is a proposal, never
an arbitrary production modification" -- a platform-wide invariant no
later phase may loosen. `service.create_canary()` therefore refuses any
`Experiment` whose `candidate_source_kind` is not
`ExperimentCandidateSourceKind.ADAPTATION`; there is no code path here
that ever activates, mutates, or otherwise "promotes" a
`SystemLearningProposal`.

**Provenance, never a live handle**: `experiment_id`/`adaptation_id` are
real foreign keys (a canary always names exactly one already-terminal
`Experiment` and its own already-`CANDIDATE` `Adaptation`);
`policy_gate_decision_id` is a plain UUID pointer, mirroring
`self_learning.experiments`' and `self_learning.adaptations`' own
"provenance column, never a live handle to mutate the referenced
decision" discipline (`PolicyGateDecision` itself is never persisted --
`control_plane.self_learning.policy_gate.models`'s own no-persistence
discipline, Phase 9.7). `candidate_version`/`baseline_version` are copied
at canary-creation time -- this phase's own Promotion requirement:
"promotion must preserve candidate identity, baseline identity ...
experiment provenance, policy-gate decision" -- so a later mutation of
the source `Experiment`/`Adaptation` row can never retroactively change
what a already-created `Canary` claims it promoted.

`CanaryStatus` has no member resembling a platform-wide or multi-tenant
state, and no member an agent could reach without going through
`service.py`'s own gate checks -- see that module's docstring for the
full lifecycle and why `ROLLBACK_FAILED` exists as a real, audited,
terminal state rather than a silently-swallowed exception
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.8's own Rollback Strategy: "a
*failed* rollback itself produces an audit/operational event, never a
silent failure").

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from infra.db import (
    JSON,
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
from infra.db import Base as _Base


class CanaryStatus(enum.StrEnum):
    """`configured` (created, not yet started) -> `running` (the
    underlying `Adaptation` has been activated for this canary's own
    tenant via `service.start_canary()`, monitoring window open) ->
    `succeeded` (the monitoring window concluded with no threshold
    violation, via `service.conclude_canary_monitoring()`) -> `promoted`
    (the terminal, confirmed-good state, via `service.promote_canary()`)
    or `rolled_back` (from `running`/`succeeded`, either automatically --
    `service.record_canary_observation()` detecting a threshold violation
    -- or explicitly via `service.rollback_canary()`) or `rollback_failed`
    (a `rolled_back` attempt whose own underlying `rollback_adaptation()`
    call itself raised -- a real, audited, terminal failure state, never
    a silent exception swallow) or `cancelled` (from `configured`/
    `running`, mirroring `Experiment.cancel_experiment()`'s own
    Rollback-Strategy discipline, Phase 9.6)."""

    CONFIGURED = "configured"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    CANCELLED = "cancelled"


VALID_CANARY_STATUSES: frozenset[str] = frozenset(s.value for s in CanaryStatus)

TERMINAL_CANARY_STATUSES: frozenset[str] = frozenset(
    {
        CanaryStatus.PROMOTED.value,
        CanaryStatus.ROLLED_BACK.value,
        CanaryStatus.ROLLBACK_FAILED.value,
        CanaryStatus.CANCELLED.value,
    }
)

Base = _Base


class Canary(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "canaries"
    __table_args__ = (
        CheckConstraint(
            "status IN ('configured', 'running', 'succeeded', 'promoted', "
            "'rolled_back', 'rollback_failed', 'cancelled')",
            name="ck_canaries_status",
        ),
        Index("ix_canaries_tenant_status", "tenant_id", "status"),
        Index("ix_canaries_tenant_experiment", "tenant_id", "experiment_id"),
        {"schema": "self_learning"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)

    experiment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("self_learning.experiments.id"), nullable=False
    )
    adaptation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("self_learning.adaptations.id"), nullable=False
    )
    candidate_version: Mapped[str] = mapped_column(String(100), nullable=False)
    baseline_version: Mapped[str] = mapped_column(String(100), nullable=False)

    # Provenance only -- `PolicyGateDecision` is never persisted (Phase
    # 9.7's own no-persistence discipline); this column records the fact
    # that a specific tier-2 ALLOW decision authorized this canary, never
    # a live handle to re-evaluate or mutate it.
    policy_gate_decision_id: Mapped[uuid.UUID] = mapped_column(nullable=False)

    # Serialized `EvaluationRules` (a tuple of `MetricThreshold`) -- see
    # `service.py`'s own `_serialize_rules()`/`_deserialize_rules()`.
    monitoring_rules: Mapped[dict] = mapped_column(JSON, nullable=False)

    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.users.id"), nullable=False
    )
    started_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    concluded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    promoted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    rolled_back_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    cancelled_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    concluded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Which monitored metric(s) triggered an automatic rollback, or why a
    # manual rollback/cancellation happened -- an identifier/reason
    # string, never raw observation content (this phase's own Audit
    # Requirement: no "unrestricted candidate contents").
    rollback_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    cancellation_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)


__all__ = [
    "CanaryStatus",
    "VALID_CANARY_STATUSES",
    "TERMINAL_CANARY_STATUSES",
    "Canary",
]
