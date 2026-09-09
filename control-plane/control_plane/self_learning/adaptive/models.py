"""L1 Adaptive Learning: the `Adaptation` entity and its typed allowlist
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.4).

`AdaptationSurface` is the **explicit, typed allowlist** of behavioral
configuration L1 may ever propose a change to -- the roadmap's own
Objective list, verbatim ("prompt/instruction candidates, model
selection/routing, tool selection, retrieval strategy, response
strategy, permitted personalization"), made a concrete enum rather than
an arbitrary `key: str`. There is no member here for security policy,
RBAC, secrets policy, autonomy-tier policy, tenant-isolation policy, or
audit policy -- an adaptation targeting any of those is not merely
rejected by a runtime check, it is *impossible to construct*, because no
such enum member exists (this task's own instruction: "do not rely
solely on string prefix checks if an explicit typed allowlist can
prevent the problem structurally"). The database's own `CHECK` constraint
on the `surface` column is the second, independent enforcement of the
same allowlist -- defense in depth against a direct-SQL bypass of this
Python enum, mirroring every other allowlisted-string column this
platform already ships (`core.audit_log.ActorType`,
`control_plane.orchestration`'s `data_classification`).

`Adaptation` is tenant-owned and RLS-protected (`self_learning` schema --
the namespace Phase 9.1 reserved and never used until now). Rows are
mutable state (`status` transitions candidate -> active -> superseded, or
candidate -> active -> rolled_back), not an immutable audit record --
`core.audit_log` (Phase 3.4) remains the platform's one append-only
security/audit trail; `service.py`'s own functions *additionally* write
to it for every creation/activation/rollback, exactly as
`control_plane.approvals` already does for its own mutable
`ApprovalRequest` rows.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from infra.db import Base as _Base
from infra.db import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Mapped,
    String,
    Text,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class AdaptationSurface(enum.StrEnum):
    """The only behavioral configuration L1 may ever target
    (docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Objective list)."""

    PROMPT_INSTRUCTION = "prompt_instruction"
    MODEL_SELECTION = "model_selection"
    ROUTING_STRATEGY = "routing_strategy"
    TOOL_SELECTION_STRATEGY = "tool_selection_strategy"
    RETRIEVAL_STRATEGY = "retrieval_strategy"
    RESPONSE_STRATEGY = "response_strategy"
    PERSONALIZATION = "personalization"


VALID_ADAPTATION_SURFACES: frozenset[str] = frozenset(s.value for s in AdaptationSurface)


class AdaptationStatus(enum.StrEnum):
    """`candidate` (proposed, not yet in effect) -> `active` (currently in
    effect, reached only through `service.activate_adaptation()` after an
    evaluation `PASS`) -> `superseded` (was active, replaced by a newer
    activation) or `rolled_back` (was active, reverted -- the immediately
    prior version is reactivated)."""

    CANDIDATE = "candidate"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ROLLED_BACK = "rolled_back"


VALID_ADAPTATION_STATUSES: frozenset[str] = frozenset(s.value for s in AdaptationStatus)


class AdaptationScope(enum.StrEnum):
    """`tenant` (default -- applies only to the originating tenant) or
    `platform_wide` (docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own
    Tenant-Isolation Requirement: "an adaptation learned from Tenant A's
    feedback does not apply to Tenant B unless explicitly, separately
    authorized as platform-wide" -- enforced in `service.py` by requiring
    an explicit `PlatformWideAdaptationAuthorization`, never inferred)."""

    TENANT = "tenant"
    PLATFORM_WIDE = "platform_wide"


VALID_ADAPTATION_SCOPES: frozenset[str] = frozenset(s.value for s in AdaptationScope)

# docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Objective, verbatim:
# "driven by explicit feedback and operator corrections only" -- L1's
# evidence is a strict *subset* of
# `control_plane.self_learning.models.VALID_EVIDENCE_TYPES` (Phase 9.2),
# which also includes tool_output/model_generated_content/external_content/
# imported_learning_material/evaluation_input -- none of those are valid
# L1 adaptation evidence, only these two.
VALID_ADAPTATION_EVIDENCE_TYPES: frozenset[str] = frozenset({"user_feedback", "operator_feedback"})
AdaptationEvidenceType = Literal["user_feedback", "operator_feedback"]

Base = _Base


@dataclass(frozen=True)
class PlatformWideAdaptationAuthorization:
    """Explicit, caller-supplied authorization permitting an adaptation
    proposed under `AdaptationScope.PLATFORM_WIDE` to actually apply
    beyond its originating tenant (docs/IMPLEMENTATION-ROADMAP.md Phase
    9.4: "unless explicitly, separately authorized as platform-wide").
    Not persisted -- mirrors `control_plane.data_authorization`'s and
    `control_plane.self_learning.models`'s own no-persistence
    policy-input discipline (Phase 9.2): a caller-supplied typed object,
    never an ambient global flag."""

    authorized_purposes: frozenset[str]


class Adaptation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "adaptations"
    __table_args__ = (
        CheckConstraint(
            "surface IN ('prompt_instruction', 'model_selection', 'routing_strategy', "
            "'tool_selection_strategy', 'retrieval_strategy', 'response_strategy', "
            "'personalization')",
            name="ck_adaptations_surface",
        ),
        CheckConstraint(
            "status IN ('candidate', 'active', 'superseded', 'rolled_back')",
            name="ck_adaptations_status",
        ),
        CheckConstraint("scope IN ('tenant', 'platform_wide')", name="ck_adaptations_scope"),
        CheckConstraint(
            "evidence_type IN ('user_feedback', 'operator_feedback')",
            name="ck_adaptations_evidence_type",
        ),
        CheckConstraint(
            "evaluation_outcome IS NULL OR evaluation_outcome IN "
            "('pass', 'fail', 'regression', 'invalid')",
            name="ck_adaptations_evaluation_outcome",
        ),
        Index("ix_adaptations_tenant_lineage", "tenant_id", "surface", "lineage_key"),
        Index("ix_adaptations_tenant_status", "tenant_id", "status"),
        {"schema": "self_learning"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    surface: Mapped[str] = mapped_column(String(40), nullable=False)
    lineage_key: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    scope: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AdaptationScope.TENANT.value
    )

    proposed_value: Mapped[str] = mapped_column(Text, nullable=False)
    previous_adaptation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("self_learning.adaptations.id"), nullable=True
    )

    learning_purpose: Mapped[str] = mapped_column(String(200), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(30), nullable=False)
    evidence_source_reference: Mapped[str] = mapped_column(String(500), nullable=False)

    # Provenance only -- neither a `LearningAuthorizationDecision` (Phase
    # 9.2) nor an `EvaluationComparison` (Phase 9.3) is itself persisted
    # (both remain in-memory-only objects, per those phases' own
    # no-speculative-persistence discipline); these columns record the
    # *fact* that a specific decision/comparison authorized/evaluated
    # this row, for audit and reproducibility, never a live handle to
    # mutate either.
    learning_authorization_decision_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    evaluation_comparison_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    evaluation_outcome: Mapped[str | None] = mapped_column(String(20), nullable=True)

    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.users.id"), nullable=False
    )
    activated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    rolled_back_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
