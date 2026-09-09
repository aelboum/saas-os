"""L1 Adaptive Learning: propose -> evaluate -> activate -> rollback
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.4).

Four operations, mirroring `control_plane.approvals`'s own "three
distinct steps, three distinct calls" discipline:

- `propose_adaptation()` -- creates a `CANDIDATE` row. Requires an
  already-ALLOW `LearningAuthorizationDecision` for the same tenant
  (Phase 9.2's gate, never bypassed) and evidence restricted to
  `user_feedback`/`operator_feedback` (Phase 9.4's own Objective:
  "driven by explicit feedback and operator corrections only" -- a
  strict subset of Phase 9.2's broader `VALID_EVIDENCE_TYPES`). Tier 0 --
  proposing a candidate has no production effect.
- `record_adaptation_evaluation()` -- attaches a Phase 9.3
  `EvaluationComparison`'s outcome to a still-`CANDIDATE` row. Tier 0 --
  recording a measured result has no production effect either.
- `activate_adaptation()` / `rollback_adaptation()` -- the two
  state-changing, production-effect-bearing operations. Both are wrapped
  as tier-1 AI Control Plane tools
  (`control_plane.tools.activate_adaptation`,
  `control_plane.tools.rollback_adaptation`) that can only run through
  `control_plane.approvals`' propose -> approve -> execute workflow
  (docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Dependencies: "7.2
  ...for anything above autonomy tier 0"). The functions here are the
  *domain logic* those tools' handlers call into -- never invoked
  directly by an agent, exactly like `control_plane.orchestration
  ._execute_tool()` is the one sanctioned path into tier>=1 execution.

`activate_adaptation()` refuses to run against a candidate whose
`evaluation_outcome` is not `EvaluationOutcome.PASS.value`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own binding Security
Requirement: "adaptation candidates are evaluated (9.3) before taking
effect, never applied directly from raw model output") -- this is
enforced structurally (`AdaptationNotEvaluatedError`), not left to a
caller's discipline.

Every one of the three roadmap-named audit events
(`learning.adaptation_created` / `.activated` / `.rolled_back`) is
written through `core.audit_log`'s existing interface -- this module has
no second audit mechanism, and (docs/IMPLEMENTATION-ROADMAP.md Phase
9.4's own explicit Non-Goals) no path that writes to `core.*`, mutates an
RBAC grant, touches `infra.secrets`, or deploys anything -- the only
persistence this module ever writes to is its own
`self_learning.adaptations` table.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from control_plane.self_learning.adaptive.errors import (
    AdaptationNotActiveError,
    AdaptationNotCandidateError,
    AdaptationNotEvaluatedError,
    AdaptationNotFoundError,
    InvalidAdaptationSurfaceError,
    NoPreviousVersionError,
    PlatformWideScopeNotAuthorizedError,
    UnauthorizedAdaptationEvidenceError,
)
from control_plane.self_learning.adaptive.models import (
    VALID_ADAPTATION_EVIDENCE_TYPES,
    VALID_ADAPTATION_SURFACES,
    Adaptation,
    AdaptationEvidenceType,
    AdaptationScope,
    AdaptationStatus,
    AdaptationSurface,
    PlatformWideAdaptationAuthorization,
)
from control_plane.self_learning.evaluation.models import EvaluationComparison, EvaluationOutcome
from control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from infra.db import select, tenant_session_scope

_AUDIT_RESOURCE_TYPE = "self_learning_adaptation"


def _audit(
    *,
    tenant_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    action: str,
    adaptation_id: uuid.UUID,
    metadata: dict[str, object],
) -> None:
    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(adaptation_id),
        outcome=AuditOutcome.SUCCESS,
        metadata=metadata,
    )


def propose_adaptation(
    *,
    tenant_id: uuid.UUID,
    surface: AdaptationSurface,
    lineage_key: str,
    proposed_value: str,
    learning_purpose: str,
    learning_authorization_decision: LearningAuthorizationDecision,
    evidence_type: AdaptationEvidenceType,
    evidence_source_reference: str,
    created_by_user_id: uuid.UUID,
    scope: AdaptationScope = AdaptationScope.TENANT,
    platform_wide_authorization: PlatformWideAdaptationAuthorization | None = None,
) -> Adaptation:
    """Create one `CANDIDATE` adaptation. Raises rather than silently
    downgrading scope or evidence -- default deny, matching every other
    gate this platform ships."""
    if surface.value not in VALID_ADAPTATION_SURFACES:  # unreachable via the typed parameter;
        raise InvalidAdaptationSurfaceError(str(surface))  # defense in depth against a raw bypass.

    if (
        learning_authorization_decision.outcome is not LearningAuthorizationOutcome.ALLOW
        or learning_authorization_decision.tenant_id != tenant_id
    ):
        raise UnauthorizedAdaptationEvidenceError(
            "Learning Authorization for this tenant must be ALLOW before proposing an adaptation."
        )

    if evidence_type not in VALID_ADAPTATION_EVIDENCE_TYPES:
        raise UnauthorizedAdaptationEvidenceError(
            f"{evidence_type!r} is not permitted L1 adaptation evidence -- only "
            "user_feedback/operator_feedback (docs/IMPLEMENTATION-ROADMAP.md Phase 9.4)."
        )

    if scope is AdaptationScope.PLATFORM_WIDE:
        if platform_wide_authorization is None or (
            learning_purpose not in platform_wide_authorization.authorized_purposes
        ):
            raise PlatformWideScopeNotAuthorizedError(tenant_id, learning_purpose)

    with tenant_session_scope(tenant_id) as session:
        current_active = session.execute(
            select(Adaptation).where(
                Adaptation.tenant_id == tenant_id,
                Adaptation.surface == surface.value,
                Adaptation.lineage_key == lineage_key,
                Adaptation.status == AdaptationStatus.ACTIVE.value,
            )
        ).scalar_one_or_none()

        max_version = session.execute(
            select(Adaptation.version)
            .where(
                Adaptation.tenant_id == tenant_id,
                Adaptation.surface == surface.value,
                Adaptation.lineage_key == lineage_key,
            )
            .order_by(Adaptation.version.desc())
            .limit(1)
        ).scalar_one_or_none()

        adaptation = Adaptation(
            tenant_id=tenant_id,
            surface=surface.value,
            lineage_key=lineage_key,
            version=(max_version or 0) + 1,
            status=AdaptationStatus.CANDIDATE.value,
            scope=scope.value,
            proposed_value=proposed_value,
            previous_adaptation_id=current_active.id if current_active is not None else None,
            learning_purpose=learning_purpose,
            evidence_type=evidence_type,
            evidence_source_reference=evidence_source_reference,
            learning_authorization_decision_id=learning_authorization_decision.decision_id,
            created_by_user_id=created_by_user_id,
        )
        session.add(adaptation)
        session.flush()
        session.refresh(adaptation)
        session.expunge(adaptation)

    _audit(
        tenant_id=tenant_id,
        actor_user_id=created_by_user_id,
        action="learning.adaptation_created",
        adaptation_id=adaptation.id,
        metadata={
            "surface": surface.value,
            "lineage_key": lineage_key,
            "version": adaptation.version,
            "scope": scope.value,
            "learning_purpose": learning_purpose,
            "evidence_type": evidence_type,
        },
    )
    return adaptation


def get_adaptation(tenant_id: uuid.UUID, adaptation_id: uuid.UUID) -> Adaptation:
    with tenant_session_scope(tenant_id) as session:
        adaptation = session.get(Adaptation, adaptation_id)
        if adaptation is None or adaptation.tenant_id != tenant_id:
            raise AdaptationNotFoundError(tenant_id, adaptation_id)
        session.expunge(adaptation)
        return adaptation


def record_adaptation_evaluation(
    tenant_id: uuid.UUID, adaptation_id: uuid.UUID, comparison: EvaluationComparison
) -> Adaptation:
    """Attach a Phase 9.3 `EvaluationComparison`'s outcome to a
    still-`CANDIDATE` adaptation. Evaluation is evidence, not a promotion
    -- this only records a measured result; it never changes `status`."""
    with tenant_session_scope(tenant_id) as session:
        row = session.get(Adaptation, adaptation_id)
        if row is None or row.tenant_id != tenant_id:
            raise AdaptationNotFoundError(tenant_id, adaptation_id)
        if row.status != AdaptationStatus.CANDIDATE.value:
            raise AdaptationNotCandidateError(adaptation_id, row.status)

        row.evaluation_comparison_id = comparison.decision_id
        row.evaluation_outcome = comparison.outcome.value
        session.flush()
        session.refresh(row)
        session.expunge(row)
        return row


def activate_adaptation(
    tenant_id: uuid.UUID, adaptation_id: uuid.UUID, *, activated_by_user_id: uuid.UUID
) -> Adaptation:
    """The tier-1 activation transition -- called only from
    `control_plane.tools.activate_adaptation`'s handler, itself only
    reachable through `control_plane.approvals.execute_approved()` once a
    human has approved it (never invoked directly by an agent)."""
    with tenant_session_scope(tenant_id) as session:
        row = session.get(Adaptation, adaptation_id)
        if row is None or row.tenant_id != tenant_id:
            raise AdaptationNotFoundError(tenant_id, adaptation_id)
        if row.status != AdaptationStatus.CANDIDATE.value:
            raise AdaptationNotCandidateError(adaptation_id, row.status)
        if row.evaluation_outcome != EvaluationOutcome.PASS.value:
            raise AdaptationNotEvaluatedError(adaptation_id, row.evaluation_outcome)

        current_active = session.execute(
            select(Adaptation).where(
                Adaptation.tenant_id == tenant_id,
                Adaptation.surface == row.surface,
                Adaptation.lineage_key == row.lineage_key,
                Adaptation.status == AdaptationStatus.ACTIVE.value,
            )
        ).scalar_one_or_none()
        if current_active is not None:
            current_active.status = AdaptationStatus.SUPERSEDED.value
            # Flushed separately, before this row becomes ACTIVE: the two
            # UPDATEs must not be visible to `ux_adaptations_one_active_per_lineage`
            # (a non-deferrable partial unique index) at the same instant,
            # or Postgres transiently sees two ACTIVE rows for one lineage
            # and raises IntegrityError even though the end state is valid.
            session.flush()

        row.status = AdaptationStatus.ACTIVE.value
        row.activated_by_user_id = activated_by_user_id
        row.activated_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        adaptation = row

    _audit(
        tenant_id=tenant_id,
        actor_user_id=activated_by_user_id,
        action="learning.adaptation_activated",
        adaptation_id=adaptation.id,
        metadata={
            "surface": adaptation.surface,
            "lineage_key": adaptation.lineage_key,
            "version": adaptation.version,
            "evaluation_outcome": adaptation.evaluation_outcome,
        },
    )
    return adaptation


def rollback_adaptation(
    tenant_id: uuid.UUID, adaptation_id: uuid.UUID, *, rolled_back_by_user_id: uuid.UUID
) -> Adaptation:
    """Revert an `ACTIVE` adaptation to its immediately-prior version
    (docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Rollback Strategy:
    "every adaptation is revertible to its immediately-prior version").
    Same tier-1/approvals-only reachability as `activate_adaptation()`.
    Returns the *reactivated previous* adaptation -- the new current
    state of this lineage."""
    with tenant_session_scope(tenant_id) as session:
        row = session.get(Adaptation, adaptation_id)
        if row is None or row.tenant_id != tenant_id:
            raise AdaptationNotFoundError(tenant_id, adaptation_id)
        if row.status != AdaptationStatus.ACTIVE.value:
            raise AdaptationNotActiveError(adaptation_id, row.status)
        if row.previous_adaptation_id is None:
            raise NoPreviousVersionError(adaptation_id)

        previous = session.get(Adaptation, row.previous_adaptation_id)
        if previous is None or previous.tenant_id != tenant_id:
            raise AdaptationNotFoundError(tenant_id, row.previous_adaptation_id)

        row.status = AdaptationStatus.ROLLED_BACK.value
        row.rolled_back_by_user_id = rolled_back_by_user_id
        row.rolled_back_at = datetime.now(UTC)
        # Flushed before `previous` becomes ACTIVE -- same
        # non-deferrable-partial-unique-index ordering discipline as
        # activate_adaptation() above.
        session.flush()

        previous.status = AdaptationStatus.ACTIVE.value

        session.flush()
        session.refresh(row)
        session.refresh(previous)
        session.expunge(row)
        session.expunge(previous)
        rolled_back, reactivated = row, previous

    _audit(
        tenant_id=tenant_id,
        actor_user_id=rolled_back_by_user_id,
        action="learning.adaptation_rolled_back",
        adaptation_id=rolled_back.id,
        metadata={
            "surface": rolled_back.surface,
            "lineage_key": rolled_back.lineage_key,
            "rolled_back_version": rolled_back.version,
            "reactivated_version": reactivated.version,
            "reactivated_adaptation_id": str(reactivated.id),
        },
    )
    return reactivated
