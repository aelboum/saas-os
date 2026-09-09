"""Learning Authorization: "can this data be retained/reused to shape
future behavior, for what purpose, for which tenant, for which
model/provider, for how long?" (ADR-0014, Accepted;
docs/IMPLEMENTATION-ROADMAP.md Phase 9.2).

The third, independent gate in the docs/AI-CONTROL-PLANE.md section 2.1 /
section 12 diagram:

    Tool Authorization (ADR-0004, control_plane.orchestration)
            |
    Data Authorization (ADR-0013, control_plane.data_authorization)
            |
    Learning Authorization (ADR-0014, this module)

`evaluate_learning_authorization()` is a pure function, structurally
default-deny exactly like
`control_plane.data_authorization.service.evaluate_data_authorization()`
-- every branch that is not an explicit, named ALLOW returns a DENY with
a specific `LearningDenialReason`. Its **first** check requires an
already-ALLOW `DataAuthorizationDecision` for the *same* tenant: passing
Data Authorization is necessary but never sufficient for Learning
Authorization to pass (ADR-0014's own "passing an earlier gate never
implies a later one passes") -- and a DENY at Data Authorization makes a
Learning Authorization ALLOW structurally unreachable, which is Phase
9.2's own Tests requirement, "data denied by Data Authorization never
reaches a learning event."

`request.evidence` (a `LearningEvidence`) is accepted by this function's
signature but never inspected by any `if`/branch below that decides the
outcome -- it flows straight through to the returned decision only as
`data_authorization_decision_id`-adjacent provenance recorded by the
audited wrapper (`authorize_learning_use()`) via `core.audit_log`'s
metadata, never as an input the evaluator reads to decide ALLOW/DENY.
This is the literal code-level enforcement of ADR-0014's "external input
is evidence, not trusted policy": swap `evidence` for a different value
with the same other request fields, and the decision is provably
unchanged (see
`tests/control_plane/self_learning/test_learning_authorization_unit.py`).

Cross-tenant reuse (`request.cross_tenant_target_tenant_id` set to a
tenant other than `request.tenant_id`) is denied unless a
`CrossTenantLearningPolicy` is supplied that names *exactly* this
source/target pair and *exactly* this purpose (ADR-0014 invariant 1;
docs/SECURITY.md section 6.2 invariant 1) -- see Phase 9.2's own adversarial
Tests requirement.

This module never imports `sqlalchemy` or `infra.secrets`, and never
imports `core.rbac` (ADR-0014's Option C was explicitly rejected: Learning
Authorization is not folded into RBAC's `can(actor, action, resource)`
chokepoint, which has no concept of purpose/retention/tenant-reuse). It
never defines or calls anything resembling `set_policy()`,
`update_security_policy()`, `modify_permissions()`, or
`change_autonomy_tier()` -- Learning Authorization decides only whether
*this* module retains/reuses data; it carries no authority over
`core.rbac`, `infra.secrets`, or `docs/AI-CONTROL-PLANE.md` section 5's
autonomy tiers (ADR-0014 Decision, "Learning Authorization does not grant
policy authority").
"""

from __future__ import annotations

import uuid

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.models import (
    VALID_EVIDENCE_TYPES,
    CrossTenantLearningPolicy,
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
    LearningAuthorizationRequest,
    LearningDenialReason,
    TenantLearningPolicy,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event

_AUDIT_RESOURCE_TYPE = "learning_authorization"
_AUDIT_ACTION_APPROVED = "learning.data_access_approved"
_AUDIT_ACTION_DENIED = "learning.data_access_denied"


def _deny(
    request: LearningAuthorizationRequest,
    data_authorization_decision: DataAuthorizationDecision,
    reason: LearningDenialReason,
) -> LearningAuthorizationDecision:
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.DENY,
        tenant_id=request.tenant_id,
        purpose=request.purpose,
        reason=reason,
        data_authorization_decision_id=data_authorization_decision.decision_id,
    )


def _allow(
    request: LearningAuthorizationRequest,
    data_authorization_decision: DataAuthorizationDecision,
) -> LearningAuthorizationDecision:
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.ALLOW,
        tenant_id=request.tenant_id,
        purpose=request.purpose,
        reason=None,
        data_authorization_decision_id=data_authorization_decision.decision_id,
    )


def evaluate_learning_authorization(
    request: LearningAuthorizationRequest,
    *,
    data_authorization_decision: DataAuthorizationDecision,
    tenant_learning_policy: TenantLearningPolicy | None,
    cross_tenant_policy: CrossTenantLearningPolicy | None = None,
) -> LearningAuthorizationDecision:
    """Default-deny evaluation of one `LearningAuthorizationRequest`.
    `request.evidence` is accepted but deliberately never read below --
    see module docstring."""
    if (
        data_authorization_decision.outcome is not DataAuthorizationOutcome.ALLOW
        or data_authorization_decision.tenant_id != request.tenant_id
    ):
        return _deny(
            request, data_authorization_decision, LearningDenialReason.DATA_AUTHORIZATION_NOT_PASSED
        )

    if (
        not request.evidence.evidence_type
        or request.evidence.evidence_type not in VALID_EVIDENCE_TYPES
        or not request.evidence.source_reference
    ):
        return _deny(request, data_authorization_decision, LearningDenialReason.INVALID_EVIDENCE)

    is_cross_tenant = (
        request.cross_tenant_target_tenant_id is not None
        and request.cross_tenant_target_tenant_id != request.tenant_id
    )
    if is_cross_tenant:
        if (
            cross_tenant_policy is None
            or cross_tenant_policy.source_tenant_id != request.tenant_id
            or cross_tenant_policy.target_tenant_id != request.cross_tenant_target_tenant_id
            or request.purpose not in cross_tenant_policy.approved_purposes
        ):
            return _deny(
                request,
                data_authorization_decision,
                LearningDenialReason.CROSS_TENANT_NOT_AUTHORIZED,
            )

    if tenant_learning_policy is None or tenant_learning_policy.tenant_id != request.tenant_id:
        return _deny(request, data_authorization_decision, LearningDenialReason.NO_LEARNING_POLICY)

    if not request.purpose or request.purpose not in tenant_learning_policy.allowed_purposes:
        return _deny(
            request, data_authorization_decision, LearningDenialReason.PURPOSE_NOT_PERMITTED
        )

    if request.target_model_or_provider not in tenant_learning_policy.allowed_models_or_providers:
        return _deny(
            request,
            data_authorization_decision,
            LearningDenialReason.MODEL_OR_PROVIDER_NOT_PERMITTED,
        )

    if request.retention not in tenant_learning_policy.allowed_retentions:
        return _deny(
            request, data_authorization_decision, LearningDenialReason.RETENTION_NOT_PERMITTED
        )

    return _allow(request, data_authorization_decision)


def authorize_learning_use(
    request: LearningAuthorizationRequest,
    *,
    data_authorization_decision: DataAuthorizationDecision,
    tenant_learning_policy: TenantLearningPolicy | None,
    cross_tenant_policy: CrossTenantLearningPolicy | None = None,
    actor_user_id: uuid.UUID,
    correlation_id: str | None = None,
) -> LearningAuthorizationDecision:
    """`evaluate_learning_authorization()` plus exactly one
    `core.audit_log` entry, allow or deny (Phase 9.2's Audit Requirement;
    action names `learning.data_access_approved` /
    `learning.data_access_denied` per the roadmap's own example).
    Metadata never carries the evidence's content -- only its type,
    source reference (a pointer, not raw data), purpose, and (on denial)
    the specific reason."""
    decision = evaluate_learning_authorization(
        request,
        data_authorization_decision=data_authorization_decision,
        tenant_learning_policy=tenant_learning_policy,
        cross_tenant_policy=cross_tenant_policy,
    )

    metadata: dict[str, object] = {
        "purpose": decision.purpose,
        "evidence_type": request.evidence.evidence_type,
        "evidence_source_reference": request.evidence.source_reference,
        "target_model_or_provider": request.target_model_or_provider,
        "retention": request.retention,
        "data_authorization_decision_id": str(decision.data_authorization_decision_id),
        "decision_id": str(decision.decision_id),
    }
    if request.cross_tenant_target_tenant_id is not None:
        metadata["cross_tenant_target_tenant_id"] = str(request.cross_tenant_target_tenant_id)
    if decision.reason is not None:
        metadata["denial_reason"] = decision.reason.value

    record_audit_event(
        tenant_id=request.tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action=_AUDIT_ACTION_APPROVED if decision.is_allowed else _AUDIT_ACTION_DENIED,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(decision.decision_id),
        outcome=AuditOutcome.SUCCESS if decision.is_allowed else AuditOutcome.DENIED,
        correlation_id=correlation_id,
        metadata=metadata,
    )
    return decision
