"""Data Authorization: "can this data reach an external AI/LLM provider,
for this one call?" (ADR-0013; docs/AI-CONTROL-PLANE.md section 2.1;
docs/IMPLEMENTATION-ROADMAP.md Phase 9.2).

`evaluate_data_authorization()` is a pure function -- same inputs always
produce the same `DataAuthorizationDecision`, no I/O, no database, no
audit write. Every branch that is not an explicit, named ALLOW falls
through to a DENY with a specific `DataDenialReason` (docs/ADR/0013-...
section 5: "Unknown or unclassified sensitive data -> DENY... the
boundary must not depend on a developer remembering to redact something
manually"). This is what "default deny must be structurally obvious in
the code" (Phase 9.2) means concretely: there is no code path that
returns ALLOW without every one of the checks below having explicitly
passed.

`authorize_data_access()` is the audited entrypoint a real caller (a
future AI Control Plane tool) uses -- it wraps the pure evaluator and
additionally writes exactly one `core.audit_log` entry per decision
(Phase 9.2's own Audit Requirement: "every data/learning-authorization
decision (allow or deny) is a core/audit-log entry"), reusing
`core/audit_log`'s existing interface -- never a second audit mechanism
(docs/ADR/0014-... "Learning Authorization does not grant policy
authority" applies equally here: this module has no path that mutates
`core.audit_log`, `core.rbac`, or `infra.secrets`, only one that calls
`core.audit_log.record()` exactly like `control_plane.orchestration`
already does).

This module never imports `sqlalchemy` or `infra.secrets` -- it holds no
database handle and requests no secret (Phase 9.2's own scope: "no
external AI/provider call is introduced by this phase"). Its only
infrastructure dependency is `core.audit_log.record()`.
"""

from __future__ import annotations

import uuid

from control_plane.data_authorization.models import (
    VALID_DATA_CLASSIFICATIONS,
    DataAuthorizationDecision,
    DataAuthorizationOutcome,
    DataAuthorizationRequest,
    DataDenialReason,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event

_AUDIT_RESOURCE_TYPE = "ai_data_authorization"
_AUDIT_ACTION_APPROVED = "ai_control_plane.data_access_approved"
_AUDIT_ACTION_DENIED = "ai_control_plane.data_access_denied"


def _deny(request: DataAuthorizationRequest, reason: DataDenialReason) -> DataAuthorizationDecision:
    return DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.DENY,
        tenant_id=request.tenant_id,
        data_classification=request.data_classification,
        purpose=request.purpose,
        provider=request.provider,
        reason=reason,
    )


def _allow(request: DataAuthorizationRequest) -> DataAuthorizationDecision:
    return DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=request.tenant_id,
        data_classification=request.data_classification,
        purpose=request.purpose,
        provider=request.provider,
        reason=None,
    )


def evaluate_data_authorization(
    request: DataAuthorizationRequest,
    *,
    tenant_policy: TenantAIDataPolicy | None,
    provider_policy: ProviderEligibilityPolicy,
) -> DataAuthorizationDecision:
    """Default-deny evaluation of one `DataAuthorizationRequest`. Every
    `return` before the final line is a DENY; the final line is the one
    and only ALLOW path, reached only once every prior check has passed
    explicitly."""
    if (
        not request.data_classification
        or request.data_classification not in VALID_DATA_CLASSIFICATIONS
    ):
        return _deny(request, DataDenialReason.UNCLASSIFIED_DATA)

    if tenant_policy is None or tenant_policy.tenant_id != request.tenant_id:
        return _deny(request, DataDenialReason.NO_TENANT_POLICY)

    if request.data_classification not in tenant_policy.allowed_data_classifications:
        return _deny(request, DataDenialReason.DATA_CLASS_NOT_PERMITTED)

    if not request.purpose or request.purpose not in tenant_policy.allowed_purposes:
        return _deny(request, DataDenialReason.PURPOSE_NOT_PERMITTED)

    if request.provider not in provider_policy.eligible_providers:
        return _deny(request, DataDenialReason.PROVIDER_NOT_GLOBALLY_ELIGIBLE)

    if request.provider not in tenant_policy.allowed_providers:
        return _deny(request, DataDenialReason.PROVIDER_NOT_PERMITTED)

    return _allow(request)


def authorize_data_access(
    request: DataAuthorizationRequest,
    *,
    tenant_policy: TenantAIDataPolicy | None,
    provider_policy: ProviderEligibilityPolicy,
    actor_user_id: uuid.UUID,
    correlation_id: str | None = None,
) -> DataAuthorizationDecision:
    """`evaluate_data_authorization()` plus exactly one `core.audit_log`
    entry, allow or deny (Phase 9.2's Audit Requirement). Metadata never
    carries the request's own data content -- only classification,
    purpose, provider, and (on denial) the specific reason, matching
    `DataAuthorizationRequest`'s own "never the data's own content"
    discipline."""
    decision = evaluate_data_authorization(
        request, tenant_policy=tenant_policy, provider_policy=provider_policy
    )

    metadata: dict[str, object] = {
        "data_classification": decision.data_classification,
        "purpose": decision.purpose,
        "provider": decision.provider,
        "decision_id": str(decision.decision_id),
    }
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
