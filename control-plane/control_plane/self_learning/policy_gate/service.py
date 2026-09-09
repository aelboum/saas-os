"""The Autonomy & Policy Gate: evaluate -> audit
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.7).

`evaluate_policy_gate()` is a pure function -- same inputs always produce
the same `PolicyGateDecision`, no I/O, no database, no audit write, no
model/provider call (mirrors `control_plane.self_learning.evaluation
.service.evaluate_candidate()`'s own "pure function" discipline, Phase
9.3). It reads only the request's typed fields; there is no branch
anywhere below that treats a model/candidate's own claim as authoritative
-- see `models.py`'s "no self-attestation surface" docstring.

Checks run in a fixed, deterministic order -- "more restrictive policy
conditions must not be bypassed by weaker downstream approvals" (Phase
9.7's own Tests bullet, generalized): every structural/identity check
(tenant present, action known, tier known, tier 3 refused, scope
declared-and-respected, tenant-matching provenance) is evaluated *before*
any tier-specific approval/evidence check, so a request cannot skip a
foundational failure by supplying an otherwise-valid approval or tier-2
evidence bundle. Every `return` before the final ALLOW is a `DENY` with a
specific `PolicyGateDenialReason` -- default deny, never a silent
downgrade, matching every other gate this platform ships
(`control_plane.self_learning.service.evaluate_learning_authorization`,
`control_plane.self_learning.evaluation.service.evaluate_candidate`).

Tier semantics (docs/AI-CONTROL-PLANE.md section 5, reused verbatim):

- **Tier 0 -- propose only**: no standing checkpoint exists because no
  action has been taken yet; once Learning Authorization, Evaluation, and
  scope have all cleared, there is nothing further to gate.
- **Tier 1 -- propose + approval**: requires an `ApprovalRequest` for the
  *same* tenant, `status == "approved"`, an `approver_user_id` that is
  both present and distinct from `proposer_user_id` (separation of
  duties, re-checked here independently of `control_plane.approvals
  .approve()`'s own guarantee -- defense in depth against a hand-built or
  stale `ApprovalRequest`), and a `proposer_user_id` matching the
  request's own `actor_user_id` (an approval issued for one actor cannot
  authorize a *different* actor's execution -- the confused-deputy case
  this phase's own Tests bullet names).
- **Tier 2 -- auto-execute + audit**: requires `tier2_promotion_evidence`
  (an ADR reference) *and* `requested_action` to be a member of the
  caller-supplied, human-approved `tier2_eligible_actions` (the "narrow,
  pre-vetted action list" docs/AI-CONTROL-PLANE.md section 5 requires --
  a caller-supplied policy input, never an ambient default; its absence
  means the empty set, so tier 2 denies by default until a human
  decision explicitly names an eligible action).
- **Tier 3 -- fully autonomous**: refused unconditionally. Not a policy
  branch that could be satisfied by any combination of evidence/approval
  -- `docs/AI-CONTROL-PLANE.md` section 5's standing platform-wide rule,
  which this phase must not silently loosen (its own Security
  Requirement, verbatim).

`evaluate_and_record_policy_gate_decision()` is the audited entrypoint
(Phase 9.7's own Audit Requirement: `learning.policy_gate_decision`) --
it wraps the pure evaluator with exactly one `core.audit_log` entry,
reusing `core/audit_log`'s existing interface, never a second audit
mechanism. Metadata carries only identifiers/enums (`requested_action`,
`requested_autonomy_tier`, `reason`) -- never a raw scope value, payload,
prompt, or candidate content (Phase 9.7's own Audit Requirement: "must
not contain secrets, raw tenant/user data, full model prompts,
unrestricted candidate payloads, or sensitive proposed values").
"""

from __future__ import annotations

from control_plane.self_learning.evaluation.models import EvaluationOutcome
from control_plane.self_learning.models import LearningAuthorizationOutcome
from control_plane.self_learning.policy_gate.models import (
    VALID_AUTONOMY_TIERS,
    VALID_POLICY_GATE_ACTIONS,
    AutonomyTier,
    PolicyGateDecision,
    PolicyGateDenialReason,
    PolicyGateOutcome,
    PolicyGateRequest,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event

_AUDIT_RESOURCE_TYPE = "self_learning_policy_gate_decision"
_AUDIT_ACTION = "learning.policy_gate_decision"


def _deny(request: PolicyGateRequest, reason: PolicyGateDenialReason) -> PolicyGateDecision:
    return PolicyGateDecision(
        outcome=PolicyGateOutcome.DENY,
        tenant_id=request.tenant_id,
        requested_action=request.requested_action,
        requested_autonomy_tier=request.requested_autonomy_tier,
        reason=reason,
    )


def _allow(request: PolicyGateRequest) -> PolicyGateDecision:
    return PolicyGateDecision(
        outcome=PolicyGateOutcome.ALLOW,
        tenant_id=request.tenant_id,
        requested_action=request.requested_action,
        requested_autonomy_tier=request.requested_autonomy_tier,
        reason=None,
    )


def evaluate_policy_gate(request: PolicyGateRequest) -> PolicyGateDecision:
    """Default-deny-shaped decision: every `return` before the final line
    is `DENY`; the final line is the one and only `ALLOW` path, reached
    only once every prior, tier-appropriate check has passed explicitly.
    See module docstring for the fixed check order and tier semantics."""
    # -- Structural / identity checks, independent of autonomy tier ------
    if request.tenant_id is None:
        return _deny(request, PolicyGateDenialReason.MISSING_TENANT)

    if request.requested_action not in VALID_POLICY_GATE_ACTIONS:
        return _deny(request, PolicyGateDenialReason.UNKNOWN_ACTION)

    if request.requested_autonomy_tier not in VALID_AUTONOMY_TIERS:
        return _deny(request, PolicyGateDenialReason.UNKNOWN_AUTONOMY_TIER)

    # Tier 3 is refused unconditionally -- not a branch any evidence or
    # approval combination could ever satisfy. See module docstring.
    if request.requested_autonomy_tier == AutonomyTier.TIER_3_FULLY_AUTONOMOUS:
        return _deny(request, PolicyGateDenialReason.TIER_3_NOT_ENABLED)

    if request.scope is None or not request.scope.authorized or not request.scope.requested:
        return _deny(request, PolicyGateDenialReason.MISSING_SCOPE)

    if not request.scope.requested.issubset(request.scope.authorized):
        return _deny(request, PolicyGateDenialReason.SCOPE_MISMATCH)

    # -- Upstream authority composition -- passing one never implies the
    # next passed (docs/AI-CONTROL-PLANE.md section 12). ------------------
    decision = request.learning_authorization_decision
    if decision is None:
        return _deny(request, PolicyGateDenialReason.LEARNING_AUTHORIZATION_NOT_ALLOWED)
    if decision.tenant_id != request.tenant_id:
        return _deny(request, PolicyGateDenialReason.CROSS_TENANT_NOT_AUTHORIZED)
    if decision.outcome is not LearningAuthorizationOutcome.ALLOW:
        return _deny(request, PolicyGateDenialReason.LEARNING_AUTHORIZATION_NOT_ALLOWED)

    comparison = request.evaluation_comparison
    if comparison is None or comparison.outcome is not EvaluationOutcome.PASS:
        return _deny(request, PolicyGateDenialReason.EVALUATION_NOT_PASSED)

    # -- Tier-specific approval / evidence requirements -------------------
    if request.requested_autonomy_tier == AutonomyTier.TIER_0_PROPOSE_ONLY:
        return _allow(request)

    if request.requested_autonomy_tier == AutonomyTier.TIER_1_PROPOSE_AND_APPROVE:
        approval = request.approval
        if approval is None:
            return _deny(request, PolicyGateDenialReason.MISSING_REQUIRED_APPROVAL)
        if approval.tenant_id != request.tenant_id:
            return _deny(request, PolicyGateDenialReason.CROSS_TENANT_NOT_AUTHORIZED)
        if approval.status != "approved":
            return _deny(request, PolicyGateDenialReason.APPROVAL_NOT_APPROVED)
        if (
            approval.approver_user_id is None
            or approval.approver_user_id == approval.proposer_user_id
        ):
            return _deny(request, PolicyGateDenialReason.SELF_APPROVAL_NOT_ALLOWED)
        if approval.proposer_user_id != request.actor_user_id:
            return _deny(request, PolicyGateDenialReason.ACTOR_MISMATCH)
        return _allow(request)

    # AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED
    evidence = request.tier2_promotion_evidence
    if evidence is None:
        return _deny(request, PolicyGateDenialReason.TIER2_EVIDENCE_MISSING)
    if request.requested_action not in request.tier2_eligible_actions:
        return _deny(request, PolicyGateDenialReason.ACTION_NOT_TIER2_ELIGIBLE)
    return _allow(request)


def evaluate_and_record_policy_gate_decision(
    request: PolicyGateRequest, *, correlation_id: str | None = None
) -> PolicyGateDecision:
    """`evaluate_policy_gate()` plus exactly one `core.audit_log` entry
    (`learning.policy_gate_decision`), for every decision that has a real
    tenant to attribute it to (Phase 9.7's own Audit Requirement: "every
    gate decision ... is a core/audit-log entry"). `core.audit_log
    .record()` requires a real, foreign-keyed `tenant_id` on every row
    (`core/audit_log/models.py`'s own docstring); a `MISSING_TENANT`
    denial has no such tenant, so -- exactly like
    `control_plane.orchestration.service._execute_tool()`'s own
    `ToolNotFoundError` precedent ("no tool means nothing to attribute the
    attempt to as a real invocation") -- that one case is not written to
    `core.audit_log`, never recorded under a fabricated placeholder
    tenant."""
    decision = evaluate_policy_gate(request)

    if decision.tenant_id is None:
        return decision

    metadata: dict[str, object] = {
        "requested_action": decision.requested_action,
        "requested_autonomy_tier": decision.requested_autonomy_tier,
    }
    if decision.reason is not None:
        metadata["reason"] = decision.reason.value

    record_audit_event(
        tenant_id=decision.tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=request.actor_user_id,
        action=_AUDIT_ACTION,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(decision.decision_id),
        outcome=AuditOutcome.SUCCESS if decision.is_allowed else AuditOutcome.DENIED,
        correlation_id=correlation_id,
        metadata=metadata,
    )
    return decision
