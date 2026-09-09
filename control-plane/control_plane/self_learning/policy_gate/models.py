"""Typed request/decision shapes for the Autonomy & Policy Gate
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.7; docs/AI-CONTROL-PLANE.md
section 5's autonomy-tier vocabulary, reused verbatim -- not a parallel
tier model).

`PolicyGateRequest` is the one typed input every candidate action must be
expressed as before `service.evaluate_policy_gate()` can decide anything.
Its fields exist because each is checked by an independent authority this
module composes with rather than duplicates (Phase 9.7's own Scope: "the
gate mechanism itself ... not any specific promotion decision"):

- `learning_authorization_decision` -- ADR-0014's gate
  (`control_plane.self_learning.models`), never re-derived here.
- `evaluation_comparison` -- Phase 9.3's gate
  (`control_plane.self_learning.evaluation.models`), never re-scored here.
- `approval` -- Phase 7.2's gate (`control_plane.approvals.models
  .ApprovalRequest`), never re-implemented here; required only for tier 1.
- `tier2_promotion_evidence` -- the ADR-citing reliability evidence Phase
  9.7's own Tests bullet requires before tier 2 ("auto-execute + audit")
  is ever granted, and `tier2_eligible_actions` -- the caller-supplied,
  human-approved, versioned tier-2-eligible-action list
  (docs/AI-CONTROL-PLANE.md section 5: "the *list* of tier-2-eligible
  actions is itself a human-approved, versioned artifact") -- not an
  ambient global default (mirrors `control_plane.self_learning.models
  .TenantLearningPolicy`'s own caller-supplied-policy-input discipline:
  absence means the empty set, never an implicit allow).

**No self-attestation surface, structurally**: there is no field here
named `authorized`/`approved`/`safe`/`autonomous`, nor any free-form
dict/payload field a caller could smuggle such a claim into -- every
field is either a real, independently-authoritative typed decision object
(`LearningAuthorizationDecision`, `EvaluationComparison`, `ApprovalRequest`)
or a plain identifier/enum `service.py` checks structurally. A caller
cannot construct a request that carries its own verdict -- Python
dataclasses reject an unknown keyword argument at construction time, the
same structural proof `control_plane.self_learning.evaluation.models
.EvaluationMetrics` and `control_plane.self_learning.system_learning
.models.SystemLearningProposal` already establish for their own domains
(see each module's own "no self-attestation surface" docstring).

`RequestedAction` is the closed, typed allowlist of what this gate can
ever be asked about -- exactly the two things a Phase 9.6 experiment can
resolve to promoting (an activated `Adaptation`, Phase 9.4, or an
experiment's own candidate reaching production, the literal next step
Phase 9.6's own Objective describes and Phase 9.8 will execute). There is
no member for a security-policy, RBAC, secrets, or autonomy-tier change --
same structural-impossibility discipline as
`control_plane.self_learning.adaptive.models.AdaptationSurface` and
`control_plane.self_learning.system_learning.models.ProposedChangeTarget`.
An unrecognized string is `PolicyGateDenialReason.UNKNOWN_ACTION`, decided
by `service.py`, never silently coerced into a known member.

No database table, migration, or ORM model is defined here -- exactly
`control_plane.self_learning.evaluation`'s own no-persistence discipline
(Phase 9.3): Phase 9.7's own Rollback Strategy is "revert code; no
candidate has been autonomously deployed yet at this phase, so no
production rollback is needed," which is only true if this package never
introduces persistent state.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field

from control_plane.approvals.models import ApprovalRequest
from control_plane.self_learning.evaluation.models import EvaluationComparison, EvaluationOutcome
from control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)


class AutonomyTier(enum.IntEnum):
    """docs/AI-CONTROL-PLANE.md section 5's own four tiers, verbatim --
    reused, not reinvented. Tier 3 is a real, constructible member (a
    request can name it) precisely so `service.evaluate_policy_gate()` has
    something concrete to always deny (docs/AI-CONTROL-PLANE.md section 5:
    "Not enabled for any capability at this stage") -- the platform-wide
    rule is enforced by `service.py` refusing it unconditionally, not by
    the vocabulary omitting it."""

    TIER_0_PROPOSE_ONLY = 0
    TIER_1_PROPOSE_AND_APPROVE = 1
    TIER_2_AUTO_EXECUTE_AUDITED = 2
    TIER_3_FULLY_AUTONOMOUS = 3


VALID_AUTONOMY_TIERS: frozenset[int] = frozenset(t.value for t in AutonomyTier)


class RequestedAction(enum.StrEnum):
    """The closed allowlist of what a policy-gate request may ever name as
    its action -- see module docstring."""

    ACTIVATE_ADAPTATION = "activate_adaptation"
    PROMOTE_EXPERIMENT = "promote_experiment"


VALID_POLICY_GATE_ACTIONS: frozenset[str] = frozenset(a.value for a in RequestedAction)


class PolicyGateOutcome(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class PolicyGateDenialReason(enum.StrEnum):
    """Every non-ALLOW branch `service.evaluate_policy_gate()` can take --
    exhaustive by construction, mirroring
    `control_plane.self_learning.models.LearningDenialReason`'s own
    docstring for why this matters: a caller (or a test) can name the
    *specific* fail-closed condition that fired, never just "denied"."""

    MISSING_TENANT = "missing_tenant"
    UNKNOWN_ACTION = "unknown_action"
    UNKNOWN_AUTONOMY_TIER = "unknown_autonomy_tier"
    TIER_3_NOT_ENABLED = "tier_3_not_enabled"
    MISSING_SCOPE = "missing_scope"
    SCOPE_MISMATCH = "scope_mismatch"
    LEARNING_AUTHORIZATION_NOT_ALLOWED = "learning_authorization_not_allowed"
    CROSS_TENANT_NOT_AUTHORIZED = "cross_tenant_not_authorized"
    EVALUATION_NOT_PASSED = "evaluation_not_passed"
    MISSING_REQUIRED_APPROVAL = "missing_required_approval"
    APPROVAL_NOT_APPROVED = "approval_not_approved"
    SELF_APPROVAL_NOT_ALLOWED = "self_approval_not_allowed"
    ACTOR_MISMATCH = "actor_mismatch"
    TIER2_EVIDENCE_MISSING = "tier2_evidence_missing"
    ACTION_NOT_TIER2_ELIGIBLE = "action_not_tier2_eligible"


@dataclass(frozen=True)
class PolicyGateScope:
    """The declared scope an action is authorized to touch
    (`authorized`) versus what it would actually touch (`requested`) --
    both opaque, caller-defined identifier sets (e.g. a lineage key, a
    surface name); this module never interprets their meaning, only their
    set relationship (Phase 9.7's own Tests bullet: "an action must
    operate only within the declared scope"). `requested` must be a
    non-empty subset of a non-empty `authorized`, checked by `service.py`
    -- an empty scope on either side is `MISSING_SCOPE`, never treated as
    "no restriction."
    """

    authorized: frozenset[str]
    requested: frozenset[str]


@dataclass(frozen=True)
class Tier2PromotionEvidence:
    """The ADR-citing, demonstrated-reliability evidence Phase 9.7's own
    Tests bullet requires before any tier-2 ("auto-execute + audit")
    promotion: "a test proves the gate rejects a promotion attempt lacking
    that evidence reference." `adr_reference` is a pointer (e.g.
    "docs/ADR/0020-...") -- this module never validates the ADR's content,
    only that a reference was actually supplied, mirroring
    `control_plane.self_learning.models.LearningEvidence.source_reference`'s
    own pointer-not-content discipline."""

    adr_reference: str
    reliability_summary: str

    def __post_init__(self) -> None:
        if not self.adr_reference or not self.adr_reference.strip():
            raise AssertionError("Tier2PromotionEvidence.adr_reference must be non-empty.")
        if not self.reliability_summary or not self.reliability_summary.strip():
            raise AssertionError("Tier2PromotionEvidence.reliability_summary must be non-empty.")


@dataclass(frozen=True)
class PolicyGateRequest:
    """One request to gate a candidate action at a declared autonomy
    tier. See module docstring for why each field exists and why there is
    no self-attestation field anywhere here."""

    tenant_id: uuid.UUID | None
    actor_user_id: uuid.UUID
    requested_action: str
    requested_autonomy_tier: int
    scope: PolicyGateScope | None
    learning_authorization_decision: LearningAuthorizationDecision | None
    evaluation_comparison: EvaluationComparison | None = None
    approval: ApprovalRequest | None = None
    tier2_promotion_evidence: Tier2PromotionEvidence | None = None
    tier2_eligible_actions: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class PolicyGateDecision:
    outcome: PolicyGateOutcome
    tenant_id: uuid.UUID | None
    requested_action: str
    requested_autonomy_tier: int
    reason: PolicyGateDenialReason | None
    decision_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        if self.outcome is PolicyGateOutcome.ALLOW and self.reason is not None:
            raise AssertionError("An ALLOW decision must not carry a denial reason.")
        if self.outcome is PolicyGateOutcome.DENY and self.reason is None:
            raise AssertionError("A DENY decision must carry a denial reason.")

    @property
    def is_allowed(self) -> bool:
        return self.outcome is PolicyGateOutcome.ALLOW


__all__ = [
    "AutonomyTier",
    "VALID_AUTONOMY_TIERS",
    "RequestedAction",
    "VALID_POLICY_GATE_ACTIONS",
    "PolicyGateOutcome",
    "PolicyGateDenialReason",
    "PolicyGateScope",
    "Tier2PromotionEvidence",
    "PolicyGateRequest",
    "PolicyGateDecision",
    # Re-exported for convenience -- a caller building a request needs
    # these to construct `learning_authorization_decision`/
    # `evaluation_comparison`.
    "LearningAuthorizationDecision",
    "LearningAuthorizationOutcome",
    "EvaluationComparison",
    "EvaluationOutcome",
    "ApprovalRequest",
]
