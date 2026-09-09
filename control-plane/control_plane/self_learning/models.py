"""Typed request/decision/policy/evidence shapes for Learning
Authorization (ADR-0014, Accepted; docs/IMPLEMENTATION-ROADMAP.md Phase
9.2).

`LearningEvidence` is the concrete shape of ADR-0014's "external input is
evidence, not trusted policy": it carries provenance about an untrusted
learning input (feedback, tool output, model output, external content)
but -- deliberately -- no field this package's evaluator (`service.py`)
reads to decide ALLOW/DENY. `source_reference` is a pointer/id, never raw
content (ADR-0013 section 2's data-minimization discipline, applied here
too: this module never receives or handles the tenant data itself, only
descriptors of it). See `service.py`'s own docstring and
`tests/control_plane/self_learning/test_learning_authorization_unit.py`
for the structural proof that evidence content cannot influence the
decision.

No policy object here is persisted -- same discipline as
`control_plane.data_authorization.models` (no database table, no
migration; `TenantLearningPolicy`/`CrossTenantLearningPolicy` are
explicit, caller-supplied inputs, not an ambient lookup). This
deliberately leaves the Learning Ledger (docs/IMPLEMENTATION-ROADMAP.md
Phase 9.1's conceptual lineage record) unimplemented -- Phase 9.2's own
Scope is "policy decision points and default-deny enforcement," and its
Files/Modules note does not list Ledger persistence.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Literal

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome

EvidenceType = Literal[
    "user_feedback",
    "operator_feedback",
    "tool_output",
    "external_content",
    "model_generated_content",
    "imported_learning_material",
    "evaluation_input",
]

VALID_EVIDENCE_TYPES: frozenset[str] = frozenset(
    {
        "user_feedback",
        "operator_feedback",
        "tool_output",
        "external_content",
        "model_generated_content",
        "imported_learning_material",
        "evaluation_input",
    }
)


class LearningAuthorizationOutcome(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class LearningDenialReason(enum.StrEnum):
    """Every non-ALLOW branch `service.evaluate_learning_authorization()`
    can take -- exhaustive by construction, see
    `control_plane.data_authorization.models.DataDenialReason`'s own
    docstring for why this matters."""

    DATA_AUTHORIZATION_NOT_PASSED = "data_authorization_not_passed"
    INVALID_EVIDENCE = "invalid_evidence"
    CROSS_TENANT_NOT_AUTHORIZED = "cross_tenant_not_authorized"
    NO_LEARNING_POLICY = "no_learning_policy"
    PURPOSE_NOT_PERMITTED = "purpose_not_permitted"
    MODEL_OR_PROVIDER_NOT_PERMITTED = "model_or_provider_not_permitted"
    RETENTION_NOT_PERMITTED = "retention_not_permitted"


@dataclass(frozen=True)
class LearningEvidence:
    """Provenance for an untrusted learning input -- evidence, never
    authorization input (ADR-0014 Decision, "External input is evidence,
    not trusted policy"). See module docstring."""

    evidence_type: EvidenceType
    source_reference: str


@dataclass(frozen=True)
class TenantLearningPolicy:
    """A tenant's explicit Learning Authorization policy (ADR-0014's own
    gate question: "for what purpose? for which tenant? for which
    model/provider? for how long?"). Absence of a policy for a tenant
    (`tenant_learning_policy=None` at the call site) means default DENY,
    identical in spirit to `TenantAIDataPolicy`'s absence in
    `control_plane.data_authorization`."""

    tenant_id: uuid.UUID
    allowed_purposes: frozenset[str]
    allowed_models_or_providers: frozenset[str]
    allowed_retentions: frozenset[str]


@dataclass(frozen=True)
class CrossTenantLearningPolicy:
    """An explicit, separately authorized policy permitting
    `source_tenant_id`'s data to become a learning input that influences
    `target_tenant_id` (ADR-0014 invariant 1 / docs/SECURITY.md section
    6.2 invariant 1). Its existence for one tenant pair authorizes
    nothing for any other pair -- `service.evaluate_learning_authorization`
    matches both ids exactly, never by inference."""

    source_tenant_id: uuid.UUID
    target_tenant_id: uuid.UUID
    approved_purposes: frozenset[str]


@dataclass(frozen=True)
class LearningAuthorizationRequest:
    """One request to retain/reuse data to shape future platform
    behavior (ADR-0014). `tenant_id` is the tenant whose data is the
    learning input; `cross_tenant_target_tenant_id`, when set to a value
    different from `tenant_id`, declares that this learning event is
    intended to influence a *different* tenant -- the specific case
    ADR-0014 invariant 1 requires an explicit authorized policy for."""

    tenant_id: uuid.UUID
    purpose: str
    target_model_or_provider: str
    retention: str
    evidence: LearningEvidence
    cross_tenant_target_tenant_id: uuid.UUID | None = None


@dataclass(frozen=True)
class LearningAuthorizationDecision:
    outcome: LearningAuthorizationOutcome
    tenant_id: uuid.UUID
    purpose: str
    reason: LearningDenialReason | None
    data_authorization_decision_id: uuid.UUID
    decision_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        if self.outcome is LearningAuthorizationOutcome.ALLOW and self.reason is not None:
            raise AssertionError("An ALLOW decision must not carry a denial reason.")
        if self.outcome is LearningAuthorizationOutcome.DENY and self.reason is None:
            raise AssertionError("A DENY decision must carry a denial reason.")

    @property
    def is_allowed(self) -> bool:
        return self.outcome is LearningAuthorizationOutcome.ALLOW


__all__ = [
    "EvidenceType",
    "VALID_EVIDENCE_TYPES",
    "LearningAuthorizationOutcome",
    "LearningDenialReason",
    "LearningEvidence",
    "TenantLearningPolicy",
    "CrossTenantLearningPolicy",
    "LearningAuthorizationRequest",
    "LearningAuthorizationDecision",
    # Re-exported for convenience -- Learning Authorization always
    # requires an upstream Data Authorization decision as an explicit
    # input (see service.py); callers building a request need both.
    "DataAuthorizationDecision",
    "DataAuthorizationOutcome",
]
