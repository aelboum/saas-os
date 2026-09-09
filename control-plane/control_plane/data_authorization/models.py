"""Typed request/decision/policy shapes for Data Authorization
(ADR-0013; docs/IMPLEMENTATION-ROADMAP.md Phase 9.2).

`DataClassification`'s three values deliberately mirror
`control_plane.orchestration.tools.ToolDefinition.data_classification`'s
existing vocabulary (`"none"` / `"tenant_data"` / `"sensitive"`,
docs/IMPLEMENTATION-ROADMAP.md Phase 7.1) rather than inventing a second,
competing taxonomy -- ADR-0013 itself defers finalizing a taxonomy
("no data-classification taxonomy is finalized... illustrative of what a
future taxonomy must consider, not fixed... adopted here"), and Phase
9.2's own Non-Goals repeat that: "no data-classification taxonomy
finalized beyond ADR-0013's existing scope." Reusing the one concrete,
already-Accepted three-value vocabulary this platform has is the
smallest coherent choice, not a new taxonomy.

No policy object here is persisted (no database table, no migration --
Phase 9.2's own Scope is "policy decision points and default-deny
enforcement; no learning logic itself"). `TenantAIDataPolicy` and
`ProviderEligibilityPolicy` are explicit, typed inputs the caller
supplies to `service.evaluate_data_authorization()` -- exactly like
`core.rbac.can()`'s `actor`/`action`/`resource` arguments are supplied by
the caller, not looked up ambiently by the function itself. A future
phase that needs a real, persisted, tenant-editable policy store builds
that against this same typed shape; this phase does not invent one
speculatively.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Literal

DataClassification = Literal["none", "tenant_data", "sensitive"]

VALID_DATA_CLASSIFICATIONS: frozenset[str] = frozenset({"none", "tenant_data", "sensitive"})


class DataAuthorizationOutcome(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class DataDenialReason(enum.StrEnum):
    """Every non-ALLOW branch `service.evaluate_data_authorization()` can
    take. Exhaustive by construction -- the evaluator's own tests assert
    every member here is reachable, so this enum cannot silently drift
    from the function's actual behavior."""

    UNCLASSIFIED_DATA = "unclassified_data"
    NO_TENANT_POLICY = "no_tenant_policy"
    DATA_CLASS_NOT_PERMITTED = "data_class_not_permitted"
    PURPOSE_NOT_PERMITTED = "purpose_not_permitted"
    PROVIDER_NOT_GLOBALLY_ELIGIBLE = "provider_not_globally_eligible"
    PROVIDER_NOT_PERMITTED = "provider_not_permitted"


@dataclass(frozen=True)
class ProviderEligibilityPolicy:
    """Platform-wide provider eligibility (ADR-0013 section 3: "provider
    trust is not equivalent across providers... policy-driven
    configuration, not a hardcoded trust assumption"). Not tenant-scoped
    -- a tenant's own `TenantAIDataPolicy.allowed_providers` narrows this
    further, never widens it (both must permit a provider for it to be
    eligible; see `service.evaluate_data_authorization`)."""

    eligible_providers: frozenset[str]


@dataclass(frozen=True)
class TenantAIDataPolicy:
    """A tenant's explicit AI data policy (ADR-0013 section 4: "Tenant ->
    AI Data Policy -> Allowed data classes / Allowed providers / Allowed
    use cases"). Absence of a policy for a tenant (`tenant_policy=None`
    at the call site) means exactly what ADR-0013 section 5 requires:
    "unclassified or unclassified sensitive data -> DENY" -- no implicit
    default-allow policy is ever synthesized."""

    tenant_id: uuid.UUID
    allowed_data_classifications: frozenset[str]
    allowed_purposes: frozenset[str]
    allowed_providers: frozenset[str]


@dataclass(frozen=True)
class DataAuthorizationRequest:
    """One request to cross the AI Data Privacy / External Model Boundary
    (docs/SECURITY.md section 6.1) for a single external-provider call.
    `resource_type`/`resource_id` are provenance only (e.g.
    `"support_ticket"`/`<id>`) -- never the data's own content; this
    module never receives or handles raw tenant data (ADR-0013 section 2,
    data minimization -- the boundary decides eligibility, it does not
    need the payload to do so)."""

    tenant_id: uuid.UUID
    data_classification: str
    purpose: str
    provider: str
    resource_type: str
    resource_id: str | None = None


@dataclass(frozen=True)
class DataAuthorizationDecision:
    outcome: DataAuthorizationOutcome
    tenant_id: uuid.UUID
    data_classification: str
    purpose: str
    provider: str
    reason: DataDenialReason | None
    decision_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        # Structural invariant, not input validation: a decision this
        # module itself constructs must never be ALLOW-with-a-reason or
        # DENY-with-no-reason -- catches a bug in service.py, not caller
        # error (docs/IMPLEMENTATION-ROADMAP.md Phase 9.2's "default deny
        # must be structurally obvious in the code").
        if self.outcome is DataAuthorizationOutcome.ALLOW and self.reason is not None:
            raise AssertionError("An ALLOW decision must not carry a denial reason.")
        if self.outcome is DataAuthorizationOutcome.DENY and self.reason is None:
            raise AssertionError("A DENY decision must carry a denial reason.")

    @property
    def is_allowed(self) -> bool:
        return self.outcome is DataAuthorizationOutcome.ALLOW
