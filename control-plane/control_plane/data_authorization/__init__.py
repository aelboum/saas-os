"""`control_plane.data_authorization` -- the AI Data Privacy / External
Model Boundary (ADR-0013, Accepted; docs/SECURITY.md section 6.1;
docs/AI-CONTROL-PLANE.md section 2.1; docs/IMPLEMENTATION-ROADMAP.md
Phase 9.2).

Answers exactly one question, independent of Tool Authorization
(ADR-0004, `control_plane.orchestration`) and Learning Authorization
(ADR-0014, `control_plane.self_learning.authorization`): **may this data
reach an external AI/LLM provider, for this one call?** Passing this gate
never implies either of the other two gates passes, and passing either
of the other two never implies this one does (docs/AI-CONTROL-PLANE.md
section 2.1's diagram).

Layer: AI Control Plane, per docs/ARCHITECTURE.md sections 1-2 -- not
tenant-specific to `products/*`, not `core` (Core must remain usable
with the AI Control Plane disabled; this module is never imported by
`core`, enforced by the existing "Core does not depend on Products or
the AI Control Plane" import-linter contract, whose `forbidden_modules`
already includes the whole `control_plane` package, not just its
previously-existing submodules).

Owns:
- `DataAuthorizationRequest` / `DataAuthorizationDecision` / the
  `DataDenialReason` taxonomy (`models.py`);
- `TenantAIDataPolicy` / `ProviderEligibilityPolicy` -- typed policy
  *input* shapes (ADR-0013 section 4), not a persisted policy store (no
  table, no migration -- Phase 9.2's own Scope: "policy decision points
  and default-deny enforcement; no learning logic itself");
- `evaluate_data_authorization()` -- the pure, default-deny decision
  function;
- `authorize_data_access()` -- the audited entrypoint (`service.py`).

Does NOT own: Tool Authorization (`control_plane.orchestration`,
`core.rbac`), Learning Authorization (`control_plane.self_learning`),
audit-log persistence (`core.audit_log` -- this module only calls its
published `record()` interface), any external-provider SDK/client (no
provider call exists anywhere in this module -- Phase 9.2's own scope
explicitly excludes it), or `infra.secrets` access (no secret is needed
to decide eligibility).
"""

from control_plane.data_authorization.models import (
    VALID_DATA_CLASSIFICATIONS,
    DataAuthorizationDecision,
    DataAuthorizationOutcome,
    DataAuthorizationRequest,
    DataClassification,
    DataDenialReason,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
)
from control_plane.data_authorization.service import (
    authorize_data_access,
    evaluate_data_authorization,
)

__all__ = [
    "DataClassification",
    "VALID_DATA_CLASSIFICATIONS",
    "DataAuthorizationOutcome",
    "DataDenialReason",
    "ProviderEligibilityPolicy",
    "TenantAIDataPolicy",
    "DataAuthorizationRequest",
    "DataAuthorizationDecision",
    "evaluate_data_authorization",
    "authorize_data_access",
]
