"""`control_plane.orchestration` -- the Tool Registry and invocation
mechanism (docs/IMPLEMENTATION-ROADMAP.md Phase 7.1;
docs/AI-CONTROL-PLANE.md section 3).

Owns:
- `ToolDefinition`/`ToolRegistry`/`register_tool`-equivalent
  (`ToolRegistry.register`) -- explicit, in-process tool registration;
  zero tools registered by this module itself (see `tools.py`'s own
  docstring for why there is no database table);
- `ToolExecutionContext` -- the scoped secrets-injection path
  (docs/AI-CONTROL-PLANE.md section 3, "Tool Secrets Access",
  docs/ADR/0012-secrets-management.md);
- `invoke_tool()` -- the tier-0 direct-invocation entrypoint; every
  invocation (allowed or denied) is audit-logged through
  `core.audit_log`.

Does NOT own: business logic of any specific tool (that lives under
`control_plane/tools/*`); authorization policy itself (delegates to
`core.rbac.can()` for tenant-scoped tools -- this module is the *caller*
of the Policy Engine, not a second one); the human approval workflow for
tier>=1 tools (`control_plane.approvals`); any AI/LLM model or agent
runtime (docs/AI-CONTROL-PLANE.md section 8 -- an open decision, not
needed by this phase: every test here invokes a plain Python stub
handler directly, exactly as a real agent runtime would call a tool,
without this module ever calling an external model itself).

`control_plane.orchestration` depends on `core.identity` (agent identity
*is* a `core.identity.User` row -- no separate machine-identity schema is
introduced; `core/audit_log/models.py`'s own `ActorType.USER` docstring:
"a core.identity User (human or an AI agent)"), `core.rbac` (the
Policy Engine), `core.audit_log` (the Audit boundary), and `infra.secrets`
(Tool Secrets Access) -- all through their published interfaces, never
their ORM internals (docs/ARCHITECTURE.md section 2's own dependency
rule: "AI Control Plane -- depends on --> SaaS Core (abstractions)").
"""

from control_plane.orchestration.errors import (
    DataAuthorizationRequiredError,
    InvalidToolDefinitionError,
    TierRequiresApprovalError,
    ToolExecutionError,
    ToolNotFoundError,
    UnauthorizedToolInvocationError,
    UndeclaredSecretError,
)
from control_plane.orchestration.service import ToolInvocationResult, invoke_tool
from control_plane.orchestration.tools import (
    ToolDefinition,
    ToolExecutionContext,
    ToolRegistry,
    default_registry,
)

__all__ = [
    "ToolDefinition",
    "ToolExecutionContext",
    "ToolRegistry",
    "default_registry",
    "invoke_tool",
    "ToolInvocationResult",
    "InvalidToolDefinitionError",
    "ToolNotFoundError",
    "UnauthorizedToolInvocationError",
    "UndeclaredSecretError",
    "TierRequiresApprovalError",
    "ToolExecutionError",
    "DataAuthorizationRequiredError",
]
