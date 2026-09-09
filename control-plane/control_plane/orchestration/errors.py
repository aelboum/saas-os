"""Typed errors for `control_plane.orchestration`
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.1). Every error here carries only
identifying metadata -- never a secret value, never a raw tool payload
that might carry tenant data.
"""

from __future__ import annotations


class InvalidToolDefinitionError(ValueError):
    """Raised by `register_tool()` when a `ToolDefinition` itself is
    malformed -- e.g. an empty key, a duplicate key, or an
    `autonomy_tier` of 3 (docs/AI-CONTROL-PLANE.md section 5: "No tool is
    ever created at tier 3 without a separate, explicit, documented human
    decision -- this document does not pre-authorize it for anything.").
    """


class ToolNotFoundError(LookupError):
    def __init__(self, tool_key: str) -> None:
        self.tool_key = tool_key
        super().__init__(f"No tool registered with key {tool_key!r}.")


class UnauthorizedToolInvocationError(PermissionError):
    """Raised when the invoking agent identity is not authorized to
    invoke a tool -- either `core.rbac.can()` denied the tenant-scoped
    permission check, or the agent's declared scope does not match the
    tool's required environment/repository scope. Deliberately carries no
    detail beyond the tool key: the caller already knows what it tried to
    invoke and as whom; this error is not a place to leak *why* in a way
    that helps an attacker refine a probe (mirrors
    `core/webhooks`/`core/notifications`'s own not-found-vs-denied
    non-disclosure convention)."""

    def __init__(self, tool_key: str) -> None:
        self.tool_key = tool_key
        super().__init__(f"Invocation of tool {tool_key!r} is not authorized.")


class UndeclaredSecretError(PermissionError):
    """Raised when a tool handler requests a secret name it did not
    declare in its own `ToolDefinition.declared_secrets`
    (docs/AI-CONTROL-PLANE.md section 3, "Tool Secrets Access")."""

    def __init__(self, tool_key: str, secret_name: str) -> None:
        self.tool_key = tool_key
        self.secret_name = secret_name
        super().__init__(
            f"Tool {tool_key!r} requested secret {secret_name!r}, which it did not declare."
        )


class TierRequiresApprovalError(PermissionError):
    """Raised when `invoke_tool()` is called directly against a tool
    whose `autonomy_tier >= 1` -- such a tool must be executed through
    `control_plane.approvals`' propose/approve workflow, never invoked
    directly (docs/AI-CONTROL-PLANE.md section 5: tier 1 = "propose +
    approval")."""

    def __init__(self, tool_key: str, tier: int) -> None:
        self.tool_key = tool_key
        self.tier = tier
        super().__init__(
            f"Tool {tool_key!r} is autonomy tier {tier} and must be executed through "
            "control_plane.approvals, not invoked directly."
        )


class DataAuthorizationRequiredError(PermissionError):
    """Raised when a tool declaring `ToolDefinition.requires_data_authorization
    = True` is invoked without a caller-supplied `DataAuthorizationDecision`
    that is an `ALLOW` for the invocation's own `tenant_id` -- either no
    decision was supplied, the decision belongs to a different tenant, or
    the decision itself is a `DENY` (docs/AI-CONTROL-PLANE.md section 2.1).

    Deliberately a distinct type from `UnauthorizedToolInvocationError`:
    Tool Authorization (`core.rbac.can()` / agent scope) and Data
    Authorization (ADR-0013) are independent gates -- this error identifies
    *which* gate rejected the invocation, it does not collapse the two.
    Carries no detail beyond the tool key, for the same non-disclosure
    reason `UnauthorizedToolInvocationError` does."""

    def __init__(self, tool_key: str) -> None:
        self.tool_key = tool_key
        super().__init__(
            f"Invocation of tool {tool_key!r} requires an ALLOW Data Authorization "
            "decision for this tenant, and none was supplied."
        )


class ToolExecutionError(RuntimeError):
    """Raised when a tool's own handler raises during execution --
    wrapped so callers see a stable, typed failure mode regardless of
    what a specific handler's implementation raises internally."""

    def __init__(self, tool_key: str, reason: str) -> None:
        self.tool_key = tool_key
        super().__init__(f"Tool {tool_key!r} execution failed: {reason}")
