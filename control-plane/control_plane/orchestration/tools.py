"""The Tool Registry (docs/IMPLEMENTATION-ROADMAP.md Phase 7.1;
docs/AI-CONTROL-PLANE.md section 3: "A tool is the atomic unit of AI
Control Plane capability").

A `ToolDefinition` is pure, in-process registration metadata -- there is
no database table for "tools" (mirrors `infra/jobs`'s own
`register_job()`: a job/tool is fundamentally code, not data). Zero
tools are registered by this module itself (docs/IMPLEMENTATION-ROADMAP.md
Phase 7.1's own Objective: "with zero tools registered yet") --
`control_plane/tools/*` is where real tool definitions live, registered
explicitly at process start.

`ToolRegistry` is an explicit class, not a bare module-level dict, so
tests can construct an isolated registry instead of mutating shared
global state across test runs (mirrors `infra/jobs/config.py::JobsConfig`'s
own "explicit config object, injectable, never ambient global state"
convention). A module-level `default_registry()` is provided for the one
real, long-lived registry a running process uses.

`register_tool()` enforces, structurally, the two hard constraints
`docs/AI-CONTROL-PLANE.md` section 5 states in prose:

- **No tier 3.** "No tool is ever created at tier 3 without a separate,
  explicit, documented human decision -- this document does not
  pre-authorize it for anything." No such decision exists anywhere in
  this repository, so `register_tool()` itself refuses tier 3 -- default
  deny at the registration boundary, not merely documented policy.
- **No arbitrary/dynamic tool.** "No arbitrary dynamically supplied tool
  may become executable merely because an LLM requested it" -- a tool
  can only ever become invocable by a call to `register_tool()` with a
  concrete `ToolDefinition` at process-start/import time; nothing in
  `control_plane.orchestration` accepts a tool definition, key, or
  handler as caller-supplied runtime input.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from control_plane.orchestration.errors import (
    InvalidToolDefinitionError,
    ToolNotFoundError,
    UndeclaredSecretError,
)
from infra.secrets import get_secrets_provider

ScopeType = Literal["tenant", "environment", "repository"]

_MAX_TIER = 2  # tier 3 is never permitted by this registry -- see module docstring
_VALID_SCOPE_TYPES: frozenset[str] = frozenset({"tenant", "environment", "repository"})
_VALID_DATA_CLASSIFICATIONS: frozenset[str] = frozenset({"none", "tenant_data", "sensitive"})
_VALID_SIDE_EFFECTS: frozenset[str] = frozenset({"read_only", "mutating"})


class ToolExecutionContext:
    """Passed to a tool handler at invocation time. `get_secret()` is the
    *only* way a handler reaches `infra.secrets` -- it never receives a
    `SecretsProvider` handle directly, and it can only ever resolve a
    secret name the tool's own `ToolDefinition.declared_secrets`
    enumerates (docs/AI-CONTROL-PLANE.md section 3, "Tool Secrets
    Access"). Requesting an undeclared name raises `UndeclaredSecretError`
    -- this is enforced here, not by convention in each handler.
    """

    def __init__(
        self,
        *,
        tool_key: str,
        declared_secrets: frozenset[str],
        agent_user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        agent_scope_value: str | None,
        correlation_id: str,
    ) -> None:
        self.tool_key = tool_key
        self.agent_user_id = agent_user_id
        self.tenant_id = tenant_id
        self.agent_scope_value = agent_scope_value
        self.correlation_id = correlation_id
        self._declared_secrets = declared_secrets

    def get_secret(self, name: str) -> str:
        if name not in self._declared_secrets:
            raise UndeclaredSecretError(self.tool_key, name)
        return get_secrets_provider().get_required(name)


ToolHandler = Callable[[ToolExecutionContext, Mapping[str, object]], Awaitable[dict[str, object]]]


@dataclass(frozen=True)
class ToolDefinition:
    """Explicit tool metadata (docs/AI-CONTROL-PLANE.md section 3's own
    list). Every field below maps directly to one bullet in that list:
    `key` (stable identifier), `description`, `handler` (the bounded
    action itself), `required_resource`/`required_action` (RBAC
    permission, tenant-scoped tools only), `required_scope_type`/
    `required_scope_value` (allowed/tenant scope), `declared_secrets`
    (Tool Secrets Access), `autonomy_tier` (section 5), `data_classification`
    and `side_effect` (risk/audit signal).

    `requires_data_authorization` declares, at registration time, whether
    this tool hands data to an external AI/LLM provider (section 2.1's
    Data Policy gate, ADR-0013). Source-defined -- set only by the
    `ToolDefinition` a deployer registers at process start, never by a
    runtime tool `payload`, so an invoking agent can never elevate a tool
    into (or out of) the Data Authorization gate merely by shaping its own
    call. Deny-by-default (`False`) unless a tool explicitly opts in.
    `control_plane.orchestration.service._execute_tool()` refuses to run
    such a tool's handler unless a caller-supplied
    `DataAuthorizationDecision` (already produced by
    `control_plane.data_authorization.authorize_data_access()`) is an
    `ALLOW` for this same `tenant_id`.
    """

    key: str
    description: str
    handler: ToolHandler
    required_scope_type: ScopeType
    required_resource: str | None = None
    required_action: str | None = None
    required_scope_value: str | None = None
    declared_secrets: frozenset[str] = field(default_factory=frozenset)
    autonomy_tier: int = 1
    data_classification: str = "none"
    side_effect: str = "mutating"
    requires_data_authorization: bool = False


class ToolRegistry:
    """An in-process registry of `ToolDefinition`s. See module docstring
    for why this is not a database table."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> ToolDefinition:
        if not definition.key or not definition.key.strip():
            raise InvalidToolDefinitionError("Tool key must be a non-empty string.")
        if definition.key in self._tools:
            raise InvalidToolDefinitionError(f"Tool key {definition.key!r} is already registered.")
        if definition.autonomy_tier < 0 or definition.autonomy_tier > _MAX_TIER:
            raise InvalidToolDefinitionError(
                f"Tool {definition.key!r} declares autonomy_tier={definition.autonomy_tier}; "
                f"only tiers 0-{_MAX_TIER} may be registered (tier 3 requires a separate, "
                "explicit, documented human decision -- docs/AI-CONTROL-PLANE.md section 5)."
            )
        if definition.required_scope_type not in _VALID_SCOPE_TYPES:
            raise InvalidToolDefinitionError(
                f"Tool {definition.key!r} declares an unknown required_scope_type "
                f"{definition.required_scope_type!r}."
            )
        if definition.required_scope_type == "tenant":
            if not definition.required_resource or not definition.required_action:
                raise InvalidToolDefinitionError(
                    f"Tool {definition.key!r} is tenant-scoped and must declare "
                    "required_resource and required_action for the core.rbac.can() check."
                )
        elif not definition.required_scope_value or not definition.required_scope_value.strip():
            raise InvalidToolDefinitionError(
                f"Tool {definition.key!r} is {definition.required_scope_type}-scoped and must "
                "declare a non-empty required_scope_value."
            )
        if definition.data_classification not in _VALID_DATA_CLASSIFICATIONS:
            raise InvalidToolDefinitionError(
                f"Tool {definition.key!r} declares an unknown data_classification "
                f"{definition.data_classification!r}."
            )
        if definition.side_effect not in _VALID_SIDE_EFFECTS:
            raise InvalidToolDefinitionError(
                f"Tool {definition.key!r} declares an unknown side_effect "
                f"{definition.side_effect!r}."
            )

        self._tools[definition.key] = definition
        return definition

    def get(self, tool_key: str) -> ToolDefinition:
        tool = self._tools.get(tool_key)
        if tool is None:
            raise ToolNotFoundError(tool_key)
        return tool

    def list(self) -> list[ToolDefinition]:
        return list(self._tools.values())


_default_registry = ToolRegistry()


def default_registry() -> ToolRegistry:
    """The one long-lived registry a real process uses. Tests construct
    their own `ToolRegistry()` instead of mutating this singleton, so a
    stub tool registered by one test can never leak into another."""
    return _default_registry
