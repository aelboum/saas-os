"""Tool invocation: authorization, secret injection, sandboxing, and audit
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.1).

`invoke_tool()` is the single entrypoint a caller (a stub in this phase;
a real agent runtime in a later one) uses to invoke a registered tool.
Every invocation -- allowed or denied -- produces exactly one
`core.audit_log` entry (Phase 7.1's own Acceptance Criteria), using
`ActorType.USER` (the invoking agent's own `core.identity.User` row --
`core/audit_log/models.py`'s own docstring: "a core.identity User (human
or an AI agent)", no separate actor type needed).

Authorization is two independent checks, corresponding to `ToolDefinition
.required_scope_type`:

- `"tenant"` -- delegates to `core.rbac.authorization.can()`, the exact
  chokepoint that module's own docstring names as this phase's intended
  caller ("a future Control-Plane tool invocation (Phase 7) can call the
  exact same function and get the exact same answer"). No parallel
  policy engine is built here; this *is* the Tool Policy Engine.
- `"environment"` / `"repository"` -- no tenant-permission model applies
  (docs/AI-CONTROL-PLANE.md section 7: an agent's scope may be "an
  environment ... or a repository", not only a tenant); authorization is
  an exact match between the invoking agent's own declared
  `agent_scope_value` and the tool's `required_scope_value` -- "A tool
  invocation outside an agent's declared scope is rejected at the
  authorization layer, independent of whether the tool itself would
  technically permit it" (same section).

`tenant_id` is a required parameter on every call regardless of a tool's
scope type -- not because every tool acts on tenant data, but because
`core.audit_log.record()` itself requires a real `tenant_id` on every
row (`core/audit_log/models.py`'s own docstring: "Phase 3.4 does not
implement a separate global/system (tenant-less) audit table ... if
global audit events are not required, do not invent them"). A
repository-scoped tool's invocation is still audited *within* whichever
tenant's operational context the caller is acting under -- exactly the
same "system actor acting within a tenant, not a tenant-less event"
shape that module already documents for `ActorType.SYSTEM`. This module
introduces no new tenant-less audit mechanism.

Tier enforcement (docs/AI-CONTROL-PLANE.md section 5): `invoke_tool()`
refuses to execute any tool whose `autonomy_tier >= 1` -- such a tool
must be proposed through `control_plane.approvals` instead. The
approvals module executes an *approved* tier-1 tool through
`_execute_tool()` below, which is not exported from this package's
public API (`control_plane/orchestration/__init__.py`) and is the only
sanctioned way to bypass the tier-1 direct-invocation refusal.

Data Authorization (docs/AI-CONTROL-PLANE.md section 2.1, ADR-0013): a
tool declaring `ToolDefinition.requires_data_authorization = True` may
only reach its own handler once a caller-supplied
`control_plane.data_authorization.DataAuthorizationDecision` -- already
produced by that module's own audited `authorize_data_access()` -- is an
`ALLOW` for the exact same `tenant_id` as the invocation. This module
never calls `authorize_data_access()` itself: Data Authorization is a
second, independent gate (never a proxy for Tool Authorization or vice
versa), its own audited decision is computed once by the caller, and
`_execute_tool()` only *checks* that decision, so its allow/deny audit
write is never duplicated here -- a denial at this gate is recorded the
same way every other `_execute_tool()` denial already is, one
`control_plane.tool_invocation` entry via `_audit()` below.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.orchestration.errors import (
    DataAuthorizationRequiredError,
    TierRequiresApprovalError,
    ToolExecutionError,
    UnauthorizedToolInvocationError,
)
from control_plane.orchestration.tools import (
    ToolDefinition,
    ToolExecutionContext,
    ToolRegistry,
    default_registry,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.rbac import can as rbac_can

_AUDIT_RESOURCE_TYPE = "control_plane_tool"


@dataclass(frozen=True)
class ToolInvocationResult:
    tool_key: str
    correlation_id: str
    output: dict[str, object]


def _is_authorized(
    tool: ToolDefinition,
    *,
    agent_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    agent_scope_value: str | None,
) -> bool:
    if tool.required_scope_type == "tenant":
        assert tool.required_resource is not None
        assert tool.required_action is not None
        return rbac_can(
            actor_id=agent_user_id,
            tenant_id=tenant_id,
            action=tool.required_action,
            resource=tool.required_resource,
        )
    # environment / repository scope: exact match against the agent's own
    # declared scope, never a tenant-permission lookup.
    return agent_scope_value is not None and agent_scope_value == tool.required_scope_value


def _data_authorization_satisfied(
    decision: DataAuthorizationDecision | None, *, tenant_id: uuid.UUID
) -> bool:
    """`ToolDefinition.requires_data_authorization` tools may proceed only
    when a caller-supplied decision exists, belongs to this exact
    `tenant_id` (a decision computed for a different tenant -- forged or
    genuine -- never authorizes this invocation), and is itself an
    `ALLOW`. This function never computes a decision itself -- it never
    calls `control_plane.data_authorization.authorize_data_access()` --
    reusing the same caller-supplied, typed-composition trust model
    `control_plane.self_learning.policy_gate.service.evaluate_policy_gate()`
    already uses for `approval`/`learning_authorization_decision`: the
    decision is opaque policy input this module only *checks*, it does not
    *derive*, so `authorize_data_access()`'s own audit write (allow or
    deny) is never duplicated here."""
    return (
        decision is not None
        and decision.tenant_id == tenant_id
        and decision.outcome is DataAuthorizationOutcome.ALLOW
    )


def _audit(
    *,
    tenant_id: uuid.UUID,
    agent_user_id: uuid.UUID,
    tool_key: str,
    outcome: AuditOutcome,
    correlation_id: str,
    extra_metadata: dict[str, object] | None = None,
) -> None:
    metadata: dict[str, object] = {"tool_key": tool_key}
    if extra_metadata:
        metadata.update(extra_metadata)
    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=agent_user_id,
        action="control_plane.tool_invocation",
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=tool_key,
        outcome=outcome,
        correlation_id=correlation_id,
        metadata=metadata,
    )


async def _execute_tool(
    tool_key: str,
    *,
    agent_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    agent_scope_value: str | None = None,
    payload: Mapping[str, object] | None = None,
    registry: ToolRegistry | None = None,
    data_authorization_decision: DataAuthorizationDecision | None = None,
) -> ToolInvocationResult:
    """The actual authorize-then-execute path, shared by `invoke_tool()`
    (tier 0 only) and `control_plane.approvals` (any tier, once already
    approved). Never call this directly for a tier>=1 tool outside the
    approvals module -- see module docstring.

    Check order for a tool declaring `requires_data_authorization=True`:
    Tool Authorization (`_is_authorized`, RBAC/scope) first, then Data
    Authorization (`_data_authorization_satisfied`), and only then the
    tool's own handler -- so no external-provider call is reachable until
    both gates have independently passed (docs/AI-CONTROL-PLANE.md section
    2.1: passing one gate never implies the other does). For a tier>=1
    tool this function is only ever reached *after*
    `control_plane.approvals.execute_approved()`'s own approval-status
    check, so the full order is RBAC -> approval -> Data Authorization ->
    handler, matching the ordering `control_plane.self_learning
    .policy_gate` already established for tier-specific approval checks
    relative to upstream authority composition."""
    active_registry = registry or default_registry()
    correlation_id = str(uuid.uuid4())
    payload = payload or {}

    tool = active_registry.get(tool_key)  # raises ToolNotFoundError -- not audited (no tool means
    # nothing to attribute the attempt to as a real invocation; the
    # roadmap's own Acceptance Criteria only requires an audit entry for
    # an actual invocation, allowed or denied, of a *registered* tool)

    if not _is_authorized(
        tool, agent_user_id=agent_user_id, tenant_id=tenant_id, agent_scope_value=agent_scope_value
    ):
        _audit(
            tenant_id=tenant_id,
            agent_user_id=agent_user_id,
            tool_key=tool_key,
            outcome=AuditOutcome.DENIED,
            correlation_id=correlation_id,
        )
        raise UnauthorizedToolInvocationError(tool_key)

    if tool.requires_data_authorization and not _data_authorization_satisfied(
        data_authorization_decision, tenant_id=tenant_id
    ):
        _audit(
            tenant_id=tenant_id,
            agent_user_id=agent_user_id,
            tool_key=tool_key,
            outcome=AuditOutcome.DENIED,
            correlation_id=correlation_id,
            extra_metadata={"denied_gate": "data_authorization"},
        )
        raise DataAuthorizationRequiredError(tool_key)

    context = ToolExecutionContext(
        tool_key=tool_key,
        declared_secrets=tool.declared_secrets,
        agent_user_id=agent_user_id,
        tenant_id=tenant_id,
        agent_scope_value=agent_scope_value,
        correlation_id=correlation_id,
    )

    try:
        output = await tool.handler(context, payload)
    except Exception as exc:
        _audit(
            tenant_id=tenant_id,
            agent_user_id=agent_user_id,
            tool_key=tool_key,
            outcome=AuditOutcome.FAILURE,
            correlation_id=correlation_id,
        )
        raise ToolExecutionError(tool_key, type(exc).__name__) from exc

    _audit(
        tenant_id=tenant_id,
        agent_user_id=agent_user_id,
        tool_key=tool_key,
        outcome=AuditOutcome.SUCCESS,
        correlation_id=correlation_id,
    )
    return ToolInvocationResult(tool_key=tool_key, correlation_id=correlation_id, output=output)


async def invoke_tool(
    tool_key: str,
    *,
    agent_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    agent_scope_value: str | None = None,
    payload: Mapping[str, object] | None = None,
    registry: ToolRegistry | None = None,
    data_authorization_decision: DataAuthorizationDecision | None = None,
) -> ToolInvocationResult:
    """Invoke a registered tier-0 tool directly. Raises
    `TierRequiresApprovalError` for any tool with `autonomy_tier >= 1` --
    such a tool must be proposed via `control_plane.approvals` instead
    (docs/AI-CONTROL-PLANE.md section 5). `data_authorization_decision` is
    required (and checked against this same `tenant_id`) only for a tool
    declaring `requires_data_authorization=True` -- see `_execute_tool()`;
    ignored entirely for every other tool, which never had a Data
    Authorization requirement to satisfy."""
    active_registry = registry or default_registry()
    tool = active_registry.get(tool_key)
    if tool.autonomy_tier >= 1:
        raise TierRequiresApprovalError(tool_key, tool.autonomy_tier)

    return await _execute_tool(
        tool_key,
        agent_user_id=agent_user_id,
        tenant_id=tenant_id,
        agent_scope_value=agent_scope_value,
        payload=payload,
        registry=registry,
        data_authorization_decision=data_authorization_decision,
    )
