"""The tier-1 tool that activates an L1 adaptation candidate
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.4).

`autonomy_tier=1` -- this tool can never be invoked directly through
`control_plane.orchestration.invoke_tool()`; it must be proposed through
`control_plane.approvals` and executed only once a human has approved it
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Dependencies: "7.2
...for anything above autonomy tier 0"). The handler itself performs no
authorization logic beyond `control_plane.orchestration`'s own
`core.rbac.can()` check (`required_scope_type="tenant"`) -- all of the
domain-specific safety checks (candidate status, evaluation outcome)
live in `control_plane.self_learning.adaptive.service.activate_adaptation()`,
which this handler calls into and nothing else.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from control_plane.orchestration.tools import ToolDefinition, ToolExecutionContext
from control_plane.self_learning.adaptive.service import activate_adaptation

TOOL_KEY = "self_learning.activate_adaptation"
REQUIRED_RESOURCE = "control_plane.self_learning.adaptation"
REQUIRED_ACTION = "activate"


async def _handler(
    context: ToolExecutionContext, payload: Mapping[str, object]
) -> dict[str, object]:
    adaptation_id = uuid.UUID(str(payload["adaptation_id"]))
    adaptation = activate_adaptation(
        context.tenant_id, adaptation_id, activated_by_user_id=context.agent_user_id
    )
    return {
        "adaptation_id": str(adaptation.id),
        "status": adaptation.status,
        "version": adaptation.version,
    }


def build_activate_adaptation_tool() -> ToolDefinition:
    return ToolDefinition(
        key=TOOL_KEY,
        description="Activate a previously-proposed, already-evaluated L1 adaptation candidate.",
        handler=_handler,
        required_scope_type="tenant",
        required_resource=REQUIRED_RESOURCE,
        required_action=REQUIRED_ACTION,
        autonomy_tier=1,
        data_classification="none",
        side_effect="mutating",
    )
