"""The tier-1 tool that rolls an active L1 adaptation back to its
immediately-prior version (docs/IMPLEMENTATION-ROADMAP.md Phase 9.4).

Same tier-1/`control_plane.approvals`-only reachability as
`control_plane.tools.activate_adaptation` -- see that module's own
docstring. All domain logic lives in
`control_plane.self_learning.adaptive.service.rollback_adaptation()`.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from control_plane.orchestration.tools import ToolDefinition, ToolExecutionContext
from control_plane.self_learning.adaptive.service import rollback_adaptation

TOOL_KEY = "self_learning.rollback_adaptation"
REQUIRED_RESOURCE = "control_plane.self_learning.adaptation"
REQUIRED_ACTION = "rollback"


async def _handler(
    context: ToolExecutionContext, payload: Mapping[str, object]
) -> dict[str, object]:
    adaptation_id = uuid.UUID(str(payload["adaptation_id"]))
    reactivated = rollback_adaptation(
        context.tenant_id, adaptation_id, rolled_back_by_user_id=context.agent_user_id
    )
    return {
        "reactivated_adaptation_id": str(reactivated.id),
        "status": reactivated.status,
        "version": reactivated.version,
    }


def build_rollback_adaptation_tool() -> ToolDefinition:
    return ToolDefinition(
        key=TOOL_KEY,
        description="Roll an active L1 adaptation back to its immediately-prior version.",
        handler=_handler,
        required_scope_type="tenant",
        required_resource=REQUIRED_RESOURCE,
        required_action=REQUIRED_ACTION,
        autonomy_tier=1,
        data_classification="none",
        side_effect="mutating",
    )
