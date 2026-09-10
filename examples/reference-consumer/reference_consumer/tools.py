"""The reference consumer's own AI Control Plane tool (ADR-0018).

Proves per-project, in-process tool registration against a project's own
`core.rbac`-registered permission (docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md
section 11: "each project registers its own tools... calling
core.rbac.register_permission() to declare the RBAC resource/action the
tool needs"). Tier 0 (direct invocation via
`control_plane.orchestration.invoke_tool()`, no approval step) and
`side_effect="read_only"` -- the simplest shape that still exercises the
real RBAC-authorization gate (`required_scope_type="tenant"`).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from sqlalchemy import text

from control_plane.orchestration.tools import ToolDefinition, ToolExecutionContext
from infra.db import tenant_session_scope

TOOL_KEY = "reference_consumer.check_widget_status"
RESOURCE = "reference_consumer.widgets"
ACTION = "read"


async def _handler(
    context: ToolExecutionContext, payload: Mapping[str, object]
) -> dict[str, object]:
    widget_id = uuid.UUID(str(payload["widget_id"]))
    with tenant_session_scope(context.tenant_id) as session:
        row = (
            session.execute(
                text("SELECT status FROM reference_consumer.widgets WHERE id = :id"),
                {"id": str(widget_id)},
            )
            .mappings()
            .first()
        )
    return {"status": row["status"] if row is not None else None}


def build_check_widget_status_tool() -> ToolDefinition:
    return ToolDefinition(
        key=TOOL_KEY,
        description="Check a reference-consumer widget's status.",
        handler=_handler,
        required_scope_type="tenant",
        required_resource=RESOURCE,
        required_action=ACTION,
        autonomy_tier=0,
        data_classification="tenant_data",
        side_effect="read_only",
    )
