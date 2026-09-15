"""The reference consumer's own AI Control Plane tool (ADR-0018).

Proves per-project, in-process tool registration against a project's own
`core.rbac`-registered permission (docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md
section 11: "each project registers its own tools... calling
core.rbac.register_permission() to declare the RBAC resource/action the
tool needs"). Tier 0 (direct invocation via
`control_plane.orchestration.invoke_tool()`, no approval step) and
`side_effect="read_only"` -- the simplest shape that still exercises the
real RBAC-authorization gate (`required_scope_type="tenant"`).

The handler reads through `reference_consumer.widgets.get_widget()` (the
fixture's one data-access function, PRIV-03 P12 / RA-08) with the tenant
the Control Plane already authorized (`ToolExecutionContext.tenant_id`),
never a tenant named in the payload; a widget of another tenant, or none
at all, is reported as `status: None` either way.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from control_plane.orchestration.tools import ToolDefinition, ToolExecutionContext
from reference_consumer.widgets import get_widget

TOOL_KEY = "reference_consumer.check_widget_status"
RESOURCE = "reference_consumer.widgets"
ACTION = "read"


async def _handler(
    context: ToolExecutionContext, payload: Mapping[str, object]
) -> dict[str, object]:
    widget_id = uuid.UUID(str(payload["widget_id"]))
    widget = get_widget(context.tenant_id, widget_id)
    return {"status": widget.status if widget is not None else None}


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
