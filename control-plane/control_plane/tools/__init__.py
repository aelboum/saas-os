"""`control_plane.tools` -- explicit tool definitions, one bounded
capability per file (docs/ARCHITECTURE.md section 3: "explicit tool
definitions (each tool = one bounded capability)").

Everything an agent can possibly do is enumerable by reading this
package (docs/AI-CONTROL-PLANE.md section 2). As of Phase 9.4, three
tools exist: `open_pull_request.build_open_pull_request_tool()` (Phase
7.3); `activate_adaptation.build_activate_adaptation_tool()` and
`rollback_adaptation.build_rollback_adaptation_tool()` (Phase 9.4 --
the tier-1-only, `control_plane.approvals`-gated path into
`control_plane.self_learning.adaptive`'s own activation/rollback
transitions).
"""

from control_plane.tools.activate_adaptation import (
    TOOL_KEY as ACTIVATE_ADAPTATION_TOOL_KEY,
)
from control_plane.tools.activate_adaptation import build_activate_adaptation_tool
from control_plane.tools.open_pull_request import TOOL_KEY, build_open_pull_request_tool
from control_plane.tools.rollback_adaptation import (
    TOOL_KEY as ROLLBACK_ADAPTATION_TOOL_KEY,
)
from control_plane.tools.rollback_adaptation import build_rollback_adaptation_tool

__all__ = [
    "build_open_pull_request_tool",
    "TOOL_KEY",
    "build_activate_adaptation_tool",
    "ACTIVATE_ADAPTATION_TOOL_KEY",
    "build_rollback_adaptation_tool",
    "ROLLBACK_ADAPTATION_TOOL_KEY",
]
