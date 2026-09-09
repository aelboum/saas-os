"""AI Control Plane.

Lets AI agents operate the platform and build it, only through explicitly
defined tools/interfaces against SaaS Core and Product modules. See
docs/AI-CONTROL-PLANE.md and docs/ADR/0004-ai-control-plane-tool-mediated-access.md.

Note on package naming: the top-level directory is `control-plane/` (matching
docs/ARCHITECTURE.md section 3), which is not a valid Python identifier.
The importable package therefore lives at `control-plane/control_plane/` and
is imported as `control_plane` (see pyproject.toml `[tool.setuptools]`
`package-dir` mapping).

Boundary rules (docs/ARCHITECTURE.md section 2, docs/ADR/0001-...,
docs/ADR/0004-...):
- control_plane MAY depend on `core` (through Core's public interfaces only).
- control_plane MUST NOT reach into Core or Product internals directly, only
  through explicitly declared tools (docs/AI-CONTROL-PLANE.md section 3) --
  not yet implemented in this phase.

No AI Control Plane modules (orchestration, tools, approvals, agents) are
implemented yet (Phase 1.1 is repository foundation only, per
docs/IMPLEMENTATION-ROADMAP.md Phase 1; agents are Phase 7+).
"""

from core import CORE_MARKER

CONTROL_PLANE_MARKER = "control_plane"

__all__ = ["CONTROL_PLANE_MARKER", "CORE_MARKER"]
