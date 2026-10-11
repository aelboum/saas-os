"""AI Control Plane.

Lets AI agents operate the platform and build it, only through explicitly
defined tools/interfaces against SaaS Core and Product modules. See
docs/AI-CONTROL-PLANE.md and docs/ADR/0004-ai-control-plane-tool-mediated-access.md.

Note on package naming: the top-level directory is `control-plane/` (matching
docs/ARCHITECTURE.md section 3), which is not a valid Python identifier.
The importable package therefore lives at `saas_os/control_plane/` and
is imported as `control_plane` (see pyproject.toml `[tool.setuptools]`
`package-dir` mapping).

Boundary rules (docs/ARCHITECTURE.md section 2, docs/ADR/0001-...,
docs/ADR/0004-...):
- control_plane MAY depend on `core` (through Core's public interfaces only).
- control_plane MUST NOT reach into Core or Product internals directly, only
  through explicitly declared tools (docs/AI-CONTROL-PLANE.md section 3),
  implemented by `saas_os.control_plane.orchestration`'s tool registry.

Per docs/IMPLEMENTATION-ROADMAP.md (Phases 7 and 9), the AI Control Plane is
implemented: `saas_os.control_plane.orchestration` (tool registry/invocation),
`saas_os.control_plane.approvals` (propose/approve/execute gate),
`saas_os.control_plane.development` (GitHub PR-proposal tool),
`saas_os.control_plane.data_authorization` (ADR-0013 data policy gate), and
`saas_os.control_plane.self_learning` (evaluation, adaptive learning, system
learning, experiments, policy gate, autonomous improvement, continuous
improvement loop -- recovered Phase 9.1-9.9 specification).
"""

from saas_os.core import CORE_MARKER

CONTROL_PLANE_MARKER = "control_plane"

__all__ = ["CONTROL_PLANE_MARKER", "CORE_MARKER"]
