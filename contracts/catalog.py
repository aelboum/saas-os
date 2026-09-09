"""Reference catalogs `contracts/schema.py`'s validator checks declared
contract fields against (docs/IMPLEMENTATION-ROADMAP.md Phase 6.1's own
Security Requirement: "a contract's declared `aiTools` and
`environmentVariables` are validated against the actual permission/
secret schemas available -- a contract cannot declare a tool or secret
it isn't authorized to reference").

Each catalog below reflects what actually exists in this repository as
of this phase (docs/IMPLEMENTATION-ROADMAP.md Phase 6.1's own
Dependencies note: "the contract references Core modules that must
exist to validate against") -- not an aspirational future list. A
catalog grows only when the corresponding phase actually ships the
module/service/tool it names; this file is never speculatively
pre-populated.
"""

from __future__ import annotations

# Every core/* module implemented through Phase 5.2 (docs/ARCHITECTURE.md
# section 3's own core/ subpackage list). `usage_events`'s own module is
# `core/usage`, so the catalog entry is the module name "usage", not the
# table name.
KNOWN_CORE_MODULES: frozenset[str] = frozenset(
    {
        "tenancy",
        "identity",
        "rbac",
        "audit_log",
        "api_keys",
        "feature_flags",
        "webhooks",
        "notifications",
        "billing",
        "usage",
    }
)

# Every infra/* subpackage implemented through Phase 5.2 (docs/
# ARCHITECTURE.md section 3's own infra/ subpackage list).
KNOWN_INFRASTRUCTURE_SERVICES: frozenset[str] = frozenset(
    {
        "db",
        "jobs",
        "observability",
        "health",
        "secrets",
        "deploy",
    }
)

# The AI Control Plane tool registry (docs/IMPLEMENTATION-ROADMAP.md
# Phase 7.1: "control-plane/orchestration -- agent runtime and tool
# registry mechanism") does not exist yet -- zero tools are registered.
# This deliberately-empty catalog is the correct, safe-default state: a
# contract declaring ANY `aiTools` entry today references a tool that
# does not exist, and validate_contract() rejects it (docs/AI-CONTROL-
# PLANE.md section 10: "a product that declares no aiTools is, by
# construction, unreachable by the Control Plane"). This catalog is
# expected to grow only once Phase 7.1 registers real tools -- never
# pre-populated speculatively.
KNOWN_AI_TOOLS: frozenset[str] = frozenset()
