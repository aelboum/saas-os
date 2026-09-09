"""SaaS Core.

Domain-agnostic business primitives (tenancy, identity, RBAC, billing, usage,
API keys, webhooks, notifications, audit log, feature flags). See
docs/ARCHITECTURE.md sections 1, 4-9.

Boundary rules (docs/ARCHITECTURE.md section 2, docs/ADR/0001-...):
- core MUST NOT import from `products` or `control_plane`.
- core MUST NOT import AI/LLM/agent frameworks.
- core MUST remain deterministic and functional with the AI Control Plane
  completely disabled.

Core owns a configuration schema (core/config, docs/ARCHITECTURE.md
section 7: each module owns the schema of the configuration it requires)
and, since Phase 3.1, its first business module: `core/tenancy` (tenant
entity and lifecycle, docs/MULTI-TENANCY.md). Identity, RBAC, billing, and
the other Core modules listed in docs/ARCHITECTURE.md section 4 are not
implemented yet. Per docs/IMPLEMENTATION-ROADMAP.md, the
application/routing/ingress-middleware layer belongs at Phase 8 (built
together with identity/RBAC); generic health/readiness endpoints belong to
`infra/health` (Phase 2.5); shared logging/tracing belongs to
`infra/observability` (Phase 2.2). None of those exist yet.
"""

CORE_MARKER = "core"
