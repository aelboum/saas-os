"""SaaS Core.

Domain-agnostic business primitives (tenancy, identity, RBAC, billing, usage,
API keys, webhooks, notifications, audit log, feature flags). See
docs/ARCHITECTURE.md sections 1, 4-9.

Boundary rules (docs/ARCHITECTURE.md section 2, docs/ADR/0001-...):
- core MUST NOT import from `products` or `control_plane`.
- core MUST NOT import AI/LLM/agent frameworks.
- core MUST remain deterministic and functional with the AI Control Plane
  completely disabled.

Core owns a configuration schema (saas_os/core/config, docs/ARCHITECTURE.md
section 7: each module owns the schema of the configuration it requires).
Per docs/IMPLEMENTATION-ROADMAP.md (Phases 3-5), Core's business modules are
implemented: `saas_os/core/tenancy` (tenant entity and lifecycle,
docs/MULTI-TENANCY.md), `saas_os/core/identity` (users, sessions, OIDC),
`saas_os/core/rbac` (authorization/scope/delegation), `saas_os/core/audit_log`,
`saas_os/core/api_keys`, `saas_os/core/feature_flags`, `saas_os/core/webhooks`,
`saas_os/core/notifications`,
`saas_os/core/billing`, and `saas_os/core/usage`. The application/routing/ingress-middleware
layer (Phase 8) lives in `api/`; generic health/readiness endpoints are
`saas_os/infra/health` (Phase 2.5); shared logging/tracing is
`saas_os/infra/observability` (Phase 2.2).
"""

CORE_MARKER = "core"
