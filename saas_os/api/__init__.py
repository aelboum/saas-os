"""`api` -- the external API ingress layer
(docs/IMPLEMENTATION-ROADMAP.md Phase 8: "First Real Routes and
End-to-End Wiring"; docs/API-ARCHITECTURE.md).

Layer placement (mirrors `saas_os/contracts/*`'s own Phase 6 precedent): a
standalone, cross-cutting top-level package, not nested under `core/`,
`infra/`, `control_plane/`, or `products/`. `docs/API-ARCHITECTURE.md`
section 2's own ownership table splits "auth/tenant-resolution/RBAC
middleware" (this package, reusing `saas_os.core.identity`/`saas_os.core.rbac`) from
"Core capability routes" (owned by each respective `saas_os/core/*` module, once
one exists) and "Product-specific routes" (owned by the Product) --
`api` is the composition root and shared middleware chokepoint every
route family passes through, never a container for business logic
itself.

Owns:
- `saas_os/api/dependencies.py` -- the enforced ingress chain (authentication ->
  tenant resolution -> rate limiting -> RBAC authorization), reusing
  `saas_os.core.identity`/`saas_os.core.rbac`/`saas_os.infra.ratelimit` entirely; no parallel
  identity or authorization model;
- `saas_os/api/context.py` -- the verified `RequestContext` every route handler
  receives;
- `saas_os/api/errors.py` -- stable, non-leaking HTTP error responses;
- `saas_os/api/platform.py` -- `build_platform_app()`, the minimal reusable
  application builder (docs/ADR/0017): FastAPI construction, `lifespan`
  (logging/tracing configuration, the RLS/database-role safety guard),
  `CorrelationIdMiddleware`, and the reusable default routers. A
  consuming project calls this to build its own application; it is the
  one thing in `api/` a consumer is meant to import as infrastructure
  rather than copy;
- `saas_os/api/main.py` -- this repository's own application composition root
  (not something a consuming project imports as its own app -- ADR-0017),
  built on top of `saas_os/api/platform.py`;
- `saas_os/api/health.py` -- infrastructure-only liveness/readiness routes
  (`GET /healthz`, `GET /readyz`; P1.8), outside the `saas_os.api.dependencies`
  chain and outside `/v1` (not part of the versioned external API);
- `saas_os/api/server.py` -- the production ASGI entrypoint (`uvicorn.run`,
  P1.8) for `saas_os.api.main.app`;
- `saas_os/api/v1/*` -- `GET /v1/tenants/{tenant_id}/status` (Phase 8.2), and
  the opt-in capability routers of docs/ADR/0040-... (members, invitations,
  a member's own API keys, billing, usage). None of them is mounted by
  `saas_os.api.platform.build_platform_app()`; a product registers the ones
  it wants.

Non-Goals (deliberately not built in this phase -- see
`saas_os/api/dependencies.py`'s own docstring for the fuller reasoning behind
each):
- API-key HTTP authentication (Phase 8.1's own Dependencies line lists
  only 3.2/3.3, not 4.1 `saas_os/core/api_keys`) -- session bearer tokens only.
- Any Core-capability route outside ADR-0040's approved set: webhook
  subscriptions, feature flags, tenant lifecycle, invitation acceptance,
  usage ingestion, audit-log query and the inbound billing-provider
  webhook have no route.
- Any AI Control Plane HTTP exposure -- Phase 8.1/8.2's own Objective,
  Tests, and Acceptance Criteria never mention exposing
  `saas_os.control_plane.orchestration`/`saas_os.control_plane.approvals` over HTTP;
  those remain in-process-only capabilities.
- Any Product-specific route (no product exists yet).
- Mutating routes in the default application: the one route
  `saas_os/api/main.py` mounts is read-only. The opt-in capability routers
  do mutate; each mutation is authorized and audited inside Core.
"""
