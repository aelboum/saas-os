"""`api` -- the external API ingress layer
(docs/IMPLEMENTATION-ROADMAP.md Phase 8: "First Real Routes and
End-to-End Wiring"; docs/API-ARCHITECTURE.md).

Layer placement (mirrors `contracts/*`'s own Phase 6 precedent): a
standalone, cross-cutting top-level package, not nested under `core/`,
`infra/`, `control_plane/`, or `products/`. `docs/API-ARCHITECTURE.md`
section 2's own ownership table splits "auth/tenant-resolution/RBAC
middleware" (this package, reusing `core.identity`/`core.rbac`) from
"Core capability routes" (owned by each respective `core/*` module, once
one exists) and "Product-specific routes" (owned by the Product) --
`api` is the composition root and shared middleware chokepoint every
route family passes through, never a container for business logic
itself.

Owns:
- `api/dependencies.py` -- the enforced ingress chain (authentication ->
  tenant resolution -> rate limiting -> RBAC authorization), reusing
  `core.identity`/`core.rbac`/`infra.ratelimit` entirely; no parallel
  identity or authorization model;
- `api/context.py` -- the verified `RequestContext` every route handler
  receives;
- `api/errors.py` -- stable, non-leaking HTTP error responses;
- `api/main.py` -- the FastAPI application composition root;
- `api/health.py` -- infrastructure-only liveness/readiness routes
  (`GET /healthz`, `GET /readyz`; P1.8), outside the `api.dependencies`
  chain and outside `/v1` (not part of the versioned external API);
- `api/server.py` -- the production ASGI entrypoint (`uvicorn.run`,
  P1.8) for `api.main.app`;
- `api/v1/*` -- the first (and, as of this phase, only) external route:
  `GET /v1/tenants/{tenant_id}/status` (Phase 8.2).

Non-Goals (deliberately not built in this phase -- see
`api/dependencies.py`'s own docstring for the fuller reasoning behind
each):
- API-key HTTP authentication (Phase 8.1's own Dependencies line lists
  only 3.2/3.3, not 4.1 `core/api_keys`) -- session bearer tokens only.
- Any Core-capability route beyond the one Phase 8.2 names (billing,
  api-keys, webhooks, feature-flags, audit-log query, etc. each get
  their own route family in a future phase with an actual tested need).
- Any AI Control Plane HTTP exposure -- Phase 8.1/8.2's own Objective,
  Tests, and Acceptance Criteria never mention exposing
  `control_plane.orchestration`/`control_plane.approvals` over HTTP;
  those remain in-process-only capabilities.
- Any Product-specific route (no product exists yet).
- Mutating/write routes (the one route this phase ships is read-only,
  matching its own Rollback Strategy: "this route carries no
  state-mutation risk").
"""
