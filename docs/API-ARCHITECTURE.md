# API Architecture

Status: ACCEPTED. Style and versioning finalized per `docs/ADR/0006-api-style-and-versioning.md`.

## 1. API Surfaces

Two structurally distinct surfaces, kept separate even where implementation code is shared:

- **Internal API** — how Core, Infra, Product, and the AI Control Plane call each other within the platform. Stability contract: internal, can evolve faster, but still versioned (see §4) because Product and Control Plane code depend on it.
- **External API** — what tenants, their end users, and third-party integrations call. Stability contract: must be strictly versioned and backward-compatible per its published guarantees, since external consumers cannot be forced to upgrade on the platform's schedule.

## 2. API Ownership

| Surface | Owner | Notes |
|---|---|---|
| Auth, tenant resolution, RBAC evaluation | `saas_os/core/identity`, `saas_os/core/rbac` | Enforced by the `saas_os/api/dependencies.py` dependency chain. Every route must declare exactly one route policy (permission, platform permission, authenticated, or explicitly public with a reason), checked at application startup — an undeclared route makes the application refuse to start ([ADR-0030](ADR/0030-foundation-enforcement.md)) |
| Core capability routes (members, invitations, API keys, billing, usage) | `saas_os/api/v1/` — opt-in routers over the respective `saas_os/core/*` module, which owns the capability but no HTTP surface | Mounted only by a product that registers them (`docs/ADR/0040-...`); one module per route family. Webhook subscriptions and the query of a tenant's own audit log have no route. Tenant lifecycle and feature flags are platform operations (next row); a tenant's own suspension is the opt-in `tenant_suspension_router` |
| Platform administration (tenant registry and lifecycle, users and credentials, feature flags, commercial overview, platform audit, operators and grants) | `saas_os/api/platform_admin/` — an opt-in router over Core functions that each authorize a platform caller (`saas_os/core/platform_authority` and the module that owns the state) | `build_platform_admin_router()`, prefix `/v1/platform`. Two opt-ins: mounted by the product, and `PLATFORM_ADMIN_HTTP_ENABLED=true` in the deployment. Its route policy is `platform_permission`: no tenant is resolved, an authenticated caller who is not an active operator gets the `404` of an unknown path, and a change to platform authority needs a session at most 15 minutes old (`docs/ADR/0045-...`) |
| Product-specific external routes | The owning Product module | Declared in that product's contract (`apiRoutes`, `docs/ARCHITECTURE.md` §9) for gateway registration |
| AI Control Plane tool invocation endpoints (if exposed over API rather than in-process) | `saas_os/control_plane/orchestration` | Distinct from both Core and Product APIs; not reachable by ordinary tenant traffic |

**Rule**: every API route — Core or Product — declares exactly one route policy built on the same auth/tenant-resolution/RBAC dependency chain (`saas_os/api/route_policy.py`). The mechanism is per-route FastAPI dependencies, not ASGI middleware. It is secure by default: `build_platform_app()`'s startup check refuses to run an application containing a route with no policy, conflicting policies, or a public route without a stated reason. A Product therefore cannot ship a route that silently bypasses platform authentication; an intentionally public route must say so, and why, in code. FastAPI's generated documentation is disabled in production ([ADR-0030](ADR/0030-foundation-enforcement.md)).

## 3. Style (Accepted)

**REST, documented with OpenAPI**, per `docs/ADR/0006-api-style-and-versioning.md`: broadest tooling compatibility for a platform meant to be consumed by multiple future products and possibly third-party integrators, and the simplest auth story for external consumers. GraphQL and RPC-style options (tRPC, gRPC) were considered and rejected for the external surface (ADR-0006 §Rejected Alternatives); an internal-only RPC mechanism remains a possible later addition for Core↔Product↔Control-Plane traffic without affecting the external contract.

## 4. Versioning (Accepted)

- **The external API is versioned from its first released route**, using a URL path segment (`/v1/...`) — there is no "unversioned v0" period once an external consumer (including Dograh, once integrated) exists.
- A future `v2` is expected to coexist with `v1` for a defined deprecation window rather than replacing it in place.
- The internal API (Core ↔ Product ↔ Control Plane) is versioned per-module at the interface level — a Core module's published interface is a contract Product code compiles/depends against, and breaking changes follow the same deprecation discipline (old interface kept functional for a defined window) rather than being changed in place.
- Event schemas (`docs/DATA-ARCHITECTURE.md` §4) follow the same versioning discipline as internal API contracts.

## 5. Contract Definition and Documentation (Accepted)

- Every API surface (internal and external) has an **OpenAPI** specification as the source of truth, generated from or validated against the implementation — not hand-maintained prose that drifts from behavior.
- The Product Contract's `apiRoutes` field (`docs/ARCHITECTURE.md` §9) is what lets the platform (and eventually the AI Control Plane) enumerate a product's external surface without reading its source code, and is expected to be expressible as (or alongside) an OpenAPI document per product.

## 6. Rate Limiting and Abuse Protection

- Owned by Infra as a cross-cutting ingress concern, applied uniformly ahead of both Core and Product routes, scoped by tenant and by API key (`core/api-keys`) — a Product cannot be individually exempted from platform-wide rate limiting, though a product may declare tighter limits for its own routes via its contract.

## 7. AI Control Plane Access to APIs

The Control Plane does not call internal/external APIs as an unauthenticated or superuser client. Every Control-Plane-initiated API call carries the invoking agent's scoped identity (`docs/SECURITY.md` §6) and is subject to the same auth/RBAC middleware as any other caller — there is no separate, more-privileged API path for AI agents.

## 8. What Is Hard to Change Later

The external API's versioning scheme and auth model become expensive to change once any external consumer (Dograh included, once it integrates) depends on them. This is why both are settled now (§3–§4), before any external route ships, rather than discovered retroactively.
