# Multi-Tenancy Architecture

Status: ACCEPTED. Isolation model finalized per `docs/ADR/0002-multi-tenancy-isolation-model.md`.

## 1. Tenant Model

- A **tenant** is a Core entity owned by `core/tenancy`, identified by a stable `tenant_id`. **A tenant *is* the customer organization** — "tenant" and "organization" are the same entity, not two related entities. `tenant_id` is the canonical column/field name in every schema and internal interface; APIs and Product-facing UI may label it `organization_id` for end users, but there is exactly one ID and one table (`core.tenants`) behind both names. Do not introduce a separate "organization" entity anywhere in Core or Product.
- A **user** is a global identity (`core/identity`), independent of any tenant, that holds zero or more memberships in tenants via `core/rbac`-scoped roles. A user is never modeled as belonging to exactly one tenant.
- Every piece of tenant-owned data, in every layer and every Product, carries a `tenant_id` that traces back to `core.tenants`. There is no tenant-owned data without an explicit tenant reference.

## 2. Isolation Model (Accepted)

Per `docs/ADR/0002-multi-tenancy-isolation-model.md`:

- **PostgreSQL, shared database, shared schema, row-level tenancy** (`tenant_id` column on every tenant-owned table) for all tenants.
- **Enforced at the data-access chokepoint** (`infra/db`), not by convention: every query that touches tenant-scoped data passes through a query layer that injects/validates `tenant_id` scoping.
- **PostgreSQL Row-Level Security (RLS) policies** on every tenant-owned table as defense in depth, keyed on a session-level `tenant_id` set by `infra/db` at the start of each request/job — so a bug in application-layer scoping does not, by itself, leak cross-tenant data at the database level.
- A **hybrid escape hatch** (dedicated database per tenant) is architecturally anticipated for high-value or compliance-constrained tenants, without being built now — `infra/db` resolves a tenant's storage location through an indirection, not a hardcoded connection, so this can be added later without changing calling code in Core or Product.

## 3. Enforcement Boundary

- **The single enforcement point is `infra/db`.** No Core module, Product module, or Control Plane tool queries the database directly — all go through this layer, which requires a `tenant_id` (or explicit, logged "cross-tenant admin" override — see §5) on every tenant-scoped query.
- This is the concrete mechanism behind the security principle in `docs/SECURITY.md` §5: tenant isolation is a data-access-layer guarantee, not a per-query discipline every engineer (or AI agent) must remember.
- Code review and CI checks (Phase 1 of the roadmap) should flag any raw query construction that bypasses this layer.

## 4. Isolation Across Other Layers

Tenant isolation is not only a database concern:

| Layer | Isolation mechanism |
|---|---|
| Database | `tenant_id` scoping enforced at `infra/db` (§3), RLS as defense in depth |
| Cache | Cache keys are namespaced by `tenant_id`; no shared cache key can serve two tenants' data |
| Job queue | Every job payload carries `tenant_id`; workers scope their data access identically to request-path code (same `infra/db` chokepoint) |
| Object/file storage | Storage paths/buckets are namespaced by `tenant_id`; no tenant can be given a credential or path scoped broader than its own prefix |
| Logs/traces | Every log line and trace span carries `tenant_id` (see `docs/OBSERVABILITY.md`), but log/trace storage itself is not tenant-isolated infrastructure — access to observability tooling is a platform-operator concern, governed by RBAC, not a customer-facing isolation boundary |
| AI Control Plane | Every agent identity acting on tenant data is scoped to that `tenant_id`; a support or product agent cannot address a different tenant's data even if the underlying tool would technically allow it (see `docs/AI-CONTROL-PLANE.md`) |

## 5. Cross-Tenant Access (Platform Admin / Support)

- Any access that spans tenants (platform admin tooling, cross-tenant analytics, human support staff looking at a customer's data) is a **distinct, explicitly logged code path** — never the same code path as tenant-scoped access with the check silently skipped.
- Cross-tenant access is itself an RBAC-governed, audit-logged action (`docs/SECURITY.md` §8), attributable to a specific human or agent identity and, where the action is customer-data-sensitive, subject to the same approval-gate framework as AI Control Plane actions.

## 6. Tenant Lifecycle

Owned by `core/tenancy`. States (directional, to be finalized when `core/tenancy` is built): `pending` → `active` → `suspended` → `deleted` (soft, retaining audit trail) → `purged` (hard delete, compliance-driven, rare). Product modules react to tenant lifecycle transitions via Core-emitted events (`docs/ARCHITECTURE.md` §7); they do not maintain their own notion of whether a tenant is active.

## 7. What Is Hard to Change Later

Restated from the discovery doc because it governs how conservatively Phase 1 must treat this area: **whether tenant scoping is centrally enforced (this document's model) vs. ad hoc is effectively a one-way door.** Once Product code exists that queries the database directly (bypassing `infra/db`), retrofitting central enforcement requires auditing and rewriting every such call site under security pressure. The `infra/db` chokepoint must exist *before* the first Product query is written, not after.
