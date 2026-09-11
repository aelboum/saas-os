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

## 8. Tenant Hierarchy (Structural Only)

Per `docs/ADR/0002-multi-tenancy-isolation-model.md`'s amendment (architecture research: universal multi-tenant tenancy, Phase A):

- A tenant may optionally have a `parent_id` referencing another tenant, forming a strict single-parent tree (never a graph — a tenant has at most one parent). A tenant with `parent_id IS NULL` is a **root tenant**; every tenant created before this feature existed is, and remains, a root tenant.
- `core.tenant_ancestry` is a precomputed closure table (every tenant is its own ancestor at depth 0, plus one row per actual ancestor) maintained transactionally by `core.tenancy.service.create_tenant()`/`move_tenant()` — never a recursive query evaluated at request time.
- **Hierarchy is structural data only and grants no authorization by itself.** A parent tenant does not gain access to a child's data, a child does not gain access to a parent's or a sibling's data, merely because `parent_id`/`core.tenant_ancestry` says so. No RLS policy reads `parent_id`/`core.tenant_ancestry` — the isolation model in §2 above (single `app.tenant_id` GUC, one equality policy per table) is completely unchanged by hierarchy existing. `core/rbac`'s scoped-role authorization (§9 below) is the one thing that *does* read the live ancestor chain, and only ever to widen or narrow the reach of a role assignment that already requires a real membership, role, and permission grant to exist — it never treats hierarchy membership alone as a grant.
- `move_tenant()` moves the hierarchy relationship (`parent_id` and the moved subtree's `core.tenant_ancestry` rows) only — it never touches any tenant-owned business row. A resource's own `tenant_id` is never rewritten by a move; its history is unaffected.
- A tenant with a living child cannot be deleted/purged (blocked by `parent_id`'s foreign key, not silently cascaded) — reparent or remove every child first.
- Depth is architecturally unbounded (the data model supports arbitrary depth) but operationally guarded by a configurable default (`TENANT_MAX_HIERARCHY_DEPTH`, `core/tenancy/config.py`) to keep ancestor-chain size bounded.
- Delegated administration, explicit deny, and a future hierarchy-aware `app.authorized_tenant_ids` RLS GUC remain explicitly deferred future phases (§9 below covers what *is* built: scoped roles).

## 9. Scoped-Role Authorization (SELF / SUBTREE)

Per architecture research: universal multi-tenant tenancy, Phase B ("RBAC + role scope: self, subtree"; `core/rbac/scope.py`, `core/rbac/authorization.py`):

- Every `MembershipRole` (a role assigned to a tenant membership, `core/rbac/models.py`) carries an authorization `scope`: **`SELF`** (the default — the assignment authorizes only the membership's own tenant, the only behavior that existed before this phase) or **`SUBTREE`** (the assignment also authorizes every *current* descendant of the membership's tenant).
- `core.rbac.can()` evaluates `SUBTREE` against the **live** `core.tenant_ancestry` closure table (via `core.tenancy.get_ancestor_ids()`), never a value captured when the role was assigned — moving a tenant in or out of a subtree (`move_tenant()`, §8) changes what a `SUBTREE` role authorizes immediately, with no rewrite of the `MembershipRole` row itself.
- This does not weaken "hierarchy grants no authorization by itself" (§8): reaching a descendant via `SUBTREE` still requires a real membership, in some tenant along the ancestor chain, with a role, with a permission grant matching the requested `(resource, action)` — `scope` only ever changes *which tenant an already-granted assignment reaches*, never substitutes for the grant itself.
- Database isolation (`app.tenant_id`, RLS) and authorization scope (`SELF`/`SUBTREE`) are deliberately separate concerns: `can()`'s scoped evaluation runs one `tenant_session_scope()`-protected query per candidate tenant in the ancestor chain — never a query spanning more than one tenant's rows, never a second GUC, never a policy change. See `core/rbac/authorization.py`'s own docstring for the exact evaluation path.
- Existing installations are unaffected: every `MembershipRole` row that existed before this phase defaults to `SELF` (the migration's `server_default`, never silently widened to `SUBTREE`), and `assign_role()`'s pre-Phase-B call shape (no `scope` argument) still produces exactly that.
