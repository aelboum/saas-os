# ADR-0002: Multi-tenancy isolation model

Status: Accepted
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

Every piece of tenant data in the platform must be isolated from every other tenant. The isolation mechanism is the platform's primary security boundary (`docs/SECURITY.md` §5) and is expensive to change once Product code exists against it. See `docs/MULTI-TENANCY.md` for the full model this decision governs.

## Options Considered

### Option A — Shared DB, shared schema, `tenant_id` column (row-level tenancy)
- Advantages: cheapest to operate; simplest migrations (one schema); easiest cross-tenant admin/analytics queries
- Disadvantages: requires airtight enforcement everywhere (a single missed filter leaks data); noisy-neighbor risk at scale

### Option B — Shared DB, schema-per-tenant
- Advantages: stronger isolation than row-level; per-tenant migration flexibility
- Disadvantages: migration fan-out cost grows linearly with tenant count; connection/schema management complexity

### Option C — Database-per-tenant
- Advantages: strongest isolation; simplest "delete a tenant" story; best per-tenant compliance/residency story
- Disadvantages: expensive at scale (migrations × N tenants); cross-tenant analytics becomes hard; heavy operational overhead

### Option D — Hybrid: row-level by default, dedicated database for enterprise/compliance-sensitive tenants
- Advantages: matches isolation cost to tenant value; common pattern in mature SaaS platforms
- Disadvantages: more code paths to test; only achievable later without a rewrite if the data-access layer already treats a tenant's storage location as a resolvable indirection

## Recommendation

Option A now, with `infra/db` designed so Option D is addable later without a rewrite.

## Decision

**Accepted.** PostgreSQL, shared database, shared schema, row-level multi-tenancy: every tenant-owned row carries a `tenant_id` foreign key to `core.tenants.id`.

**Terminology**: the platform's tenant entity (`core/tenancy`, `core.tenants`) *is* the customer organization. "Tenant" and "organization" refer to the same entity throughout this platform — `tenant_id` is the canonical column name in every schema; Product code and APIs may expose it to end users as `organization_id` (the more familiar customer-facing term) but it is never a separate identifier or a separate table. There is exactly one canonical ID for this concept. This equivalence is binding and must not be reintroduced as an open question in Product code.

Enforcement:
- Centralized at the `infra/db` chokepoint (`docs/MULTI-TENANCY.md` §3): no module queries the database directly; every tenant-scoped query is required to carry a `tenant_id`.
- PostgreSQL Row-Level Security (RLS) policies are applied on every tenant-owned table as defense in depth, keyed on a session-level `tenant_id` set by `infra/db` at the start of each request/job — so even a bug in application-layer scoping does not, by itself, leak cross-tenant data at the database level.
- Cross-tenant access (platform admin, support tooling) uses a distinct, explicitly audited code path (`docs/MULTI-TENANCY.md` §5) — never a silent bypass of the RLS policy. *(The platform-admin part of that path is now designed, not built — see "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)".)*

## Rejected Alternatives

- **Schema-per-tenant (Option B)**: rejected for the initial platform — migration fan-out cost is not justified before there is a demonstrated need for stronger-than-RLS isolation, and it adds operational complexity (per-tenant schema/connection management) with no corresponding benefit at current scale.
- **Database-per-tenant (Option C)**: rejected for the initial platform for the same reason, at a higher cost — full database provisioning and migration per tenant does not match the platform's current stage (pre-scale, single real product).

## Future Migration / Extension Path

- **Hybrid escape hatch (Option D)** remains available and is the anticipated next step for enterprise or compliance-constrained tenants: `infra/db` must resolve a tenant's storage location through an indirection (a lookup, not a hardcoded single connection string) from the start, specifically so a subset of tenants can be moved to a dedicated database later without changing any calling code in Core, Product, or the AI Control Plane.
- Moving from row-level to schema-per-tenant is not anticipated and would be a substantially larger migration if ever required; row-level + RLS + the Option D escape hatch is expected to cover the platform's needs through multiple future scale stages.

## What Would Be Difficult to Change Later

The enforcement point (centralized at `infra/db` vs. ad hoc per query) is the truly irreversible part, independent of which storage topology sits behind it. Retrofitting centralized enforcement after Product queries already bypass it requires a security-critical, full-codebase audit and rewrite. This is why the `infra/db` chokepoint (Phase 2.1) must exist and be enforced before the first Product query is ever written (Phase 3.1, `docs/IMPLEMENTATION-ROADMAP.md`).

## Amendment (Phase A: tenant hierarchy foundation)

**Status: Accepted, additive.** Architecture research into universal multi-tenant and delegated tenancy (B2B/B2C/B2B2C, hierarchical organizations) concluded that `Tenant` should remain the platform's sole canonical isolation abstraction — no separate `Organization`/`Workspace`/`Account` entity is introduced — but that `Tenant` may optionally participate in a strict, single-parent tree recording *which tenant is the parent of which*.

This amendment does not reopen the terminology decision above: "tenant" and "organization" remain the same entity, one canonical ID. A hierarchical organization (departments, branches, a holding/subsidiary structure) is modeled as a tree of `Tenant` rows connected by `parent_id` — an `Organization` in the colloquial sense is simply a `Tenant` with children, never a second table or a second identifier space.

**What was added** (`core/tenancy/models.py`, `core/tenancy/service.py`):

- `Tenant.parent_id` — nullable, self-referential. `NULL` means *root tenant*. Every tenant that existed before this column was added is, and remains, a root tenant (a plain `ADD COLUMN ... NULL` cannot retroactively infer a parent) — flat tenancy is the degenerate case of this model, not a separate code path.
- `core.tenant_ancestry` — a precomputed closure table (one row per (tenant, ancestor) pair, including a self row at depth 0 for every tenant) so ancestor/descendant queries are indexed lookups, never a recursive CTE evaluated at read time.
- `core.tenancy.service.move_tenant()` — moves a tenant (and its subtree) to a new parent, transactionally, with cycle prevention (a tenant may never become its own ancestor) and a configurable depth guardrail (`TENANT_MAX_HIERARCHY_DEPTH`, `core/tenancy/config.py`).

**What this amendment explicitly does NOT change:**

- **Hierarchy is structural data only. It grants no authorization by itself.** A parent tenant does not gain access to a child's data merely because `parent_id` exists; a child does not gain access to a parent's or a sibling's data. No RLS policy and no `core.rbac` check reads `parent_id` or `core.tenant_ancestry` as of this amendment.
- The RLS enforcement model above (§"Decision") is entirely unchanged: still a single session-level `app.tenant_id` GUC, still one equality-comparison policy per tenant-owned table, still `FORCE ROW LEVEL SECURITY`, still no `SECURITY DEFINER`, still no role with `BYPASSRLS`. *(All of this still holds for tenant-owned tables. A different policy on three tables that are not tenant-owned is decided and not yet implemented — see "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)".)* A future `app.authorized_tenant_ids` GUC (a *second*, opt-in, hierarchy/delegation-aware policy layered alongside the first) remains exactly that — future, deferred, unimplemented by this amendment.
- Cross-tenant access (platform admin, delegated administration, scoped roles, explicit deny) remains the "distinct, explicitly audited code path" this ADR already commits to above — not built by this amendment, and specifically not implied by a tenant simply having a `parent_id`.
- Resource `tenant_id` ownership is unaffected by a hierarchy move: `move_tenant()` rewrites `Tenant.parent_id` and `core.tenant_ancestry` only, never any tenant-owned business row's own `tenant_id`. A resource created before a tenant was moved is unaffected by the move; its historical `tenant_id` is not rewritten.

**Future migration/extension path (unchanged in spirit, now more concrete):** the hierarchy this amendment adds is the structural prerequisite for the hierarchy-aware authorization, delegated administration, and the second RLS GUC described in the architecture research — each remains a distinct, separately-decided future phase, not implied or unlocked automatically by this one.

## Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)

[ADR-0045](0045-installation-scoped-platform-authority.md) is the repository owner's accepted baseline for platform authority (2026-10-12). **Implementation status (updated 2026-10-12).** Phase B of ADR-0045 is implemented and merged into `main` (merge commit `bb9ca423f3875ee03d73ccb2c24b7d911b3a18eb`, pull request #9): the three platform tables with their exclusion policy and privilege revocations, the platform permission vocabulary, `platform_can()` and `authorize_platform_caller()`, the operator and grant lifecycle, the last-active-platform-owner invariant, platform audit, and the bootstrap and recovery command. Where this amendment says of a Phase B item that it is "not implemented" or "does not exist yet", that sentence predates Phase B and this paragraph supersedes it. Nothing else in ADR-0045 is implemented. No platform HTTP router and no `/v1/platform` route has been implemented or activated. Phase C (callers on the tenant-lifecycle and feature-flag functions, user deactivation and reactivation, session and API-key revocation, oversight reads) remains separately gated. The last-owner concurrency tests that pass for Phase B do not establish the concurrency correctness of `deactivate_user` or `reactivate_user`, which do not exist. This amendment records what that decision means for this ADR. For every item of a phase that has not shipped, the body of this ADR describes the code. No table, policy, call site or test changes with this amendment, and no test was run for it.

### Tenant-owned data and global platform-authority tables

- **Unchanged.** Everything this ADR decides about tenant-owned data: every tenant-owned row carries `tenant_id`; one equality-comparison policy per tenant-owned table, keyed on the single `app.tenant_id` variable; `FORCE ROW LEVEL SECURITY`; the `infra/db` chokepoint; no `SECURITY DEFINER`; no role with `BYPASSRLS`; no second variable. ADR-0045 changes none of it and relies on all of it.
- **Three tables that are not tenant-owned.** ADR-0045 adds `core.platform_operators`, `core.platform_grants` and `core.platform_audit_log`. They hold who may administer the deployment and the evidence of what was done with that authority. They belong to no tenant and have no `tenant_id` column. The audit table's reference to a tenant is named `target_tenant_id`; it records what an action was about and confers no ownership. They are global in the sense `core.users` and `core.sessions` are, and none of this ADR's tenant-data rules applies to them: they are not read "as a tenant", they are not purged with a tenant, and a tenant's administrators have no access to them.
- **A second policy shape, for those three only.** Each carries a *tenant-context exclusion* policy, enabled and forced: its rows are visible and writable only in a transaction in which `app.tenant_id` is unset or empty (ADR-0045 section 9b gives the decided expression; no such policy exists in any database yet). It uses the same variable and the same runtime role. This ADR's statement "one equality-comparison policy per tenant-owned table" remains exactly true; what changes is that it is no longer a complete description of every policy in the schema.
- **What that policy is.** Defence in depth, in the sense this ADR already uses the term: a tenant-scoped transaction cannot read or change platform authority or platform evidence, whatever bug the code in it contains.
- **What that policy is not.** An authorization boundary. `app.tenant_id` is set by application code and is not a credential. The policy cannot tell platform code from any other code running as the application role, and it does not hold against code that opens an untenanted transaction or clears the variable. Who may use platform authority is decided in Core, by `platform_can()`, and by nothing in the database. The same is true of the tenant policy in the other direction, as this ADR has always said: RLS is the layer under application-level scoping, not a substitute for it.

### The audited cross-tenant path

The Decision says cross-tenant access "uses a distinct, explicitly audited code path — never a silent bypass of the RLS policy", and the hierarchy amendment repeats that it is "not built by this amendment". ADR-0045 designs the platform-admin part of it (section 9d). It is not built.

- **How it reads.** One tenant at a time. A platform operation that needs a fact from tenant-owned tables binds that tenant's ordinary scope, runs one fixed query under the tenant policy, and leaves the scope. No statement spans tenants. The tenant policy filters every row it returns.
- **What it may read.** Fixed, minimal projections named in ADR-0045 section 4: for the commercial overview, a subscription's status, plan key, payer tenant and last update; for one named tenant, its flag overrides. There is no function that takes a table name or a column list, and nothing in ADR-0045 returns a tenant's business records, messages, members or audit trail to a platform operator.
- **Who decides.** One Core authorization per call, held under row locks for the call, and one audit row written before anything is read. Each call is bounded by fixed maxima.
- **What it does not create.** No new exception to tenant isolation. The reads go *through* the tenant policy, not around it. What is new is the reason a tenant is named: until now a tenant's scope was entered because the actor held authority in that tenant; here it is entered because the actor holds a platform permission. That is the decision ADR-0045 records, and its narrow projections are what keep it from becoming general access.
- **Customer data.** Access to a tenant's data by anyone outside it remains the tenant-approved support-access mechanism, unchanged.
- **Hierarchy.** "Hierarchy is structural data only. It grants no authorization by itself" is unchanged. ADR-0045 restricts who may attach a child to an existing tenant (its section 12a); it gives a parent nothing over a child.

### Not covered here

Whether the locking ADR-0045 describes for `deactivate_user` and for its last-platform-owner invariant is correct is unverified. ADR-0045 lists seven questions that only implementation and PostgreSQL tests can answer, and gates the affected operations on them. Nothing in this amendment bears on those questions or answers any of them.

## Related

[ADR-0045](0045-installation-scoped-platform-authority.md); `docs/MULTI-TENANCY.md`; `docs/SECURITY.md` §5; `docs/DATA-ARCHITECTURE.md` §9; `docs/ARCHITECTURE-DISCOVERY.md` §9.
