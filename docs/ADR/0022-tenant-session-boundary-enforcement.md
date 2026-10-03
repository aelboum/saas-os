# ADR-0022: Static architecture enforcement for the tenant-session boundary

Status: Accepted (amended 2026-10-01 — billing catalog and provider tables, see Amendment below)
Date: 2026-09-18
Supersedes / Superseded by: —

## Context

BANK-SEC-01 (the Open Banking security readiness audit) identified finding S-04 (LOW): PostgreSQL Row-Level Security already fails closed on every tenant-owned table (`infra/db/rls.py`, `tests/core/tenancy/test_tenant_isolation_integration.py`), but the repository had no *architecture-level* check forcing tenant-owned access through the intended `infra.db.tenant_session_scope()` boundary — the discipline was convention (`docs/MULTI-TENANCY.md` section 3), not an enforced, CI-catchable invariant. This ADR is BANK-SEC-06: the remediation for S-04 only.

**Inspecting the actual architecture before proposing a mechanism** (this phase's own directive) found:

- `infra/db/session.py` exports two session entry points: `session_scope()` (untenanted) and `tenant_session_scope()` (sets the `app.tenant_id` PostgreSQL session variable RLS policies check). Both are legitimately exported from `infra.db` (`tests/infra/test_db_public_surface_unit.py`'s own curated whitelist) — a tenant-owned table's repository correctly calling `tenant_session_scope()` and one incorrectly reaching for the untenanted `session_scope()` are both valid Python, both pass every existing check, and both import `infra.db` identically. **This is the actual gap**: not "someone might construct a raw SQLAlchemy session" (already fully blocked — see Existing Controls below) but "someone might call the wrong one of two sanctioned functions."
- A **complete, verified inventory** (every table's migration read, every call site classified — not merely counted) found exactly 45 `session_scope()` call sites outside `infra/db` itself, across exactly 10 files, all in `core/`. `control-plane/control_plane` (every self-learning and approvals service) and `products/` (currently empty) use `tenant_session_scope()` exclusively, with zero plain `session_scope()` call sites. Every one of the 45 was individually verified against the actual table/model it queries and that table's actual migration (Table Inventory below) — none is a guess, and one (`core/identity/service.py::accept_invitation`) is a pre-existing, already-documented, already-accepted exception (PRIV-01) rather than something this ADR classifies for the first time.

## Table Inventory (from the actual migrations, not assumed)

**Tenant-owned (RLS-protected, `tenant_rls_statements()` applied):** `core.webhook_subscriptions`, `core.webhook_replay_records`, `core.notifications`, `control_plane.approval_requests`, `core.billing_subscriptions`, `core.audit_log`, `core.idempotency_records`, `self_learning.canaries`, `self_learning.adaptations`, `self_learning.experiments`, `core.service_accounts`, `core.service_account_roles`, `core.feature_flag_tenant_overrides`, `core.usage_events`, `core.tenant_memberships`, `core.roles`, `core.role_permissions`, `core.membership_roles`, `core.support_access_requests`, `core.delegation_grants`, `core.deny_grants`, `core.invitations` (RLS added later, `cb7120cfa806`, not at table creation).

**Global/system (no RLS — either no `tenant_id` column, or a documented structural exception):**

| Table | Why global |
|---|---|
| `core.tenants` | The tenant registry itself — "a tenant cannot scope itself into existence" |
| `core.tenant_ancestry` | Registry/hierarchy structure, not tenant-owned business data |
| `core.users`, `core.external_identities`, `core.sessions` | Global identity — a user is never modeled as belonging to exactly one tenant (`docs/MULTI-TENANCY.md` section 1) |
| `core.login_transactions` | Exists before any user or tenant is known (pre-authentication) |
| `core.permissions` | Global permission catalog |
| `core.billing_plans` | Global product catalog |
| `core.feature_flags` | Global flag-definition catalog |
| `core.api_keys` | **Has a `tenant_id` column but is deliberately NOT RLS-scoped** (`3a2522ccb9ea_create_core_api_keys_table.py`): a bearer credential must be resolvable by its hash *before* the caller's tenant is known, and an untenanted query against an RLS-protected, FORCE-enabled table always returns zero rows. A composite FK onto `core.tenant_memberships` is this table's substitute integrity guarantee instead. |

## Existing Controls This ADR Builds On (not duplicated)

1. **PostgreSQL RLS + `FORCE ROW LEVEL SECURITY`** (`infra/db/rls.py`) — the actual, database-level, fail-closed control. Unchanged.
2. **"Only infra/db may import SQLAlchemy or psycopg directly"** (import-linter contract, `tests/architecture/test_layer_boundaries.py::test_only_infra_db_can_import_sqlalchemy_or_psycopg` / `::test_forbidden_direct_sqlalchemy_import_from_core_is_actually_caught`) — already fully enforces "no module outside `infra/db` can construct its own raw SQLAlchemy `Session`/`sessionmaker`/engine at all." This already satisfies "a tenant-owned access path that directly creates an unrestricted database session must fail" — verified still passing, not re-implemented here.
3. **The curated `infra.db.__all__` whitelist** (`tests/infra/test_db_public_surface_unit.py`) — `text()` (raw SQL) is not exported at all, so a compliant `tenant_session_scope()` block cannot smuggle a `set_config` exploit either.
4. **`tests/core/tenancy/test_tenant_isolation_integration.py`** — the real, database-backed proof that RLS itself does what it claims (missing tenant context, wrong tenant context, cross-tenant read/insert/update/delete, forged session settings, connection-pool leakage across sequential sessions). Unchanged, unweakened.

None of these distinguish `session_scope()` from `tenant_session_scope()` — that is the one gap this ADR closes.

## Options Considered

### Option A — A new import-linter contract

- Advantages: reuses the tool already used for every other layering rule.
- Disadvantages: import-linter contracts reason about *module-level import edges* ("does module A import module B"), not about *which name* is imported from an edge already permitted. `session_scope` and `tenant_session_scope` are both legitimately exported from `infra.db` — there is no import-linter contract shape that can say "core/billing may import `infra.db`, but only the `tenant_session_scope` name, except in these four specific functions." Rejected: the wrong tool for a call-site-level distinction.

### Option B — An AST-based static architecture test with a curated, per-function allowlist

- Advantages: can inspect actual `ast.Call` nodes to distinguish the two entry points precisely; mirrors this codebase's own established "curated whitelist, audited entries" pattern (`tests/infra/test_db_public_surface_unit.py`'s export whitelist, `.secrets.baseline`'s audited findings) rather than inventing a new enforcement style; a genuinely new global/system exception requires a deliberate, reviewed edit to the allowlist (fail-closed for new bypasses); needs no database, runs in the default unit-test suite, sub-second.
- Disadvantages: static analysis proves *which entry point a call site reaches*, not runtime correctness of what happens once inside it (stated explicitly as a limitation below, not glossed over).

### Option C — Require every function touching a tenant-owned ORM model to use `tenant_session_scope()`, detected via deeper type/data-flow analysis of which model each block queries

- Advantages: would remove the need for a maintained allowlist entirely.
- Disadvantages: requires reliable static type inference of which SQLAlchemy model a given `session.execute(select(...))` call touches — infeasible to build reliably with plain `ast` (no type checker integration), and a wrong inference would be worse than an explicit, human-reviewed allowlist (false confidence). `core/identity/service.py::accept_invitation`'s own token-lookup-by-hash pattern (Table Inventory above) shows this codebase already has at least one case where the *same file* legitimately needs both entry points for different tables — a rule keyed on "which model" needs to already know the tenant-ownership answer this ADR's own inventory had to establish by hand. Rejected as unreliable for the actual, current failure mode; the curated allowlist is the smaller, more honest mechanism.

## Recommendation

Option B.

## Decision

**Accepted.** `tests/architecture/test_tenant_session_boundary.py` is a new architecture test:

1. **`_find_session_scope_call_sites()`** walks every `.py` file under `core/`, `control-plane/control_plane/`, `products/`, and `api/` (excluding `tests/`, `__pycache__`, `migrations/`; `infra/db` itself is never scanned — it is the trusted chokepoint implementation, and `tenant_session_scope()`'s own body legitimately calls `session_scope()` internally) via `ast.parse`, recording every `Call` whose callee resolves to the exact identifier `session_scope` (never a substring match against `tenant_session_scope`), tagged with its enclosing function name.
2. **`_ALLOWLIST`** is the curated registry above (45 entries across 10 files), each individually justified against the actual table it queries.
3. **`test_every_plain_session_scope_call_site_is_an_approved_global_or_system_operation`** fails if any real call site is not in `_ALLOWLIST` — this is the actual enforcement: a new function that mistakenly reaches for the untenanted entry point where a tenant-owned table required `tenant_session_scope()` is an unclassified violation, not a silent pass. A genuinely new global/system exception requires a deliberate, reviewed edit to this file.
4. **`test_allowlist_has_no_stale_entries`** — the reverse direction, mirroring `.secrets.baseline`'s own audited-entry discipline: an allowlist entry with no matching real call site is itself flagged, so the exception surface cannot silently drift from what the file claims it is.
5. **`test_control_plane_and_products_have_zero_plain_session_scope_call_sites`** — a non-vacuous, independent confirmation of the inventory's own claim that every current exception lives in `core/`.
6. Synthetic, `tmp_path`-isolated positive/negative cases exercise the *real* `_find_session_scope_call_sites`/allowlist-comparison functions directly (never a reimplementation of their logic): a new, unapproved tenant-shaped bypass is rejected; an explicitly approved global access passes; a compliant `tenant_session_scope()` call site produces zero findings; `infra/db` and `tests/` directories are confirmed excluded.

## Relationship to PostgreSQL RLS

This is a second, independent, **static** control layered in front of RLS's **runtime, database-level** one — not a replacement. RLS remains the actual last line of defense: even if this static check were somehow bypassed (a reviewer approves a bad allowlist entry, or a future call-site shape this AST scan does not recognize), an untenanted or wrongly-tenanted query against a real RLS-protected table still returns zero rows, never another tenant's data, exactly as before this ADR. This ADR's contribution is catching the mistake earlier — at review/CI time, as a named, attributable test failure — rather than relying solely on RLS silently returning nothing.

## Limitations of Static Enforcement (stated explicitly, not implied)

- **Does not verify the `tenant_id` passed to `tenant_session_scope()` is the correct one.** A compliant call site with a wrong or attacker-influenced `tenant_id` argument is invisible to this check — that is an application-logic correctness question (input validation, authorization), not an entry-point-selection question, and remains covered by RLS itself (a wrong `tenant_id` still only ever sees that tenant's rows, never a cross-tenant leak) and by `docs/SECURITY.md`'s authorization boundary, not this ADR.
- **Does not catch a call site shape it cannot parse as a plain `Call` node** — e.g., `getattr(infra.db, "session_scope")()`, a dynamically constructed callable, or a wrapper function that itself calls `session_scope()` once and is then called from many places (the wrapper itself is scanned and must be allowlisted or use `tenant_session_scope`; call sites of the *wrapper* are not separately re-scanned, since they no longer contain the literal `session_scope(` call). This mirrors every AST-based check in this codebase (e.g. the `text()` export ban) — a deliberate scope limit, not an oversight.
- **Does not itself run any query or touch a database** — it is pure source analysis, and complements, not substitutes for, `tests/core/tenancy/test_tenant_isolation_integration.py`'s real-PostgreSQL proof that RLS behaves as claimed.
- **This ADR does not claim static analysis guarantees tenant isolation.** RLS is, and remains, the actual fail-closed guarantee; this is architecture-review automation sitting in front of it.

## Tests

`tests/architecture/test_tenant_session_boundary.py` (9 tests): the real-repository scan (positive), allowlist-staleness check, explicit classification of lifecycle/purge/admin operations, zero-violations confirmation outside `core/`, and four synthetic `tmp_path` cases proving the actual checker function — not a reimplementation — rejects a new bypass, accepts an approved entry, never flags a compliant `tenant_session_scope()` site, and correctly excludes `infra/db` and `tests/` directories. `tests/architecture/test_layer_boundaries.py` (existing, unmodified) continues to prove direct SQLAlchemy/session construction outside `infra/db` is caught. `tests/core/tenancy/test_tenant_isolation_integration.py` (existing, unmodified) continues to prove RLS's own runtime guarantees: missing tenant context, wrong tenant context, cross-tenant read/insert/update/delete, forged session settings, sequential-session leakage.

## What Would Be Difficult to Change Later

If a future refactor introduces a third session-scoping entry point (e.g., a "batch admin" session distinct from both `session_scope()` and `tenant_session_scope()`), this check's `_callee_name(...) == "session_scope"` matcher would need a corresponding update — it does not automatically generalize to an arbitrary number of entry points. This is an explicit, narrow maintenance dependency, not a hidden one.

## Amendment (upstream SaaS-OS fix: invitation acceptance RLS bootstrap)

**Status: Accepted, additive.** `core/identity/service.py::accept_invitation()`'s own token-hash lookup -- named above (Context, Table Inventory, Option C) as the one pre-existing PRIV-01 exception to this ADR's own 45-call-site inventory -- has been fixed, not merely re-documented: the function now takes `tenant_id` as an explicit, required parameter and resolves the token entirely inside `tenant_session_scope(tenant_id)`, exactly like every other function on `core.invitations`. It no longer calls the untenanted `session_scope()` at all. The `_ALLOWLIST` entry for `accept_invitation` in `tests/architecture/test_tenant_session_boundary.py` has been removed accordingly (`test_allowlist_has_no_stale_entries` would otherwise fail), bringing the real, current count to 44 call sites across the same 10 files -- this ADR's own historical inventory numbers above are left as the record of what was true at the time this ADR was accepted, not restated. See `core/identity/service.py::accept_invitation()`'s own docstring for the fixed design (the `tenant_id` argument scopes the lookup only; the invitation token remains the sole bearer credential for acceptance).

## Amendment (2026-10-01): owner-scoped billing catalog and global-by-design provider tables

**Status: Accepted, additive, architecture only.** No table, policy, call site or `_ALLOWLIST` entry changes with this amendment. The Table Inventory above remains the historical record of what was true when this ADR was accepted, following the precedent of the invitation amendment above.

### `core.billing_plans` is no longer "global product catalog"

The Table Inventory classifies `core.billing_plans` as a "Global product catalog". Under [ADR-0029](0029-commercial-parties-and-billing-relationships.md) that description is superseded. The catalog becomes:

```text
owner-scoped catalog           every plan has an owner_tenant_id (the platform is an ordinary tenant)
+ application-level eligibility one shared predicate decides listing, checkout and subscription creation
+ non-RLS catalog storage       the catalog tables stay outside tenant_rls_statements()
```

**Why RLS alone cannot implement catalog visibility.** RLS policies here key on a single `app.tenant_id` (`infra/db/rls.py::tenant_rls_statements()`), and a catalog row's visibility is not a function of one tenant:

- **public** plans must be readable by every tenant, so a single-tenant policy would hide them;
- **descendants** visibility depends on the reader's position in the hierarchy relative to the plan owner. That needs an ancestry lookup inside the policy, which this codebase explicitly forbids (`core/tenancy/models.py::TenantAncestry`: never embed a recursive lookup inside a policy; any hierarchy-aware RLS must instead populate a GUC once per transaction);
- **private** visibility depends on the *actor's* permission on the owner tenant (`can()`), which RLS cannot evaluate;
- **unlisted** plans depend on the existence of an explicit offer to the reader, plus the same actor authorization.

So the catalog tables stay outside RLS, exactly as `core.billing_plans` is today. Visibility is enforced by one application-level eligibility predicate (ADR-0029, "Catalog"). It lives in `core/billing`, is shared by every listing, checkout and subscribe path, and is covered by a dedicated cross-tenant isolation suite. An unfiltered listing of all plans (today's `core/billing/service.py::list_plans()`) must not remain a public, consumer-facing entry point once owner-scoped plans exist. The catalog's existing `_ALLOWLIST` entries (`create_plan`, `get_plan`, `list_plans`, `get_entitlements`) are re-justified as "owner-scoped catalog; visibility enforced by the eligibility predicate" when Phase 4 changes them.

**Status update (2026-10-02): Phase 5.3.** The catalog change above ("Phase 4" in the Billing Foundation v2 numbering) is delivered by roadmap Phase 5.3 B2B2C Billing Completion, step 2 ([ADR-0029](0029-commercial-parties-and-billing-relationships.md) "Amendment (2026-10-02)"). Catalog eligibility extends to merchant- and owner-scoped plans:

```text
catalog visibility (public | descendants | private | unlisted)
+ owner scope (plan owner tenant; owner-scoped key uniqueness; offers for unlisted)
+ merchant compatibility (plan merchant = billing account merchant = subscription merchant)
+ the single eligibility predicate evaluate_plan_eligibility(caller, service_tenant, plan, session)
```

`list_plans()` becomes an eligibility-aware catalog read, not an unrestricted global enumeration. The catalog tables stay outside RLS, as decided above. **Implemented** (Phase 5.3 step 2, migration `d23cbb2ba746`):

- `core/billing/catalog.py` reads and writes owned plans only under `tenant_session_scope()`.
- The unrestricted `service.list_plans()` is removed.
- `create_plan`/`get_plan` remain allowlisted for the legacy (unowned) key namespace only.
- Offers live in the RLS-protected `core.billing_plan_offers`, owned by the plan owner.

### Two new global-by-design tables (Billing Foundation v2 Phases 2 and 6 — `ProviderRef` implemented in Phase 2 as `core.billing_provider_refs`, allowlisted for `core/billing/provider_refs.py::register_provider_ref`/`_lookup`; `ProviderEvent` still future)

Both follow the existing `core.api_keys` precedent, which is resolved by hash before the caller's tenant is known:

- **`ProviderRef`**: an index `(provider, provider_account_ref, object_type, provider_ref) → (tenant, local object id)`. A provider event or callback names only provider objects. The tenant that owns the corresponding local row is unknown until this index is consulted, and an untenanted query against an RLS-protected FORCE-enabled table returns zero rows. The index is therefore not RLS-scoped. It holds opaque references only, never payment data or secrets, and it is the *only* sanctioned way to resolve a provider object to a tenant. Provider-side metadata must never be used for that (ADR-0008 amendment, point 9).
- **`ProviderEvent`**: a durable ledger `(provider, provider_account, event_id UNIQUE, status, …)` used to deduplicate and track processing of inbound provider events. Deduplication must happen before tenant resolution, so a replay can be rejected even for an event that later fails tenant resolution. That makes the ledger global-by-design.

When these tables are created, every `session_scope()` call site that touches them must be added to `tests/architecture/test_tenant_session_boundary.py::_ALLOWLIST` with a per-function justification, as for every other global exception. Rows reached through them (subscriptions, billing accounts, invoices) are still read and written only through `tenant_session_scope()` for the resolved tenant.

## Related

`docs/MULTI-TENANCY.md` section 3 (the enforcement-boundary convention this ADR converts into an enforced invariant); `docs/ADR/0002-multi-tenancy-isolation-model.md`; `infra/db/rls.py`, `infra/db/session.py`; `tests/architecture/test_layer_boundaries.py`; `tests/infra/test_db_public_surface_unit.py`; `tests/core/tenancy/test_tenant_isolation_integration.py`; the BANK-SEC-01 audit (finding S-04) and BANK-SEC-06 (this remediation)'s own directive.
