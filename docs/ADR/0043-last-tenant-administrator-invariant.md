# ADR-0043: Last tenant administrator invariant

Status: Accepted (2026-10-11) and implemented. Extended twice the same day: from membership suspend/revoke to every tenant-level mutation that can remove administrative authority, then across the tenant hierarchy (ancestor mutations, tenant move, tenant suspension, expiring delegations)
Date: 2026-10-11
Supersedes / Superseded by: —

## Context

`saas_os.core.identity.suspend_membership()` and `revoke_membership()` checked one thing: that the caller holds `membership:suspend` or `membership:revoke`. Nothing stopped a member with that permission from removing every other member, every administrator and finally themselves. Revocation is terminal, so a tenant emptied this way cannot be repaired from inside.

Core always allowed this to any in-process caller. ADR-0040 made it reachable from a browser, and its independent review recorded it as a MEDIUM finding. The repository owner asked for a transactionally enforced invariant that prevents removing or deactivating the final active tenant administrator, using existing permission semantics and transaction patterns, without a fixed administrator role.

Guarding membership alone is not enough. The same end state is reachable by taking the authority away while leaving the membership in place: remove the role from the member, revoke the permission from the role, place an explicit deny on the member, or withdraw a delegation.

Guarding one tenant is not enough either. Authority flows down the tenant hierarchy — a SUBTREE-scoped role, deny or delegation at a tenant also decides who administers its descendants — and lapses with tenant status and with time. Eight ways to empty a tenant from outside it were demonstrated by tests before this ADR was extended: five mutations in a parent tenant, moving the tenant, suspending its parent, and a delegation expiring. The owner asked for those to be closed rather than recorded as a limit.

The difficulty is the word "administrator". SaaS OS has no such role. Roles belong to a tenant and are freely named; the bootstrap's `owner` role is a name with no meaning to the authorization engine.

## Inventory: what can take administrative authority away

| Change | Function | Reaches | Disposition |
|---|---|---|---|
| Suspend or revoke a membership | `saas_os.core.identity.suspend_membership`, `revoke_membership` | the tenant; descendants where the member is also a member (their SUBTREE roles hang off this membership) | **Guarded** |
| Remove a role from a member | `saas_os.core.rbac.remove_role` | same | **Guarded** |
| Revoke a permission from a role | `saas_os.core.rbac.revoke_permission` | the tenant; descendants where any holder of the role is a member | **Guarded** |
| Create a deny grant | `saas_os.core.rbac.create_deny` | the tenant; with SUBTREE scope, descendants where the denied user is a member | **Guarded** |
| Revoke a delegation | `saas_os.core.rbac.revoke_delegation` | the tenant; descendants where the delegate is a member | **Guarded** |
| Move a tenant | `saas_os.core.tenancy.move_tenant` | every tenant of the moved subtree (old ancestors' grants stop applying, new ancestors' denies start) | **Guarded** |
| Suspend or close a tenant | `saas_os.core.tenancy.transition_tenant_status` | its descendants (a role held at a tenant that no longer admits its principals authorizes nothing below it) | **Guarded** for descendants; the tenant itself is exempt, since locking its principals out is what the transition is for |
| A delegation expiring | time; nothing executes | the delegate | **Closed by definition**: an expiring delegation never makes the administrator a tenant may be left with |
| Delete a role | `saas_os.core.rbac.delete_role` | nothing: the foreign keys reject deleting a role that is assigned or still grants a permission | **No guard needed** (tested) |
| Reactivate a membership; assign a role; grant a permission; create a delegation; revoke a deny; reactivate a tenant | — | only add authority | Not restricted |
| Deactivate a user | no Core function sets `core.users.is_active` | — | **Nothing to guard**; an inactive user does not count *(A deactivation operation is decided by ADR-0045 and will be* ***Guarded*** *— see "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)". Not implemented.)* |
| Service-account role and deny mutations | `remove_service_account_role`, `create_deny_for_service_account` | none: a service account is not a member | Not applicable |
| Tenant purge, identity erasure | operator-only, import-fenced from `saas_os.api` | destroy the rows by design | Exempt |

## Options Considered

### Option A — A named or flagged administrator role
- Advantages: easy to explain.
- Disadvantages: the role hierarchy that was ruled out; a migration and a backfill decision for every tenant; says nothing about what the flagged role can do.

### Option B — Define the administrator by a capability the engine already evaluates, and check it around each change
A guarded change records whether each tenant it can reach has an administrator before it changes anything, and refuses to commit if one of them had an administrator and no longer does.
- Advantages: no schema change, no new concept, no role names; identical for every change, because it asks the authorization engine about the result instead of reasoning about each change's effect; picks up role scope, the ancestor chain, delegation, deny grants, membership, user and tenant status for free.
- Disadvantages: a search over active members calling `can()`; for hierarchy-wide changes, over several tenants.

### Option C — Reason about each change's own effect
- Advantages: can be cheaper per call.
- Disadvantages: one bespoke rule per change, each re-deriving part of `can()`; a permission revoked from a shared role, or a subtree deny, removes several administrators in several tenants at once, which a per-target rule gets wrong.

### For the hierarchy: which descendants to judge
- *Every descendant, always*: correct, and proportional to the subtree on every role change at a large parent.
- *Only descendants in which an affected user is an active member* (chosen for the user-targeted mutations): an administrator is a member of the tenant, so a tenant in which none of the affected users is a member cannot lose an administrator through that change. Exact, and typically a handful of tenants.
- *The whole affected subtree* (chosen for move and suspension): no single user is affected; these are rare operator actions.

### For expiry
- *Refuse to create an expiring delegation of `membership_role:create`*: changes what may be delegated.
- *Do not count an expiring delegation towards the invariant* (chosen): authorization is unchanged; only the guard's question narrows.

## Recommendation

Option B, with the affected-member rule for mutations, the whole subtree for move and suspension, and expiring delegations excluded from the definition.

## Decision

**Accepted by the repository owner on 2026-10-11; implemented** in `saas_os/core/rbac/administrators.py`.

1. **Definition.** A tenant administrator is an ACTIVE membership of an active user for whom `saas_os.core.rbac.can(action="create", resource="membership_role")` is true at that tenant **without relying on a delegation that has an expiry**. Whoever can assign roles can hand out every other authority, so it is the one a tenant cannot recover from inside.
2. **Invariant.** After every supported change, each tenant that had an administrator before it still has one. Otherwise the change raises `saas_os.core.identity.LastTenantAdministratorError`, naming the tenant that would be emptied, and its transaction rolls back: no row changes in any tenant, nothing is audited.
3. **One mechanism**, inside the change's own transaction:
   1. `lock_tenant_administrators(session, tenant_id)` — first statement, before the caller is authorized;
   2. the change's existing authorization and row lookup, unchanged;
   3. `guard = guard_last_administrator(session, tenant_id, affected_users=[...])` — immediately before the change; locks the reached descendants and remembers one current administrator of each guarded tenant;
   4. the change, flushed;
   5. `guard.verify(session)` — for each guarded tenant that had an administrator, find one now, or raise.

   `move_tenant` and `transition_tenant_status` use `guard_tenants(session, tenant_ids)` over the moved subtree, respectively the descendants, with the same `verify`.
4. **It does not matter who asks or whom it targets.** The rule is about each tenant's resulting state.
5. **Who does not count.** A suspended or revoked membership; a deactivated user; a member of another tenant — including a parent tenant's administrator who can assign roles in the child through a SUBTREE role but is not a member of it; a service account; a delegate whose delegation expires; a member who can manage memberships or roles' permissions but cannot assign roles.
6. **What it never does.** It never restricts a change that only adds authority. A tenant that has no administrator to begin with is not locked further, and not repaired. A caller who is not authorized, and a call that turns out to change nothing, cause no search.
7. **No authorization rule changes.** `can()` gained one optional argument, `ignore_expiring_delegations` (default `False`), which can only turn an allow into a deny and is passed by the guard alone. No permission, role, scope, grant or inheritance rule is altered; no migration.
8. **HTTP.** `saas_os/api/v1/members.py` maps the error to `409` with a fixed detail. No other guarded change has a platform route.

## Transactions, locks and concurrency

- **Transaction boundary.** The snapshot, the change and the verification run in the change's own transaction. A refusal is an exception inside it, so every row touched — in the mutation's tenant, in the ancestry table for a move, in the tenant row for a suspension — is rolled back together. There is no partial update and no compensating step.
- **The lock.** One transaction-scoped PostgreSQL advisory lock per tenant, key `tenant.administrators` (`saas_os.infra.db.acquire_tenant_advisory_lock`, the mechanism `consume_quota()` uses), shared by every guarded change that can reach that tenant.
- **Order.** The change's own tenant first, before authorization; then the descendants it reaches, nearest first and then by id (`saas_os.core.tenancy.descendant_ids_by_depth`). A tenant's depth below one ancestor differs from its depth below another by a constant, so any two transactions take the locks they share in the same order — an ancestor before its descendants — and cannot deadlock on them.
- **Against the tenant-row locks.** `can()` share-locks the tenant rows it reads; `move_tenant` and `transition_tenant_status` lock tenant rows for update. Both take the administrator locks *before* those row locks, so a guarded mutation holding a descendant's administrator lock never waits on a row that a move or suspension holds while that operation waits for the same administrator lock.
- **Authorization after the lock.** A caller whose own authority a concurrent change just removed is judged against what that change committed.
- **Administrator locks before the denied user's row.** `create_deny` locks the denied user's row exclusively (ADR-0031). It takes the administrator locks of the tenants it reaches, and records their administrators, *before* that row lock. In the other order a parent's deny could hold a user's row while waiting for a child tenant's administrator lock, and a guarded mutation in the child could hold that lock while waiting to read the row. This was not theory: the first CI run of the hierarchy tests hit exactly that deadlock once, in the parent-deny-against-child-deny race. PostgreSQL broke it by failing one transaction, so the invariant held, but a caller received a database error. The order was corrected and a test now forces the interleaving.
- **What remains possible.** Authorization share-locks the *caller's* own user row before the reached descendants are known and locked. If, at the same moment, a transaction in one of those descendants creates a deny against that very caller, the two can still deadlock: one holds the caller's row and waits for the descendant's administrator lock, the other holds that lock and waits for the row. Likewise two deny grants in two *unrelated* tenants, each denying a user who is also a member of the other. In both cases PostgreSQL aborts one transaction, which surfaces as a database error, changes nothing, and can be retried; the invariant is not at risk.

## What this does not cover

- **User deactivation.** Core has no function that deactivates a user. When one is added it must take the lock and call the guard for each tenant the user is an active member of. *(Design decided 2026-10-12 — see "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)".)*
- **Operator paths.** Tenant purge and identity erasure.
- **A tenant attached under a tenant in the instant it is suspended.** The suspension guards the descendants it read before taking the tenant's row lock; a tenant moved or created beneath it in that window is not among them.
- **A delegation's `starts_at` in the future, and support access.** Neither confers `membership_role:create` to begin with (support access never satisfies an authority resource), so neither makes an administrator.
- **Tenants with no administrator.** The rule preserves; it does not create.

## Consequences for operators and parent tenants

Operations that succeeded before are now refused when they would empty a tenant of administrators:

- a parent tenant can no longer deny, or withdraw inherited authority from, a child tenant's last administrator;
- `move_tenant` is refused when the move would leave a tenant of the moved subtree without one;
- suspending or closing a tenant is refused while a descendant's only administrators draw their authority from it.

In each case the remedy is the same and is in the error: give the named tenant an administrator of its own (a member with a role that carries `membership_role:create`), then repeat the operation.

## Cost

- A mutation searches its own tenant's active members, in creation order, until it finds one administrator, and re-checks that member afterwards — usually one `can()` each side. For each descendant of the tenant it runs one indexed membership lookup, and only for those in which an affected user is an active member does it repeat the search. A parent with many children pays one small query per child on these mutations.
- `move_tenant` and a suspension or closure search every tenant of the affected subtree.

These are rare, deliberate operations; the cost was accepted over a second source of truth about who administers a tenant.

## Evidence

- `tests/core/identity/test_last_administrator_integration.py` — 25 tests: membership suspend and revoke.
- `tests/core/rbac/test_last_administrator_rbac_integration.py` — 32 tests: `remove_role`, `revoke_permission`, `create_deny`, `revoke_delegation`, `delete_role`; mixed mutations racing inside one tenant.
- `tests/core/rbac/test_last_administrator_hierarchy_integration.py` — 47 tests: each of the eight outside-the-tenant scenarios refused, with the tenant named, nothing changed and nothing audited, and allowed once the child has an administrator of its own; three levels; a move under a parent that denies; expiring and non-expiring delegations; only reached descendants searched; five cross-tenant races (parent against child mutation, two ancestor levels, move against child, suspension against child, parent deny against child deny in opposing order), five to eight runs each, every run ending with an administrator; and one forced interleaving of the two denies that deadlocks with the row lock taken first and passes with the administrator locks taken first.
- `tests/api/v1/test_capability_routers_integration.py` — `409` through the route.
- Negative controls, in the test files: with `AdministratorGuard.verify` replaced by a no-op, the last administrator is removed by a tenant-local mutation, by a parent mutation, by a move and by a suspension; with the descendant search switched off, a parent mutation empties the child.
- Negative control by hand, tenant-local lock removed (run 4): 10 of 25 concurrency runs end with no administrator.
- Negative control by hand, descendant locks removed (run 6): **the cross-tenant races still pass**, 44 local runs. In those scenarios the row locks `can()` already takes serialize the two transactions, so no administrator is lost without the descendant locks. What the locks and their order decide is whether transactions wait or deadlock — which the forced-interleaving test above does demonstrate, failing with `create_deny`'s original lock order and passing with the corrected one.

## What Would Be Difficult to Change Later

The definition. Tenants will arrange their roles around "whoever can assign roles, without an expiry, is an administrator, and one must remain in every tenant". Tightening it (two administrators) would start refusing operations that work today; loosening it reopens the lockout.

## Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)

[ADR-0045](0045-installation-scoped-platform-authority.md) is the repository owner's approved baseline for platform authority (2026-10-12). It governs where it and this ADR differ, within its scope. **Implementation status (updated 2026-10-12).** Phase B of ADR-0045 is implemented in a local working tree: the three platform tables with their exclusion policy and privilege revocations, the platform permission vocabulary, `platform_can()` and `authorize_platform_caller()`, the operator and grant lifecycle, the last-active-platform-owner invariant, platform audit, and the bootstrap and recovery command. At the time of this edit it is not committed or merged. Where this amendment says of a Phase B item that it is "not implemented" or "does not exist yet", that sentence predates Phase B and this paragraph supersedes it. Nothing else in ADR-0045 is implemented. No platform HTTP router and no `/v1/platform` route has been implemented or activated. Phase C (callers on the tenant-lifecycle and feature-flag functions, user deactivation and reactivation, session and API-key revocation, oversight reads) remains separately gated. The last-owner concurrency tests that pass for Phase B do not establish the concurrency correctness of `deactivate_user` or `reactivate_user`, which do not exist. For every item of a phase that has not shipped, the code behaves as the body of this ADR describes: the body is the record of what exists, and this amendment is the record of what has been decided. No test was run for this amendment and none is claimed.

### User deactivation becomes a guarded change

"What this does not cover" says that a deactivation function, when added, "must take the lock and call the guard for each tenant the user is an active member of". ADR-0045 adds `deactivate_user` and applies that requirement. The invariant, the definition of an administrator and `can()` are not changed.

**The difficulty this ADR did not have to face.** Every guarded change so far starts from a tenant and reaches its descendants through the ancestry table. A deactivation starts from a user, and `core.tenant_memberships` is tenant-owned: no query lists a user's tenants. ADR-0045 introduces no membership index and does not weaken the tenant policy. Discovery is a scan of the tenant registry, one tenant scope at a time, bounded by a configured ceiling (default 10 000 tenants). Above the ceiling the operation refuses; it never proceeds on a partial scan.

**The transaction** (ADR-0045 section 11c), in one transaction with no tenant bound:

1. The platform-owners advisory lock; then a preliminary, non-locking authorization check and the ceiling check.
2. A first scan giving the tenants in which the user is an ACTIVE member.
3. `guard_tenants` over those tenants, nearest the root first, then by id.
4. The caller's authorization.
5. An exclusive lock on the user's row.
6. A second scan; a tenant found now and not before aborts the transaction, which is retried.
7. The change: `is_active`, sessions, API keys.
8. `guard.verify`, then the last-platform-owner recheck.

**How it joins this ADR's rules.**

- *Lock, then authorize* ("Authorization after the lock"): kept.
- *Administrator locks before the user's row*: kept. This is the order this ADR reached for `create_deny` after the deadlock it records, and the deactivation is the same shape: an exclusive lock on a user's row, taken after every administrator lock.
- *The guard never invents an administrator*: kept, with its consequence. A tenant that has no administrator, in which the user is made the first one while being deactivated, ends with no active administrator. A guard whose recorded administrator is `None` verifies nothing, here as everywhere in this ADR.
- *Refusal.* `LastTenantAdministratorError` names the tenant, and the whole transaction rolls back. Section "Decision", rule 2, says "nothing is audited". That remains true of the tenant's audit trail. For a platform operation one `denied` row is written to the platform audit table in a separate transaction, as ADR-0031 already does for refusals.
- *A last administrator cannot be deactivated* until the tenant has another. Session and API-key revocation are never refused by this invariant, because they remove no authority.

**Inventory.** The row "Deactivate a user … Nothing to guard" becomes **Guarded** when `deactivate_user` ships. Reactivating a user only adds authority and is not restricted by this invariant. Until then the row is accurate: no Core function sets the column.

### A second invariant, and where its lock sits

ADR-0045 defines a *last-active-platform-owner* invariant on the same pattern as this one: a definition by capability instead of a role, one advisory lock, a recheck on the flushed state, rollback on violation. Its lock is `acquire_tenant_advisory_lock(session, <nil UUID>, "platform.owners")`, the sentinel form the hierarchy lock already uses, with a different key.

**Documented order, extended.** The section "Transactions, locks and concurrency" gives: the change's own administrator lock, before authorization; the descendants' administrator locks; then row locks. With ADR-0045 the order is:

1. the platform-owners lock, for operations that can change who is a platform owner;
2. tenant-administrator locks, in this ADR's order;
3. row locks, including the decision's `FOR SHARE` locks and the tenant-row locks of a move or suspension.

- **Which operations take both.** Only `deactivate_user`. Operator and grant changes take the platform-owners lock and no administrator lock. Every change guarded by this ADR today takes administrator locks and not the platform-owners lock.
- **Hierarchy locks.** `create_tenant` and `move_tenant` take the hierarchy-wide lock and per-node locks. No operation in ADR-0045 takes a hierarchy lock together with the platform-owners lock, so no order between those two is defined, and none is needed until an operation requires both. The order between hierarchy locks and administrator locks inside `move_tenant` is whatever the code has today; ADR-0045 does not change it.
- **Tenant suspension and reactivation by an operator, and a tenant's self-service suspension,** go through `transition_tenant_status` and keep this ADR's descendant guard unchanged. They gain a caller and evidence, nothing else.
- **Creating a child.** ADR-0045 refuses a child beneath a `SUSPENDED` parent and reads the parent's status under a row lock. That bears on the window recorded under "What this does not cover" ("a tenant attached under a tenant in the instant it is suspended") for creation. Whether it closes that window is not claimed here; it was not analysed, and the window for a *move* is untouched.

### What remains possible, in addition to the cases already listed

- **A deadlock that is not removed.** "What remains possible" records that authorization share-locks the caller's row before the reached descendants are locked. If the user being deactivated is, at that moment, the caller of a guarded mutation that reaches a descendant the deactivation has locked, that mutation holds the user's row and waits for the administrator lock, while the deactivation holds the lock and waits for the row. PostgreSQL aborts one. Nothing is changed and a retry succeeds. ADR-0045 does not alter the order in which this ADR's guards take descendant locks, so it cannot remove the cycle.
- **Depth read before a concurrent move.** The deactivation orders administrator locks by depth and then id, from depths it read during its scan. A `move_tenant` that commits between that read and the locking changes those depths. The deactivation may then take two locks in an order that disagrees with a concurrent guarded mutation in the moved subtree. This case was found during this reconciliation. ADR-0045 records it as the seventh of its "Open questions for Phase C" and requires a race test for it. It has not been analysed further: whether it can produce a deadlock, whether either invariant can be violated, and whether the membership and administrator facts the deactivation recorded remain the right ones after the move, are all unverified, and nothing is asserted here about the outcome.

### Not proven

Section "Evidence" lists tests that were run for this ADR. None of them exercises a deactivation operation, because none exists. The correctness of `deactivate_user` under concurrency, and of the last-platform-owner locking, rests on an argument from reading code. ADR-0045 lists the PostgreSQL race tests that must exist and pass (for deactivation, six numbered cases and a seventh for a tenant move during the scan; for the owner invariant, twelve) and makes them a gate: **`deactivate_user` and `reactivate_user` are not exported and not routed until they pass.** One premise of that argument is taken from this ADR's text and was confirmed in code only for membership transitions: that every guarded mutation takes its own tenant's administrator lock as its first statement.

## Related

ADR-0031 (typed callers, same-transaction audit, the row locks `can()` takes — the transactions this check joins); ADR-0040 (the HTTP exposure that made the gap reachable); ADR-0045 (platform authority: user deactivation as a guarded change, the last-platform-owner invariant, the platform-owners lock); ADR-0002 and ADR-0022 (tenant-scoped sessions); `saas_os/core/rbac/authorization.py` (`can`, role scope, delegation, deny); `saas_os/core/rbac/administrators.py`; `saas_os/core/tenancy/service.py` (`move_tenant`, `transition_tenant_status`, `descendant_ids_by_depth`); `docs/P-ROADMAP.md`.
