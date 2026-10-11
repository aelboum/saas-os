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
| Deactivate a user | no Core function sets `core.users.is_active` | — | **Nothing to guard**; an inactive user does not count |
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
- **What remains possible.** `create_deny` locks the denied user's row exclusively before the guard reads other users' rows. Two deny grants in two *unrelated* tenants, each denying a user who is also a member of the other, can still deadlock on those row locks; PostgreSQL aborts one, which surfaces as a database error and changes nothing. No administrator lock is involved and the invariant is not at risk.

## What this does not cover

- **User deactivation.** Core has no function that deactivates a user. When one is added it must take the lock and call the guard for each tenant the user is an active member of.
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
- `tests/core/rbac/test_last_administrator_hierarchy_integration.py` — 46 tests: each of the eight outside-the-tenant scenarios refused, with the tenant named, nothing changed and nothing audited, and allowed once the child has an administrator of its own; three levels; a move under a parent that denies; expiring and non-expiring delegations; only reached descendants searched; five cross-tenant races (parent against child mutation, two ancestor levels, move against child, suspension against child, parent deny against child deny in opposing order), five to eight runs each, every run ending with an administrator and without a deadlock.
- `tests/api/v1/test_capability_routers_integration.py` — `409` through the route.
- Negative controls, in the test files: with `AdministratorGuard.verify` replaced by a no-op, the last administrator is removed by a tenant-local mutation, by a parent mutation, by a move and by a suspension; with the descendant search switched off, a parent mutation empties the child.
- Negative control by hand, tenant-local lock removed (run 4): 10 of 25 concurrency runs end with no administrator.
- Negative control by hand, descendant locks removed (run 6): **the cross-tenant races still pass**, 44 runs. In those scenarios the row locks `can()` already takes serialize the two transactions. The descendant locks are therefore evidenced as a fixed lock order, not as the only thing preventing a lost administrator; they are kept because they make that order explicit and independent of which rows a future change happens to read.

## What Would Be Difficult to Change Later

The definition. Tenants will arrange their roles around "whoever can assign roles, without an expiry, is an administrator, and one must remain in every tenant". Tightening it (two administrators) would start refusing operations that work today; loosening it reopens the lockout.

## Related

ADR-0031 (typed callers, same-transaction audit, the row locks `can()` takes — the transactions this check joins); ADR-0040 (the HTTP exposure that made the gap reachable); ADR-0002 and ADR-0022 (tenant-scoped sessions); `saas_os/core/rbac/authorization.py` (`can`, role scope, delegation, deny); `saas_os/core/rbac/administrators.py`; `saas_os/core/tenancy/service.py` (`move_tenant`, `transition_tenant_status`, `descendant_ids_by_depth`); `docs/P-ROADMAP.md`.
