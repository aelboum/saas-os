# ADR-0031: Foundation authority and evidence — typed callers, same-transaction audit, support-access boundary, `User.is_active`

Status: Accepted and implemented
Date: 2026-10-01
Supersedes / Superseded by: — (builds on [ADR-0022](0022-tenant-session-boundary-enforcement.md) and [ADR-0030](0030-foundation-enforcement.md); refines the Phase E/F/G authorization designs recorded in `core/rbac`)

## Context

Foundation audit findings #2 and #3, confirmed against the code at `2a59d9a`:

**1. Authority-changing Core functions trusted whoever called them.**
- `create_role`, `delete_role`, `grant_permission`, `revoke_permission`, `remove_role`, `remove_service_account_role`, `add_tenant_membership`, `create_service_account`, `disable_service_account`/`enable_service_account`, `revoke_api_key` and `rotate_api_key` took no caller at all and checked nothing.
- `suspend_membership`/`reactivate_membership`/`revoke_membership` took an `actor_user_id` but never authorized it: any value was accepted and simply written into the audit log.
- Where a caller existed it was a bare UUID keyword (`actor_user_id`, `delegator_user_id`, …).
- `revoke_tenant_support_access(actor_user_id=None)` used `None` to mean "the platform".

**2. Privileged changes were not evidenced atomically.**
- Every audited mutation committed its change in one `tenant_session_scope()` transaction and wrote its audit entry afterwards with `core.audit_log.record()`, in a second, independent transaction.
- A failure between the two left an unaudited change.
- `assign_role` (the core privilege grant) and every function listed above wrote no audit entry at all.
- `revoke_api_key`/`rotate_api_key` attributed the action to the key's *owner*, never to whoever revoked or rotated it.

**3. Support access could change authority.**
- An approved support-access grant satisfies every capability except a fixed exclusion list. That list covered delegation/deny grants, service-account roles, support requests, API keys and service accounts, but not `role`, `role_permission`, `membership`, `membership_role` or `invitation`.
- A support engineer could therefore pass `can()` for inviting someone (an invitation becomes a permanent membership) and for the role-management capabilities the gated functions below now require. Any such change would outlive the temporary grant.
- Approve/deny/revoke checked "already decided" outside the transaction that wrote the decision. Two concurrent approvers could both write a decision and both be audited.

**4. `User.is_active` was never read.**
An inactive user could log in, keep using an existing session or API key, and pass `can()`.

## Decision

### 1. An explicit typed caller (`core/authority`)

- **The types.** `UserCaller(user_id)`, `ServiceAccountCaller(service_account_id, tenant_id)` and `SystemCaller(SystemAuthority)` are frozen dataclasses that validate their own fields.
  - `SystemAuthority` names exactly two purposes: `PROVISIONING` (a tenant's initial authority structure, before any principal could hold authority) and `TENANT_PURGE`. *(Three since the amendment of 2026-10-02, which added `BILLING_OPERATIONS`; a fourth, `PLATFORM_BOOTSTRAP`, is decided and not yet implemented — see "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)".)*
  - The package imports only the standard library — no FastAPI, no request context, no other Core module.
  - These name the identities `core.identity` already has; they are not a second identity model.
- **Strict signatures.** Every authority-changing Core function takes a required, keyword-only `caller`, with no default and no legacy actor-id parameter beside it:
  - `core.rbac`: roles, grants, assignments, delegations, denies, support access;
  - `core.identity`: memberships, service accounts, invitations;
  - `core.api_keys`: create, revoke, rotate.
  - `require_caller()` fails closed (`CallerTypeError`) for `None`, a string, a UUID, a dict or a subclass.
  - `tests/architecture/test_authority_contract.py` enforces the signatures and the inventory.
- **No ambient authority.** No Core authority function reads a request context, a global or the correlation context for its caller, and `None` is never a caller. Turning an HTTP request into a caller is the API layer's job. No HTTP route calls these functions yet. *(The last sentence was true when this ADR was accepted and is superseded. Marker added 2026-10-12: since [ADR-0040](0040-reusable-http-platform-capabilities.md), 2026-10-11, the opt-in capability routers in `saas_os/api/v1/` call functions of this inventory, each passing a `UserCaller` built from the authenticated actor: `members.py` (`suspend_membership`, `reactivate_membership`, `revoke_membership`), `invitations.py` (`create_invitation`, `revoke_invitation`) and `api_keys.py` (`create_api_key`, `rotate_api_key`, `revoke_api_key`). No router is mounted by default, and the rest of this bullet is unchanged: no Core function reads a request for its caller. The remaining functions of the inventory have no route. The platform-authority functions decided by [ADR-0045](0045-installation-scoped-platform-authority.md) do not exist yet and have no route.)*
- **System authority is narrow and reviewed.** `SystemCaller` is accepted only by the functions that declare that purpose:
  - `PROVISIONING`: `create_role`, `grant_permission`, `add_tenant_membership`, `create_service_account`, `assign_first_role_for_new_tenant` (the last now *requires* it);
  - `TENANT_PURGE`: `revoke_tenant_support_access`.
  - Shipped code constructs it only in `api/tenant_bootstrap.py` and `core/tenancy/service.py` (purge), which an architecture test pins.

### 2. Authorization through the existing chokepoint

`core.rbac.authorize_caller()` is the single step for the newly gated operations. A principal must hold a dedicated capability through `can()`, so deny-first evaluation, delegation and lifecycle fences all apply unchanged:

| Resource | Actions |
|---|---|
| `role` | `create`, `delete` |
| `role_permission` | `grant`, `revoke` |
| `membership_role` | `delete` |
| `service_account_role` | `delete` |
| `membership` | `create`, `suspend`, `reactivate`, `revoke` |
| `service_account` | `create`, `disable`, `enable` |
| `api_key` | `revoke`, `rotate` (another principal's key) |

Rules beyond the capability check:
- **Anti-amplification for `grant_permission`.** The caller must also already hold the granted permission through ordinary membership-role authority. This is the rule `assign_role`/`create_delegation` already apply. That machinery evaluates human users only, so a service-account caller fails it (fail closed).
- **Own keys.** A user may revoke their own API key, or rotate it while active; a service account may revoke, never rotate, its own key.
- **Previously gated functions** keep their own capability checks and errors.
- **Service accounts** are first-class callers wherever a plain capability suffices.

The policy itself — what `can()` decides — is unchanged.

### 3. Same-transaction evidence

- **The primitive.** `core.audit_log.record_in_transaction(session, *, caller, …)` adds the entry to the mutation's own `tenant_session_scope()` session and flushes it; it never commits.
- **Atomicity.** The change and its evidence commit together or roll back together. A forced failure after both were written leaves neither behind; the integration tests prove this against PostgreSQL.
- **Tenant scope.** RLS refuses an entry for any tenant other than the session's.
- **Actor columns** are derived from the caller, so evidence cannot name a different actor than the one authorized. A `SystemCaller` is recorded as `ActorType.SYSTEM` with `metadata.system_authority`.
- **Coverage.** Every function in the inventory now records in-transaction, including the previously unaudited ones and `assign_role`. API-key mutations run under `tenant_session_scope()` for this.
- **Static guard.** No inventory function calls the separate-transaction `record()`.
- **Denials stay separate.** Audit entries for *refused* attempts (`api_key.validate` denials, `api.access_denied`) intentionally keep `record()`: evidence of a refusal must survive the refusal.

### 3a. Authorization in the mutation's transaction

The decision and the change it authorizes run in one transaction, so a revocation can never commit between them.

- **Session-aware `can()`.** `can(..., session=)` evaluates the whole decision on the caller's session: no other session is opened, nothing is committed or flushed. Without `session` (route guards, billing, bootstrap verification) it runs in one plain `session_scope()` of its own, with the same semantics.
- **Required for mutations.** `authorize_caller()`, `require_active_user()` and the anti-amplification check take a required `session`, and every protected mutation calls them, or `can()`, inside its own `tenant_session_scope()` before writing. `register_permission(..., session=)` upserts in that transaction through a savepoint.
- **Tenant scope.** Each tenant-owned read is RLS-scoped to its candidate tenant through `infra.db.bind_tenant_scope(session, tenant_id)` (`set_config(..., is_local=true)`, parameter-bound, prior scope restored). It grants nothing `tenant_session_scope()` does not; it only keeps the reads in one transaction.
- **Locks, not snapshots.** PostgreSQL runs at READ COMMITTED, so one transaction alone does not freeze what was read. The decision holds every authoritative row `FOR SHARE` until the mutation ends: target and candidate tenants, the actor's `core.users` or service-account row, the consulted membership, the granting `membership_roles`/`service_account_roles` and `role_permissions` rows, the granting delegation or support-access row, and the `core.tenant_ancestry` rows walked. Removal, revocation, suspension, disable, deactivation and `move_tenant()` therefore wait for the authorized mutation, or, if they committed first, are observed: a locking read re-checks a row changed by a committed transaction.
- **Deny is an insert.** There is no existing row to lock for a new `DenyGrant`, so `create_deny*()` locks the denied principal's row `FOR NO KEY UPDATE`, which conflicts with every in-flight decision's `FOR SHARE` on it.
- **Cost.** Revocations briefly wait on in-flight mutations. A deadlock between two such transactions is detected by PostgreSQL and fails one of them closed. No table locks, advisory locks, retries or timing assumptions.
- **Proof.** `tests/core/rbac/test_authorization_transaction_race_integration.py` forces both orderings with real row locks for role, permission, membership, deny, delegation, support-access, API-key, service-account and user-deactivation races.

### 4. Support-access boundary

- **Exclusions.** The resources an approved support grant can never satisfy are now exactly `AUTHORITY_RESOURCES` — every resource whose capabilities gate an authority change, adding `role`, `role_permission`, `membership`, `membership_role` and `invitation`. A support grant still works for ordinary resources.
- **Race fix.** Approve/deny/revoke re-read the request `FOR UPDATE` inside the decision's transaction and re-validate its state, so concurrent decisions serialize and exactly one is written and audited.
- **Self-service request.** Requesting support access requires an existing, active requester. Approval still requires a different approver holding `support_access_request:approve`. The 24-hour maximum window is unchanged.

### 5. `User.is_active`

An inactive user is never an authenticated or authorized application actor:
- **Sessions:** `issue_session` refuses one, and the OIDC callback answers 401. `validate_session` checks the user live on every request, so an existing session stops authenticating at once (401 through the existing dependency chain).
- **API keys:** `validate_api_key` denies a user-owned key, audited as `denied_gate: inactive_user`.
- **Authorization:** `can()` returns `False` for an inactive `USER` actor on every path — ordinary, delegated and support access.
- **Self-service operations** with no capability check of their own (`create_api_key`, `accept_invitation`, `create_support_access_request`) require an active user.
- **Unaffected:** service accounts (their own `status` already gates them), and an inactive user as the *subject* of an administrative action.

Session contract: deactivation does not revoke session rows. While the user is inactive the session is unusable; it still expires on its own schedule, and reactivating the user makes an unexpired session valid again. *(Superseded for the deactivation operation by ADR-0045, decided 2026-10-12 and not yet implemented — see "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)". This sentence still describes the code.)*

## Consequences

- **Breaking change for consumers.** Every listed Core function now requires `caller=`. A consumer passes an explicit `UserCaller`, or for its own initial seeding a `SystemCaller(SystemAuthority.PROVISIONING)`.
  - The reference consumer's `scenarios.py` was updated only at those call sites.
  - Positional order changed only where an actor id was positional: `create_invitation`, `accept_invitation`, `create_api_key`, `create_service_account_api_key` (now keyword-only).
- **Granting the new capabilities.** Tenant administrators need them before they can manage roles, memberships or service accounts; the first-tenant bootstrap's owner permissions are unchanged.
- **New audit rows.** Role, membership and service-account creation now write audit rows. `core.audit_log` references tenants and users, and the runtime role cannot delete audit rows, so test cleanup clears them with the privileged role first.
- **Bootstrap audit actions changed.** The bootstrap command's own `rbac.*` entries are replaced by Core's `role.create`, `role_permission.grant`, `membership.create` and `membership_role.create`.

## Explicitly not part of this decision (deferred)

- **Delegation linkage.** An audit entry for a change authorized through a delegation does not yet record the `delegation_grant_id` that granted the capability.
- **Billing callers.** Billing keeps its own pre-existing typed caller (`BillingActor`/`TrustedSystemCaller`) and post-commit audit. Converging it is billing work. *(Decided 2026-10-02 for Phase 5.3 — see "Amendment (2026-10-02)" below.)*
- **Feature flags and tenant lifecycle.** Feature-flag overrides and tenant lifecycle/hierarchy operations (`create_tenant`, `move_tenant`, `transition_tenant_status`, `purge_tenant` and the `purge_*` steps) keep their current caller and audit shape. Lifecycle Completion owns them. The purge steps are gated by `require_purging_tenant`. *(Decided 2026-10-12 by ADR-0045; not implemented — see "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)".)*
- **Global permission catalog.** `register_permission` takes no caller: defining a capability grants nothing, and the table is global, with no tenant to audit under.
- **User deactivation.** There is no user-deactivation operation (`is_active` is set by an operator) and no session revocation on deactivation. *(Decided 2026-10-12 by ADR-0045; not implemented, and gated on race tests — see "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)".)*
- **Transactional outbox, retries, rate limiting, webhooks** — Reliability & Events.

## Amendment (2026-10-02): billing convergence and the support-access boundary for billing mutations

**Status: Accepted — implemented by Phase 5.3 step 1** (see "Implementation status" below) (Phase 5.3 B2B2C Billing Completion, step 1; [ADR-0029](0029-commercial-parties-and-billing-relationships.md) "Amendment (2026-10-02)"). It resolves the "Billing callers" deferral above. Its implementation is recorded in "Implementation status" below.

### Billing converges on the core authority model

- **Callers.** Billing mutations take a `core.authority` caller: `UserCaller` for a principal, or `SystemCaller` for platform authority.
  - Service-account billing actors remain deferred, because their audit attribution is bound to the account's own tenant (ADR-0029 "Implementation status").
- **Authorization** goes through `core.rbac.authorize_caller()` / `can(session=)` in the protected mutation's own transaction (section 3a), not in a separate transaction as `core/billing/authorization.py::authorize_billing()` did when this amendment was written (converged in step 1).
- **Audit** is written with `record_in_transaction()` in the same transaction as the state change (section 3), replacing the post-commit audit. The entry is written in the tenant that owns the changed row, and the metadata names the other commercial parties.
- **System authority.** The free-form `trusted_system(reason)` / `TrustedSystemCaller` is deprecated. It is replaced by a typed `SystemAuthority` purpose for billing operations (for example `BILLING_OPERATIONS`): an explicit, enumerated purpose rather than caller-supplied text. As for every `SystemAuthority`, a billing operation accepts a `SystemCaller` only for the purposes it lists.
- **`BillingActor`** remains only as a compatibility layer during implementation, and is removed or converged once its callers move to `UserCaller`.

### The provider-call boundary

An external provider call cannot take part in a database transaction. A billing mutation that calls a provider is therefore structured as:

```text
authorize (in a transaction; nothing persisted)
  → provider operation (outside any transaction; idempotency key per ADR-0008)
  → new final transaction:
      re-authorize (can(session=), with the decision's rows locked)
      → re-check preconditions (e.g. plan eligibility, ADR-0029)
      → persist the state change
      → audit (same transaction)
```

- **What is atomic:** only the final transaction. The persisted state and its evidence commit or roll back together.
- **What is not:** the provider operation. If the final transaction refuses (authority revoked, eligibility lost, a lost race), the provider object already created is not deleted automatically. It stays recorded for reconciliation, as in the existing ADR-0029 Phase 3 pattern. Nothing claims the provider call was transactional.

### Support access cannot authorize billing mutations

- **The gap (when this amendment was written; closed in step 1, see "Implementation status"):** section 4 excluded support access by **resource** (`AUTHORITY_RESOURCES`). `billing.*` resources are not in that set, so an approved support grant currently satisfies every billing action at the target tenant, including `billing.account:charge` and `billing.subscription:create`.
- **The change:** the exclusion is extended **by action**. A support grant can never satisfy a billing mutation action:

  | Resource | Mutation actions (never satisfied by support access) |
  |---|---|
  | `billing.subscription` | `create`, `change`, `cancel`, `reactivate` |
  | `billing.account` | `charge`, `manage` |
  | `billing.catalog` | `manage` |
  | `billing.merchant` | `manage` |

  Any billing action added later is classified as a read or a mutation when it is defined.
- **Unchanged:** billing read actions (`billing.subscription:read`, `billing.account:read`, `billing.catalog:read`, `billing.invoice:read`) stay subject to normal authorization, support access included. They are not excluded wholesale.
- **What had to change in the contract:** `_SUPPORT_ACCESS_EXCLUDED_RESOURCES == AUTHORITY_RESOURCES` was resource-level. The implementation adds an action-level exclusion and pins it in `tests/architecture/test_authority_contract.py`.

### Implementation status (Phase 5.3 step 1)

- **Typed purpose.** `SystemAuthority.BILLING_OPERATIONS` (`core/authority/caller.py`). `core/billing/authorization.py::authorize_billing(caller, checks, *, operation, session)`:
  - accepts `UserCaller` (each check through `can(session=session)`) and `SystemCaller(BILLING_OPERATIONS)` only;
  - denies any other system purpose (`BillingNotAuthorizedError`);
  - refuses service accounts and `None` (`BillingActorRequiredError`).
- **Compatibility.** `BillingActor` maps to `UserCaller`, and `trusted_system(reason)` (now emitting `DeprecationWarning`) maps to `SystemCaller(BILLING_OPERATIONS)`. Its reason is only an audit note (`trusted_system_reason`) and never selects an authority.
- **Entry points converged:** `create_merchant_account`, `set_merchant_account_status`, `get_or_create_billing_account`, `create_subscription`, `reconcile_subscription_status`, `cancel_commercial_subscription` and `reconcile_legacy_subscription`.
  - Each authorizes and audits (`record_in_transaction`) in the same transaction as its write.
  - The provider-calling ones authorize first in a transaction that persists nothing, then re-authorize in the final transaction.
- **Support boundary.** `core/rbac/authorization.py::BILLING_MUTATION_ACTIONS` is the action-level exclusion (`_SUPPORT_ACCESS_EXCLUDED_ACTIONS`), pinned in `tests/architecture/test_authority_contract.py`.
- **Not converged in this step.** Each is owned by a later Phase 5.3 step:
  - the legacy trusted paths `subscribe()`, `subscribe_idempotent()`, `upgrade_subscription()`, `cancel_subscription()` and `create_plan()` (step 5, and step 2 for the catalog);
  - `set_tenant_billing_inheritance()` (step 5);

  **Resolved by later steps.**
  - `set_tenant_billing_inheritance()` was removed in step 5. Inheritance changes only through the authorized and audited opt-out and sponsored migration.
  - Step 2 gated `create_plan()` with Catalog v2: owned plans, and explicit legacy adoption.
  - Step 5 made the legacy `upgrade_subscription()`/`cancel_subscription()` fail closed for inheriting tenants.
  - Step 7 fenced them from commercial rows (`LegacyBillingPathError`).
  - The legacy paths remain unauthenticated trusted entry points for genuine legacy rows only; retiring them is deferred.
  - the payer-side `billing.subscription_charged_to_account` record of a sponsored subscription (still deferred at Phase 5.3 completion). It is still written after the service tenant's transaction, because ADR-0029 keeps per-tenant writes in separate transactions. Step 4 gave the payer a durable view (the payer projection) but deliberately did not move this record into the projection consumer, which writes no audit evidence; making it outbox-durable is deferred. The service tenant's own `billing.subscription_created` entry is written in the transaction that inserts the row.

## Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)

[ADR-0045](0045-installation-scoped-platform-authority.md) is the repository owner's approved baseline for platform authority (2026-10-12). It governs where it and this ADR differ, within its scope. **Implementation status (updated 2026-10-12).** Phase B of ADR-0045 is implemented in a local working tree: the three platform tables with their exclusion policy and privilege revocations, the platform permission vocabulary, `platform_can()` and `authorize_platform_caller()`, the operator and grant lifecycle, the last-active-platform-owner invariant, platform audit, and the bootstrap and recovery command. At the time of this edit it is not committed or merged. Where this amendment says of a Phase B item that it is "not implemented" or "does not exist yet", that sentence predates Phase B and this paragraph supersedes it. Nothing else in ADR-0045 is implemented. No platform HTTP router and no `/v1/platform` route has been implemented or activated. Phase C (callers on the tenant-lifecycle and feature-flag functions, user deactivation and reactivation, session and API-key revocation, oversight reads) remains separately gated. The last-owner concurrency tests that pass for Phase B do not establish the concurrency correctness of `deactivate_user` or `reactivate_user`, which do not exist. For every item of a phase that has not shipped, the code behaves as the body of this ADR describes: the body is the record of what exists, and this amendment is the record of what has been decided. No test was run for this amendment and none is claimed.

### Two authorization chokepoints, one identity model

- **Unchanged.** Section 1's callers name the identities `core.identity` has. ADR-0045 adds no caller type: a platform operator is a `UserCaller`.
- **Decided.** A second chokepoint, `platform_can()` with `authorize_platform_caller()`, decides platform operations from platform grant storage only. `can()` and `authorize_caller()` decide tenant operations and are not changed. Neither reads the other's data; an import-linter contract pins that `core.rbac` does not import the platform module. Phase B.
- **`ServiceAccountCaller` is refused by every platform operation.** A service account is owned by one tenant.
- **Platform permissions are not rows in `core.permissions`.** No role, delegation, deny or support-access grant can name one. Section 4's support-access boundary therefore needs no entry for them.

### System authority

Section 1 lists the purposes and the functions that accept each. The decided matrix (ADR-0045 section 5a) is:

| Purpose | Accepted today | Decided additions | Phase |
|---|---|---|---|
| `PROVISIONING` | `create_role`, `grant_permission`, `add_tenant_membership`, `create_service_account`, `assign_first_role_for_new_tenant`, webhook `subscribe` and `unsubscribe` | `create_tenant` for a root tenant or beneath a `PENDING` parent only; `transition_tenant_status` for `PENDING → ACTIVE` only; `create_flag` | C |
| `TENANT_PURGE` | `revoke_tenant_support_access` | `transition_tenant_status` for `DELETED → PURGING` and `PURGING → PURGED` only | C |
| `BILLING_OPERATIONS` | Billing entry points (amendment of 2026-10-02) | None | — |
| `PLATFORM_BOOTSTRAP` (new) | — | Operator enrollment, grant creation and operator suspension, from the bootstrap and recovery command only | B |

- **No system purpose is accepted** for tenant suspension, reactivation, move or deletion; for user deactivation or reactivation; for session or API-key revocation; for a flag override; for grant or operator revocation; for any oversight read; for purge or erasure beyond the two purge transitions above.
- **A `SystemCaller` is not a platform operator.** It holds no grant and `platform_can()` is never evaluated for it.
- **Provisioning and the hierarchy.** A provisioning caller cannot create a child beneath an `ACTIVE` or `SUSPENDED` tenant and cannot move a tenant. In the initial release only a platform operator creates a child beneath an `ACTIVE` tenant; a tenant administrator has no path (ADR-0045 section 12a).
- **Where accepted purposes are declared.** Section 2's `authorize_caller(system_authorities=…)` lets a call site name the purposes it accepts. For platform operations the set comes from one declared operation table, which a call site cannot widen. `authorize_caller` itself is not changed.
- **The reviewed-sites guard.** Section 1 says an architecture test pins where `SystemCaller` is constructed. That test matches a bare-name call only. Decided: match the import instead, pin the importing modules, and assert that no module under `saas_os/api` other than the two command modules imports `SystemCaller` or `SystemAuthority`. Phase B.
- **The limit, unchanged and now stated.** None of this authenticates a `SystemCaller`. Any in-process code can construct one; a consuming product's code is not scanned. A purpose is a label, not a credential, and the static checks are defence in depth. `PROVISIONING` keeps the reach section 1 gave it into any open tenant through membership and role creation; ADR-0045 does not narrow that and records it as deferred.

### Callers and evidence for the functions this ADR deferred

- **Tenant lifecycle and feature flags** ("Feature flags and tenant lifecycle" under "deferred"). `create_tenant`, `move_tenant`, `transition_tenant_status`, `create_flag`, `set_tenant_override` and `remove_tenant_override` gain a required keyword-only `caller` and same-transaction evidence. This is a breaking signature change of the kind "Consequences" describes. Phase C.
- **Two audit tables.** `core.audit_log` and `record_in_transaction` are unchanged: tenant evidence, under the tenant policy, `tenant_id NOT NULL`. Platform evidence goes to a separate table, `core.platform_audit_log`, through its own in-transaction primitive. Section 3's rules carry over to it unchanged: the change and its evidence commit or roll back together; actor columns are derived from the caller; refusals are written separately so that they survive the refusal.
- **Dual evidence.** A platform operation that changes a tenant's state writes the platform row and, in the same transaction, a row in that tenant's `core.audit_log` inside `bind_tenant_scope`, naming the operator as a `user` actor. Platform rows are written only while no tenant is bound, tenant rows only inside a bind block (ADR-0045 section 9c).
- **Failure.** If either row cannot be written the transaction rolls back and the operation did not happen. A refusal leaves no tenant row and one `denied` platform row.
- **Human actors.** No operation performed by a person is recorded as `system`.

### Support access

- **Decided.** `("tenant", "suspend")` joins the action-level exclusions introduced by the amendment of 2026-10-02, when tenant self-service suspension is implemented (Phase C). A support grant can never suspend a tenant.
- **Unchanged.** Support access is the only route to a tenant's data for anyone outside it, and it stays tenant-approved. Platform oversight reads are fixed projections; they neither use nor confer support access (ADR-0045 section 9d).

### `User.is_active`, sessions and API keys

Section 5's session contract reads: "deactivation does not revoke session rows. While the user is inactive the session is unusable; it still expires on its own schedule, and reactivating the user makes an unexpired session valid again." That was written for a system with no deactivation operation, and it still describes what happens when the column is changed directly.

**Decided replacement, for the operations ADR-0045 adds:**

> Deactivating a user revokes every live session and every unrevoked user-owned API key of that user in the same transaction. Reactivating a user restores neither: the user authenticates again and is issued new keys. A revocation takes effect on the next request that presents the credential.

- **The rest of section 5 is unchanged.** An inactive user is never an authenticated or authorized actor; `validate_session`, `validate_api_key` and `can()` keep their live checks. The transactional revocation is added to those checks; it does not replace them.
- **Issuance.** `issue_session` reads the user under `FOR SHARE` in the inserting transaction, and `rotate_api_key` locks the key owner's row `FOR SHARE` and refuses an inactive owner. Without these a credential issued concurrently with a deactivation could outlive it. `reactivate_user` also revokes whatever is still unrevoked before it sets the user active.
- **Separate revocation.** `revoke_user_sessions` and `revoke_user_api_keys` are separately authorized operations that deactivate nobody. API-key revocation is permanent in the existing model: nothing clears `revoked_at`.
- **Not covered.** Service-account keys; a key outliving its owner's *membership* suspension (ADR-0040 gap G3, item 5); a direct edit of `is_active`, which revokes nothing.
- **Observable changes for consumers.** A reactivated user must log in again and needs new keys. An administrator can no longer rotate an inactive user's key. `issue_session` takes a row lock it did not take.

### The gate on `deactivate_user` and `reactivate_user`

**Neither function may be exported from Core or given a route until the PostgreSQL race tests ADR-0045 requires for them (its six numbered cases and the seventh, for a tenant move during the scan) exist and pass.** If they cannot be made to pass with the locking described, both are withdrawn from Phase C, and session and API-key revocation remain the incident path. ADR-0043's amendment of the same date gives the locking.

### Questions only Phase C can answer

Section 3a says the integration tests prove the decision locks "for … user-deactivation races". Those tests change the column directly. They prove that an authorization decision and a concurrent change of `is_active` serialize. They do not prove anything about the new operations. The following seven are open, and are conditions on Phase C, not results. They are the seven questions of ADR-0045, "Open questions for Phase C", which is the authoritative list:

1. Does the locking of `deactivate_user` (ADR-0045 section 11c) hold under its six numbered race tests?
2. Does every ADR-0043-guarded mutation take its administrator lock first? It was read directly only for membership transitions.
3. Is there a limit on the number of API keys a user may hold? None was found, so key revocation is not bounded by a constant.
4. Does `core.audit_log` accept a row for a closed tenant? If not, per-key tenant evidence is omitted for closed tenants.
5. Can `lock_open_tenant` serve as the parent-state lock in `create_tenant`?
6. Does the last-platform-owner locking (ADR-0045 section 6) hold under its twelve concurrency tests?
7. What happens when `move_tenant` commits while `deactivate_user` is between reading tenant depths in its first scan and taking the administrator locks of the tenants it found? The deactivation orders those locks by depths it read earlier, and a move can change them. Whether that can produce a deadlock, whether either invariant can be violated, and whether the facts the deactivation recorded are still the right ones after the move, are unverified. It requires a seventh race test, in addition to the six of question 1.

Neither the deactivation locking nor the last-owner locking is proven.

## Related

[ADR-0002](0002-multi-tenancy-isolation-model.md); [ADR-0022](0022-tenant-session-boundary-enforcement.md); [ADR-0030](0030-foundation-enforcement.md); [ADR-0043](0043-last-tenant-administrator-invariant.md); [ADR-0045](0045-installation-scoped-platform-authority.md); `core/authority/`; `core/audit_log/service.py`; `core/rbac/service.py`; `core/rbac/authorization.py`; `core/identity/service.py`; `core/identity/sessions.py`; `core/api_keys/service.py`.
