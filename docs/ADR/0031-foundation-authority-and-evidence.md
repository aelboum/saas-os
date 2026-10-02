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
  - `SystemAuthority` names exactly two purposes: `PROVISIONING` (a tenant's initial authority structure, before any principal could hold authority) and `TENANT_PURGE`.
  - The package imports only the standard library — no FastAPI, no request context, no other Core module.
  - These name the identities `core.identity` already has; they are not a second identity model.
- **Strict signatures.** Every authority-changing Core function takes a required, keyword-only `caller`, with no default and no legacy actor-id parameter beside it:
  - `core.rbac`: roles, grants, assignments, delegations, denies, support access;
  - `core.identity`: memberships, service accounts, invitations;
  - `core.api_keys`: create, revoke, rotate.
  - `require_caller()` fails closed (`CallerTypeError`) for `None`, a string, a UUID, a dict or a subclass.
  - `tests/architecture/test_authority_contract.py` enforces the signatures and the inventory.
- **No ambient authority.** No Core authority function reads a request context, a global or the correlation context for its caller, and `None` is never a caller. Turning an HTTP request into a caller is the API layer's job. No HTTP route calls these functions yet.
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

Session contract: deactivation does not revoke session rows. While the user is inactive the session is unusable; it still expires on its own schedule, and reactivating the user makes an unexpired session valid again.

## Consequences

- **Breaking change for consumers.** Every listed Core function now requires `caller=`. A consumer passes an explicit `UserCaller`, or for its own initial seeding a `SystemCaller(SystemAuthority.PROVISIONING)`.
  - The reference consumer's `scenarios.py` was updated only at those call sites.
  - Positional order changed only where an actor id was positional: `create_invitation`, `accept_invitation`, `create_api_key`, `create_service_account_api_key` (now keyword-only).
- **Granting the new capabilities.** Tenant administrators need them before they can manage roles, memberships or service accounts; the first-tenant bootstrap's owner permissions are unchanged.
- **New audit rows.** Role, membership and service-account creation now write audit rows. `core.audit_log` references tenants and users, and the runtime role cannot delete audit rows, so test cleanup clears them with the privileged role first.
- **Bootstrap audit actions changed.** The bootstrap command's own `rbac.*` entries are replaced by Core's `role.create`, `role_permission.grant`, `membership.create` and `membership_role.create`.

## Explicitly not part of this decision (deferred)

- **Delegation linkage.** An audit entry for a change authorized through a delegation does not yet record the `delegation_grant_id` that granted the capability.
- **Billing callers.** Billing keeps its own pre-existing typed caller (`BillingActor`/`TrustedSystemCaller`) and post-commit audit. Converging it is billing work.
- **Feature flags and tenant lifecycle.** Feature-flag overrides and tenant lifecycle/hierarchy operations (`create_tenant`, `move_tenant`, `transition_tenant_status`, `purge_tenant` and the `purge_*` steps) keep their current caller and audit shape. Lifecycle Completion owns them. The purge steps are gated by `require_purging_tenant`.
- **Global permission catalog.** `register_permission` takes no caller: defining a capability grants nothing, and the table is global, with no tenant to audit under.
- **User deactivation.** There is no user-deactivation operation (`is_active` is set by an operator) and no session revocation on deactivation.
- **Transactional outbox, retries, rate limiting, webhooks** — Reliability & Events.

## Related

[ADR-0002](0002-multi-tenancy-isolation-model.md); [ADR-0022](0022-tenant-session-boundary-enforcement.md); [ADR-0030](0030-foundation-enforcement.md); `core/authority/`; `core/audit_log/service.py`; `core/rbac/service.py`; `core/rbac/authorization.py`; `core/identity/service.py`; `core/identity/sessions.py`; `core/api_keys/service.py`.
