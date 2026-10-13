# ADR-0045: Installation-scoped platform authority

Status: Accepted (2026-10-12) — accepted by the repository owner as the architecture baseline for platform authority. Phase B is implemented and merged into `main` (merge commit `bb9ca423f3875ee03d73ccb2c24b7d911b3a18eb`, pull request #9); Phase C is implemented and merged into `main` (merge commit `92792d10af982c9bf86693f2b4423a474fa64800`, pull request #13); Phase D is in progress and Phases E and F are not implemented (see "Implementation status"). It incorporates the eight constraints in "Accepted constraints", the design decisions D1–D8 and the rulings R1–R3. No design decision is open. Seven questions that only implementation and tests can answer are listed in "Open questions for Phase C". Each phase needs its own authorization: Phase B was authorized and implemented on 2026-10-12; Phase C was authorized on 2026-10-12 and merged on 2026-10-13; Phases D, E and F were authorized together on 2026-10-13, and Phase D is in progress
Date: 2026-10-12
Supersedes / Superseded by: — (amends [ADR-0002](0002-multi-tenancy-isolation-model.md), [ADR-0022](0022-tenant-session-boundary-enforcement.md), [ADR-0030](0030-foundation-enforcement.md), [ADR-0031](0031-foundation-authority-and-evidence.md), [ADR-0040](0040-reusable-http-platform-capabilities.md) and [ADR-0043](0043-last-tenant-administrator-invariant.md); each of the six carries a section "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)". The amendments record decisions, not implemented behaviour. See "Reconciliation with existing ADRs")

## Context

An audit of the repository at `d5eb2c9` found that SaaS OS has no platform-level principal. The facts below were verified against the code at that commit.

- `saas_os.core.rbac.can()` is tenant-scoped by construction and returns `False` for any actor type other than a user or a service account (`saas_os/core/rbac/authorization.py`).
- `create_tenant`, `move_tenant`, `transition_tenant_status` and `purge_tenant` take no caller and perform no authorization (`saas_os/core/tenancy/service.py`). ADR-0040 recorded this as gap G1 and left it undecided. This ADR decides it (section 12), and ADR-0040 now carries the amendment that says so; the functions themselves are unchanged until Phase C.
- `create_flag`, `set_tenant_override` and `remove_tenant_override` take no caller and check nothing (`saas_os/core/feature_flags/service.py`).
- `core.users.is_active` is enforced on every authentication and authorization path, but no function in `saas_os` writes it. A user's sessions can be revoked only by that user, through `/auth/logout`.
- `core.audit_log.tenant_id` is `NOT NULL` and the table is under tenant RLS. An event with no tenant, such as a login, a tenant creation or a platform grant, cannot be recorded.
- `SystemCaller` is an in-process value. Nothing checks at run time who constructed it. One static test (`tests/architecture/test_authority_contract.py`) pins the modules that construct it, and that test matches only a bare `SystemCaller(...)` call.
- `PLATFORM_TENANT_ID` designates the deployment's commercial tenant and grants no authority (ADR-0029, `saas_os/core/tenancy/service.py::require_platform_tenant`).
- SaaS OS trusts the identity provider's `(issuer, subject)` pair and nothing else. Whoever holds ZITADEL `IAM_OWNER` can take over any subject.

Platform-level power therefore exists today, held by whoever can run code in the process or use the migrations database role, with no principal, no grant and no evidence naming a person.

### Security objectives

1. A person exercises platform authority only through an explicit, revocable grant recorded in that deployment's own database.
2. Platform authority and tenant authority are separate systems. Neither can be obtained through the other.
3. Platform authority does not include access to customer data.
4. Every platform operation leaves evidence naming the acting person, written in the same transaction as the change.
5. The deployment can never be left without a person able to administer platform authority, and can recover if it is.
6. No row-level security policy, database role or tenant boundary is weakened.

### Accepted constraints

Approved by the repository owner on 2026-10-12. This ADR treats them as fixed.

1. **Installation-scoped.** Each deployment holds its own platform grants. A grant in one deployment confers nothing in another.
2. **Distinct authority model.** Platform authority has its own type and its own storage. It is not a tenant RBAC role, and designating a tenant with `PLATFORM_TENANT_ID` grants nothing.
3. **HTTP.** Platform administration may be exposed through an explicitly opt-in router. Permissions are enforced in Core, not only at the route.
4. **Tenant data.** No unrestricted access to customer data. Customer-data access uses the existing tenant-approved support-access mechanism. Only narrow, data-minimized operational oversight is allowed.
5. **Destructive operations.** Tenant purge and identity erasure stay CLI-only. Migrations and infrastructure operations stay operator responsibilities.
6. **Platform audit.** A separate platform audit table. `core.audit_log.tenant_id NOT NULL` and its RLS are not relaxed.
7. **ZITADEL `IAM_OWNER`** is tier-0 infrastructure authority outside SaaS OS's authorization boundary, addressed by compensating controls, documentation and auditability.
8. **Tenant self-service suspension** is permitted with explicit authorization and safeguards. Tenant administrators do not gain deletion or purge authority.

## Options Considered

The constraints above already rule out a tenant role and a shared operator organization. The options that remained open concern how the distinct model is shaped.

### Option A — A new caller type for platform operators, next to `UserCaller`
- Advantages: the type itself says "platform".
- Disadvantages: a platform operator is a `core.users` user who logged in like anyone else. A second caller type for the same identity lets a call site choose which authority to claim, which is the ambient-authority pattern ADR-0031 removed. ADR-0031 states that callers "name the identities `core.identity` already has; they are not a second identity model".

### Option B — `UserCaller` names the person; a separate chokepoint decides platform authority (recommended)
A platform operation takes the existing `UserCaller` and is authorized by a new function, `platform_can()`, that reads only platform grant storage. The distinct authority type required by constraint 2 is the grant, the closed permission vocabulary and the chokepoint, not a new way to name a person.
- Advantages: one identity model; who is acting is never a call-site choice; mirrors `can()`'s transaction and locking discipline; `can()` is untouched.
- Disadvantages: two authorization functions exist, and each operation must call the right one. Addressed by keeping the vocabularies disjoint and by architecture tests.

### Option C — Platform permissions stored in the tenant permission catalog (`core.permissions`) with a sentinel tenant
- Advantages: reuses `can()`.
- Disadvantages: contradicts constraint 2. A platform permission would become assignable to a tenant role, delegable, and reachable through a SUBTREE role at a root tenant.

### For the grant shape: named bundles ("owner", "operator", "viewer") or individual permissions
- *Bundles*: easy to explain, but a bundle is a role hierarchy by another name, and its content drifts as permissions are added.
- *Individual permissions, closed vocabulary* (recommended): a grant names exactly one permission. "Platform Owner" is a definition over grants (below), in the way ADR-0043 defines a tenant administrator by a capability instead of a role.

### For the last-owner invariant: count check under a row lock, or one deployment-wide advisory lock
- *Row locks only*: revoking a grant is an update, but enrolling and granting are inserts, and two revocations of two different owners touch disjoint rows. Each can pass its own check and both commit.
- *One advisory lock taken first* (recommended): the mechanism ADR-0043 and the tenant hierarchy already use (`saas_os.infra.db.acquire_tenant_advisory_lock`). Platform authority changes are rare, so serializing them costs nothing.

## Recommendation

Option B, individual permissions from a closed vocabulary, and one advisory lock for the last-owner invariant.

## Decision

**Accepted by the repository owner on 2026-10-12.** The sections below are the accepted design. Only the Phase B part of it is implemented ("Implementation status"), and where a section says that something is unproven, unverified or an argument from reading code, acceptance does not change that.

### 1. Authority boundaries

Five authorities exist around a deployment. They are listed with what each may do and how each is established. No authority implies another.

| Authority | Established by | May do | May not do |
|---|---|---|---|
| **Infrastructure (tier 0)** | Possession of host access, the migrations database role, deployment secrets, or ZITADEL `IAM_OWNER` | Everything, including bypassing SaaS OS | — (outside SaaS OS's boundary; see section 10) |
| **Platform** | An unrevoked grant in `core.platform_grants` held by an active operator who is an active user | The operations in the permission table (section 4) | Read or change tenant-owned data; hold or assign tenant roles by virtue of the grant; purge or erase |
| **Tenant administration** | Tenant membership, roles, delegation (`can()`), unchanged | Administer one tenant and, with SUBTREE scope, its descendants | Any platform operation |
| **Support access** | A `SupportAccessRequest` approved by the tenant, time-bounded, unchanged | Non-authority, non-billing-mutation actions in that tenant for the window | Authority resources, billing mutations, any platform operation |
| **Product administration** | Permissions a product registers and assigns in its tenants | Product business functions | Anything in SaaS OS beyond what `can()` grants |

A SaaS OS code maintainer has none of these in a deployment by virtue of maintaining the code. The runtime shares no credential with the repository.

**In-process code is trusted.** A consuming product runs in the same process as Core, with the same database role. It can construct any caller and write any row the application role may write. This ADR does not, and cannot in Python, defend against the product's own code. The boundary it defends is between *principals* arriving over a request or a command, not between Python modules. Section 5a states what is and is not done about it.

### 2. Installation-scoped trust model

- A deployment is one database (ADR-0015 rule 3). Platform grants are rows in that database, keyed by that database's `core.users.id`.
- There is no deployment identifier in a grant and no lookup outside the database. A second deployment has a different `core.users` table, different session rows and different grants, so the same person, or the same identity-provider subject, has no authority there until that deployment grants it.
- A shared operator identity across products is possible later through the identity provider. It would give the same `(issuer, subject)` in two deployments and nothing more.
- **A database copy copies authority.** Restoring or cloning a production database into another environment carries the grants with it. This is a property of installation scope and is handled operationally (section 10, runbook), not hidden.

### 3. Principal and grant model

A platform operator is a `core.users` user enrolled as an operator. Two new tables, both in the `core` schema, both classified `GLOBAL` in `saas_os/core/tenancy/isolation.py` (they have no tenant) and `SECURITY_RETAIN` in `saas_os/core/tenancy/retention.py`.

**`core.platform_operators`** — one live row per enrolled user.

| Column | Notes |
|---|---|
| `id` | UUID primary key |
| `user_id` | FK `core.users.id`; unique among rows whose status is not `revoked` |
| `status` | `active`, `suspended` or `revoked`, with a CHECK; `revoked` is terminal |
| `enrolled_by_user_id` | Nullable FK `core.users.id`; `NULL` means enrolled by the bootstrap or recovery command |
| `status_changed_at`, `status_changed_by_user_id` | Last transition |
| `created_at`, `updated_at` | |

**`core.platform_grants`** — one row per permission granted to an operator.

| Column | Notes |
|---|---|
| `id` | UUID primary key |
| `operator_id` | FK `core.platform_operators.id` |
| `permission` | One value of the closed vocabulary in section 4, with a CHECK |
| `granted_by_user_id` | Nullable; `NULL` means the bootstrap or recovery command |
| `granted_at` | |
| `revoked_at`, `revoked_by_user_id` | A grant is revoked, never deleted |

A partial unique index on `(operator_id, permission) WHERE revoked_at IS NULL` prevents duplicate live grants. The no-self-grant rule (section 6) is to be enforced in the grant operation and remains to be pinned by a test (Phase B; no such test exists yet); a grant row does not carry the operator's user id, so a CHECK constraint cannot express it without a redundant column, and none is proposed.

Neither table has a `tenant_id` column, so the canonical tenant policy (`saas_os/infra/db/rls.py`) cannot apply to them. That alone is not an isolation policy; section 9 states what the database enforces for these tables, what it does not, and what is left to Core.

**History and re-granting.** A grant row is never updated except to set `revoked_at` and `revoked_by_user_id`, once. Granting the same permission again inserts a new row; the partial unique index allows it because the old row is no longer live. The sequence of rows for one `(operator_id, permission)` is therefore the grant history, and `platform.operator:read` returns revoked rows as well as live ones.

**Re-enrolling a revoked operator.** Allowed. It creates a new `core.platform_operators` row for the same user (the partial uniqueness excludes `revoked` rows) with no grants; nothing is carried over from the revoked row, which stays as history. It requires `platform.authority:manage` held by a different person, like any enrollment, or the recovery command. The audit row records the previous operator id in its metadata so the re-enrollment is visible as one.

**A platform owner** is not a role. It is a definition: an operator with status `active`, whose user has `is_active = true`, holding an unrevoked `platform.authority:manage` grant. Whoever can manage platform authority can grant every other platform permission, so it is the capability the deployment cannot recover from inside once nobody holds it.

Suspension is on the operator, not on a grant: a suspended operator keeps the grant rows and has no authority until reactivated. Revoking an operator is terminal and revokes every live grant in the same transaction. Enrolling the same user again creates a new operator row with no grants.

### 4. Platform permissions

A closed enumeration in code (`PlatformPermission`) with **eighteen** members: six oversight, eleven operations, one authority. It is not stored in `core.permissions`, so a platform permission cannot be attached to a tenant role, delegated, denied or satisfied by support access. Holding one permission implies no other.

**Oversight (read-only, data-minimized)**

| Permission | Allows | Returns (the complete projection; section 9 gives the access path) |
|---|---|---|
| `platform.tenant:read` | List and read the tenant registry | `id`, `name`, `status`, `parent_id`, `created_at`, `updated_at` |
| `platform.user:read` | Resolve one user by id or by `(issuer, subject)`, for incident response | `id`, `is_active`, `created_at`, whether the user is an enrolled operator, the number of live sessions, and for at most 50 most recent sessions: `id`, `created_at`, `expires_at`, `revoked_at`. Never a token hash, never the issuer or subject, never the user's tenants |
| `platform.operator:read` | List operators and their grants | Operator and grant rows, including revoked ones |
| `platform.audit:read` | Read the platform audit table | Platform audit rows |
| `platform.billing:read` | Commercial overview across tenants | Per service tenant, at most 10 most recently updated subscriptions: `status`, plan `key`, `payer_tenant_id`, `updated_at`. Never a provider customer, subscription or price id, a billing or merchant account id, an invoice, or payment detail |
| `platform.feature_flag:read` | Read the flag catalog and one named tenant's overrides | Flag `key`, `enabled_by_default`; for the named tenant, flag `key` and `enabled` |

Two fields the first draft listed are not available and are not part of the projection. A subscription **period end** is not stored anywhere in `saas_os/core/billing`; returning it would need a provider call or a schema change, and neither is proposed. A user's **tenant memberships** are tenant-owned rows that no query can read across tenants (`docs/MULTI-TENANCY.md` section 5: "tenant discovery is the caller's responsibility"); listing them for an operator is a disclosure decision left to "Deferred".

**Operations (change platform or tenant-lifecycle state; no tenant data)**

| Permission | Allows |
|---|---|
| `platform.tenant:create` | Create a tenant, as a root or under a `PENDING` or `ACTIVE` parent (section 12a), and activate it |
| `platform.tenant:suspend` | `ACTIVE → SUSPENDED` for any tenant |
| `platform.tenant:reactivate` | `SUSPENDED → ACTIVE` |
| `platform.tenant:move` | Re-parent a tenant. No HTTP route (section 7) |
| `platform.tenant:delete` | `→ DELETED`, the irreversible entry to the purge workflow. No HTTP route |
| `platform.user:deactivate` | Set `is_active = false` and revoke the user's sessions and user-owned API keys (section 11) |
| `platform.user:reactivate` | Set `is_active = true` |
| `platform.session:revoke` | Revoke all sessions of a named user without deactivating |
| `platform.api_key:revoke` | Revoke every unrevoked user-owned API key of one named user, without deactivating (section 11f, ruling R2). Nothing else: not creating, rotating, listing or reading a key, and not a service account's keys |
| `platform.feature_flag:define` | Create a flag definition |
| `platform.feature_flag:override` | Set or remove a tenant override |

**Authority (changes who holds platform authority)**

| Permission | Allows |
|---|---|
| `platform.authority:manage` | Enroll, suspend, reactivate and revoke operators; grant and revoke platform permissions |

There is no permission for purge, identity erasure, migrations, backup, owner bootstrap or recovery. Those are infrastructure operations (section 7).

**What no platform permission allows.** Reading or writing a tenant-owned table's rows other than through the fixed projections above; adding a membership; assigning, creating or changing a tenant role; creating a delegation or deny grant; approving, denying or revoking a support-access request; issuing or rotating an API key, or reading a key's name, hash or tenant; creating a child tenant on behalf of a tenant administrator; changing a subscription. A platform operator who needs to see customer data files a support-access request and the tenant approves it, exactly as today.

### 5. The platform authorization chokepoint

`platform_can(*, user_id, permission, session=None) -> bool`, in a new Core module (working name `saas_os.core.platform_authority`).

- **Evaluation.** The user exists and `is_active`; an operator row for that user has status `active`; a grant for `permission` on that operator is unrevoked. Any missing link returns `False`. It never raises and never defaults to allow.
- **What it never reads.** Tenant memberships, roles, role permissions, delegation grants, deny grants, support-access requests, tenant status, `PLATFORM_TENANT_ID`.
- **What `can()` never reads.** Platform operators or grants. `saas_os.core.rbac` does not import the platform authority module; an import-linter contract pins this. The rule is about direct imports: no module of `saas_os.core.rbac` imports the package. It is not a claim that no import path exists, because `saas_os.core.rbac` imports `saas_os.core.tenancy` and `saas_os.core.identity`, and section 12a requires functions there to call `authorize_platform_caller`. Which modules import the package at all is pinned by an architecture test, module by module ("Implementation status", amendment of 2026-10-12).
- **Transaction.** Same model as ADR-0031 section 3a. With `session`, the decision runs in the mutation's own transaction and holds the user row, the operator row and the grant row `FOR SHARE` until that transaction ends, so a revocation, suspension or deactivation either committed first and is observed, or waits. Without `session` (a route guard, a read) it runs in one `session_scope()` of its own.

`authorize_platform_caller(caller, *, session, operation)` is the single step a platform operation calls, parallel to `saas_os.core.rbac.authorize_caller`. The permission and the accepted system purposes come from the declared operation table (section 5a), not from the call site:

| Caller | Treatment |
|---|---|
| `UserCaller` | Must pass `platform_can()` for `permission` in `session` |
| `ServiceAccountCaller` | Always refused. A service account is owned by one tenant; a tenant-owned principal never holds platform authority. A machine platform principal is not designed here and depends on the API-key authentication decision (ADR-0040 G3) |
| `SystemCaller` | Accepted only if its purpose is in the set the operation table declares for that operation; otherwise refused |
| anything else, `None` | `CallerTypeError`, before any read |

#### 5a. System authority

A `SystemCaller` is not a platform operator. It names no person, it is never looked up in `core.platform_operators`, it holds no grant, and `platform_can()` is never evaluated for it. It is accepted by an operation only when that operation lists its purpose, and it is recorded as actor type `system`, never as a user.

**Purpose-to-operation matrix.** "Today" was read from the code at `d5eb2c9`; "Decided" is this design, not yet implemented. A purpose is accepted by the operations in its row and by no other.

| Purpose | Accepted today | Decided additions | Never accepted (stated so that tests can pin it) |
|---|---|---|---|
| `PROVISIONING` | `create_role`, `grant_permission`, `add_tenant_membership`, `create_service_account`, `assign_first_role_for_new_tenant`, webhook `subscribe` and `unsubscribe` | `create_tenant`, only for a root tenant or under a `PENDING` parent (section 12a); `transition_tenant_status` for `PENDING → ACTIVE` only; `create_flag` | Any other transition (suspend, reactivate, delete, purging, purged); `move_tenant`; `create_tenant` under an `ACTIVE` or `SUSPENDED` parent; `deactivate_user`, `reactivate_user`, `revoke_user_sessions`, `revoke_user_api_keys`; flag overrides; every operator and grant operation; every oversight read; purge; erasure |
| `TENANT_PURGE` | `revoke_tenant_support_access` (inside `purge_tenant`) | `transition_tenant_status` for `DELETED → PURGING` and `PURGING → PURGED` only | Everything else, including `→ DELETED` |
| `BILLING_OPERATIONS` | Billing entry points only (ADR-0031 amendment 2026-10-02) | None | Every operation in this ADR |
| `PLATFORM_BOOTSTRAP` (new) | — | `enroll_operator`, `grant_platform_permission`, `suspend_operator` | Grant revocation, operator revocation, operator reactivation, every tenant, user, session, API-key, flag and oversight operation |

`PROVISIONING` is kept for tenant creation because the first-tenant bootstrap, the reference consumer's seed code and a product's own "create my organization" flow (assigned to the product by ADR-0040) all create a tenant before any principal in it could hold authority. `create_tenant` and activation take no caller at all today, so accepting exactly one purpose for exactly those two steps narrows what exists; it does not widen it.

**What `PROVISIONING` already reaches, unchanged by this design.** `add_tenant_membership`, `create_role` and `grant_permission` accept it for any open tenant, and `assign_first_role_for_new_tenant` checks that the tenant is open, not that it is new. In-process code holding a provisioning caller can therefore already give a user a role in an existing tenant. That is tenant authority, not platform authority, it predates this ADR, and this ADR neither relies on it nor extends it. It is recorded here because it bounds what "narrow" can honestly mean for this purpose.

**Enforcement (decided, not implemented).**

1. *One declared table.* A single mapping in `saas_os.core.platform_authority` (working name `PLATFORM_OPERATIONS`) gives, for each platform operation, its `PlatformPermission` and the frozen set of system purposes it accepts, most often empty. `authorize_platform_caller` takes the operation's key and reads the set from that table. A call site cannot pass a wider set, which the existing `authorize_caller(system_authorities=…)` shape allows. A unit test compares the table with the matrix above, row by row.
2. *Transition-level check.* `transition_tenant_status` selects the operation key from the `(from, to)` pair after reading the tenant row under its existing lock, so a provisioning caller presenting `PENDING → ACTIVE` against a tenant that is in fact `SUSPENDED` is refused on the state actually read.
3. *Request paths never name a purpose.* In `saas_os/api`, the caller of a Core function is built in one place from the authenticated actor and is always a `UserCaller` or a `ServiceAccountCaller`. No request model, header, query parameter or path segment is ever parsed into a `SystemAuthority`. An architecture test asserts that no module under `saas_os/api` imports `SystemCaller` or `SystemAuthority`, except the two command modules (`tenant_bootstrap.py`, `platform_bootstrap.py`), which are not routers; and that no route module imports those two.
4. *Static site guard, hardened.* `tests/architecture/test_authority_contract.py` today matches only a bare-name `SystemCaller(...)` call. The proposal is to match the import instead (any `import` or `from … import` of `SystemCaller`, `SystemAuthority` or `trusted_system`, under any alias) and to pin the set of importing modules.

**What this is and is not.** Items 1 and 2 are run-time checks on which purpose reaches which operation. Items 3 and 4 are static checks on this repository's own source. None of them authenticates a `SystemCaller`: any code in the process can construct one, and a consuming product's code is not scanned at all. A purpose value is a label, not a credential. The security claim is therefore limited to this: *a request that arrives over HTTP cannot obtain system authority unless in-process code deliberately constructs it on that request's behalf.* A product that builds a sign-up endpoint does exactly that for `create_tenant`. The one request-supplied input that could turn that into authority over somebody else's hierarchy is the parent tenant, and section 12a restricts it inside Core (decision D5).

#### 5b. Operation inventory

The declared operation table of 5a, written out. It is the one place where an operation, its permission, the system purposes it accepts and its audit action are tied together; a unit test compares the table in code with this one. "Tenant row" means a row in the affected tenant's own `core.audit_log`, written in the same transaction (section 8).

| Operation key | Core function | Permission | System purposes | Platform audit action | Tenant row |
|---|---|---|---|---|---|
| `tenant.read` | registry list and read | `platform.tenant:read` | — | `platform.tenant.read` | no |
| `user.read` | resolve one user | `platform.user:read` | — | `platform.user.read` | no |
| `operator.read` | list operators and grants | `platform.operator:read` | — | `platform.operator.read` | no |
| `audit.read` | read platform audit | `platform.audit:read` | — | `platform.audit.read` | no |
| `billing.read` | commercial overview | `platform.billing:read` | — | `platform.billing.read` | no |
| `feature_flag.read` | flag catalog; one tenant's overrides | `platform.feature_flag:read` | — | `platform.feature_flag.read` | no |
| `tenant.create_root` | `create_tenant`, no parent | `platform.tenant:create` | `PROVISIONING` | `platform.tenant.create` | new tenant |
| `tenant.create_child` | `create_tenant`, with parent | `platform.tenant:create` | `PROVISIONING`, and then only under a `PENDING` parent | `platform.tenant.create` | new tenant and parent |
| `tenant.activate` | `PENDING → ACTIVE` | `platform.tenant:create` | `PROVISIONING` | `platform.tenant.activate` | yes |
| `tenant.suspend` | `ACTIVE → SUSPENDED` by an operator | `platform.tenant:suspend` | — | `platform.tenant.suspend` | yes |
| `tenant.reactivate` | `SUSPENDED → ACTIVE` | `platform.tenant:reactivate` | — | `platform.tenant.reactivate` | yes |
| `tenant.move` | `move_tenant` | `platform.tenant:move` | — | `platform.tenant.move` | tenant, old and new parent |
| `tenant.delete` | `→ DELETED` | `platform.tenant:delete` | — | `platform.tenant.delete` | yes |
| `tenant.purge_transition` | `→ PURGING`, `→ PURGED` | none | `TENANT_PURGE` | `platform.tenant.purge_transition` | existing purge events |
| `user.deactivate` | `deactivate_user` | `platform.user:deactivate` | — | `platform.user.deactivate` | one `api_key.revoke` per revoked key |
| `user.reactivate` | `reactivate_user` | `platform.user:reactivate` | — | `platform.user.reactivate` | one `api_key.revoke` per key it had to revoke |
| `session.revoke` | `revoke_user_sessions` | `platform.session:revoke` | — | `platform.session.revoke` | no |
| `api_key.revoke` | `revoke_user_api_keys` | `platform.api_key:revoke` | — | `platform.api_key.revoke` | one `api_key.revoke` per revoked key |
| `feature_flag.define` | `create_flag` | `platform.feature_flag:define` | `PROVISIONING` | `platform.feature_flag.define` | no |
| `feature_flag.override` | set or remove a tenant override | `platform.feature_flag:override` | — | `platform.feature_flag.override` | yes |
| `operator.enroll` | `enroll_operator` | `platform.authority:manage` | `PLATFORM_BOOTSTRAP` | `platform.operator.enroll` | no |
| `operator.suspend` | `suspend_operator` | `platform.authority:manage` | `PLATFORM_BOOTSTRAP` | `platform.operator.suspend` | no |
| `operator.reactivate` | `reactivate_operator` | `platform.authority:manage` | — | `platform.operator.reactivate` | no |
| `operator.revoke` | `revoke_operator` | `platform.authority:manage` | — | `platform.operator.revoke` | no |
| `grant.create` | `grant_platform_permission` | `platform.authority:manage` | `PLATFORM_BOOTSTRAP` | `platform.grant.create` | no |
| `grant.revoke` | `revoke_platform_permission` | `platform.authority:manage` | — | `platform.grant.revoke` | no |

Two events have no operation key because nobody is authorized for them: `platform.operator.session_issued`, written by the OIDC callback, and the refusal rows, which reuse the action of the operation refused with outcome `denied`. Two further actions are derived or stand alone (added 2026-10-13): the attempt row of an oversight read uses the read's action with the suffix `_attempt` (`platform.tenant.read_attempt`, `platform.billing.read_attempt`; section 8), and the refusal of an identity erasure (section 6) is recorded as `platform.user.erase` with outcome `denied`. Erasure is not a platform operation and has no row here; that action exists only for its refusal. Tenant self-service suspension (section 12) is a tenant operation authorized by `can()` and is not in this table. All eighteen permissions appear in the table, and no permission appears that is not in section 4.

**Refusal labels that are not operations (added 2026-10-13, before Phase D).** A refusal names what was refused in its `operation` attribute. That value is a key of the table above or a member of one closed set, declared next to the table (`NON_OPERATION_REFUSALS` in `saas_os/core/platform_authority/operations.py`), and nothing else: `user.erase` (identity erasure; its refusal is recorded as `platform.user.erase`), `tenant.transition` (the name under which `transition_tenant_status` refuses a caller of the wrong type before the edge is known; never recorded), and `platform.bootstrap` and `platform.recover` (the two composites of section 6, whose refusal rows reuse the action of the first operation they would have performed). None of the four is a platform operation: none has a permission, a system purpose or a row in the table, and no route or policy may be derived from them. Identity erasure in particular stays what sections 4 and 7 say it is. A refusal cannot be constructed with any other value -- that is a programming error (`UnknownPlatformOperationError`), exactly as an unknown key is at the chokepoint. A handler maps a refusal by its type and its `code`, never by looking its `operation` up in the operation table.

### 6. Grants: creation, suspension, revocation, recovery

**Rules for every authority change made by a person**

- The caller holds `platform.authority:manage` (through `authorize_platform_caller`).
- **No self-service.** A caller may not grant to, revoke from, suspend, reactivate or revoke their own operator, and may not deactivate their own user (section 11). The check compares the caller's user id with the subject operator's `user_id` inside the operation, so it holds for every entry point, not only for routes. A sole owner therefore cannot widen or remove their own authority; a second owner or the recovery command does it. Recovery is a separate break-glass procedure, not an operator action.
- **Anti-amplification.** A caller may grant only a permission they themselves hold, the rule `assign_role` and `create_delegation` already apply.
- **Least privilege after bootstrap.** Only the first owner receives a set of permissions in one step. Every later grant is one permission, named explicitly, authorized and audited on its own. There is no "copy this operator's grants" and no bundle.
- The subject user must exist and be active to be enrolled or granted to.
- A bounded, non-empty `reason` is required and recorded.

**Bootstrap** — `python -m saas_os.api.platform_bootstrap bootstrap`, following `saas_os/api/tenant_bootstrap.py`.

- Runs as the restricted application role (`validate_application_role`), never the migrations role.
- Takes the owner's `(issuer, subject)`; the issuer must equal the configured OIDC issuer. Resolves or creates the user with the existing `get_or_create_user_for_external_identity`.
- Refuses if any operator row exists, in any status. A deployment is bootstrapped once.
- Grants the first owner an explicit initial permission set (decision D8): a literal tuple of `PlatformPermission` members written out in the command module, `BOOTSTRAP_PERMISSIONS`. It is not computed from the enumeration, so adding a permission to the vocabulary changes nothing about what bootstrap grants. The list holds all eighteen permissions of section 4, because nobody exists yet who could grant a missing one and anti-amplification would otherwise leave it ungrantable from inside. Written out, in the order of section 4:

  ```
  BOOTSTRAP_PERMISSIONS = (
      platform.tenant:read,
      platform.user:read,
      platform.operator:read,
      platform.audit:read,
      platform.billing:read,
      platform.feature_flag:read,
      platform.tenant:create,
      platform.tenant:suspend,
      platform.tenant:reactivate,
      platform.tenant:move,
      platform.tenant:delete,
      platform.user:deactivate,
      platform.user:reactivate,
      platform.session:revoke,
      platform.api_key:revoke,
      platform.feature_flag:define,
      platform.feature_flag:override,
      platform.authority:manage,
  )
  NOT_GRANTED_AT_BOOTSTRAP = ()
  ```

  `platform.api_key:revoke` is in the tuple because ruling R2 added it to the vocabulary before any deployment was bootstrapped. That is an explicit entry in a reviewed literal, not an automatic grant: had a deployment already existed, its owners would not have received it (see "Later additions").
  - *Validation in the repository.* A second literal, `NOT_GRANTED_AT_BOOTSTRAP` (empty today), sits next to it. A unit test asserts that the two are disjoint and that their union equals the vocabulary. Adding a permission therefore fails the test until a reviewer places the new permission in one list or the other; it cannot be granted, or left out, by omission. A second test pins the bootstrap tuple against a copy written in the test, so a change to it is always a visible diff in two files.
  - *Validation at run time.* Before opening a transaction the command checks that every entry is a member of `PlatformPermission` and that there are no duplicates. A mismatch exits non-zero with nothing written. The database CHECK on `core.platform_grants.permission` is the last line: a value outside the vocabulary aborts the transaction, which leaves no operator and no grant.
  - *Later additions.* A permission added after a deployment was bootstrapped is held by nobody there. Existing owners do not receive it. The first holder is created by the recovery command, explicitly and audited; from then on it is granted like any other.
- Requires `--confirm-production` when `ENVIRONMENT=production`.
- Idempotent: an identical second run changes nothing and exits successfully.
- Writes platform audit rows with actor type `system` and `system_authority = platform_bootstrap`, in the same transaction.

**Recovery** — `python -m saas_os.api.platform_bootstrap recover`.

- For lockout (no owner can act) and for compromise (an owner must be stopped and no other owner exists).
- May enroll and grant a named identity, and may suspend a named operator. It never revokes or deletes: suspension is reversible, so a mistaken recovery can be undone, and the evidence stays.
- **Replacing an owner.** One invocation may carry both an enrollment with grants and a suspension, and runs as one transaction under the platform-owners lock with the last-owner recheck at the end. Suspending the only owner without enrolling a replacement that holds `platform.authority:manage` in the same invocation is refused; the deployment is never ownerless between two commands.
- Requires `--reason` and, in production, `--confirm-production`. Works whether or not an owner exists.
- **Trust assumption.** It is not a security boundary and is not described as one. It runs with the application role's database credentials; whoever can run it already holds tier-0 access and could write the rows directly, without the lock and without the audit row. The command adds no protection against that person. What it adds is that the legitimate path is the convenient one and leaves evidence.
- **Operational controls** (runbook, Phase E; none is enforced by SaaS OS): the credentials it needs are held by the people who hold other tier-0 credentials and by nobody else; a recovery is performed by two people; the reason given is a ticket or incident reference; the platform audit is reviewed after every recovery.
- **Evidence.** Every run writes platform audit rows with actor type `system` and `system_authority = platform_bootstrap`, the reason, and the enrolled or suspended operator as target, in the same transaction as the change, plus a structured log line at warning level. The rows cannot name the person at the keyboard, because SaaS OS has no way to know who that is; the runbook's ticket reference is the link.
- It is reachable only as a command. No route, no router and no Core function reachable from a route accepts `PLATFORM_BOOTSTRAP`.

**Last-active-platform-owner invariant**

*After every supported change, a deployment that had a platform owner still has one.*

The specification below is written to be implemented as stated. It has been reasoned through on paper against the locking primitives the repository has. **It is not proven.** It becomes evidence only when the concurrency tests listed at the end of this section exist and have been run against PostgreSQL in an authorized later phase.

*1. Predicate.* A platform owner exists when this query returns a row:

```sql
SELECT 1
FROM core.platform_operators o
JOIN core.users u            ON u.id = o.user_id
JOIN core.platform_grants g  ON g.operator_id = o.id
WHERE o.status = 'active'
  AND u.is_active
  AND g.permission = 'platform.authority:manage'
  AND g.revoked_at IS NULL
LIMIT 1
```

All three tables are global, so the query runs with no tenant bound.

*2. Operations that can change the predicate.*

| Direction | Operation | Entry point |
|---|---|---|
| Can remove an owner | Revoke a `platform.authority:manage` grant | `revoke_platform_permission` |
| Can remove an owner | Suspend an operator | `suspend_operator`; recovery command |
| Can remove an owner | Revoke an operator (revokes all of its live grants in the same transaction) | `revoke_operator` |
| Can remove an owner | Deactivate a user who is an operator | `deactivate_user` |
| Can add an owner | Grant `platform.authority:manage`; reactivate an operator; reactivate a user; enroll (only together with a grant) | the corresponding operations; bootstrap; recovery |
| Refused outright | Identity erasure of a user who has a non-revoked operator row | `erase_user_identity` refuses until the operator is revoked through a guarded path |

No Core function deletes a `core.users` row or a platform row, and the application role has no `DELETE` on the platform tables, so there is no further path inside the application's privileges.

*3. Transaction boundary and lock.* Every operation in the table runs in exactly one transaction, opened with no tenant bound, containing the lock, the authorization, the mutation, the verification and the success audit row. Its first statement is `acquire_tenant_advisory_lock(session, <nil UUID>, "platform.owners")`. The nil UUID is not a tenant id; this is the sentinel pattern `saas_os/core/tenancy/service.py::_lock_hierarchy_globally` already uses, with a distinct key. The lock is transaction-scoped and released by PostgreSQL at commit or rollback. Operations that can only add an owner take it too: it costs nothing at this frequency, and it serializes anti-amplification and the live-grant uniqueness with everything else.

*4. Lock order.* Fixed, and the same in every operation:

1. the platform-owners advisory lock;
2. ADR-0043 tenant-administrator advisory locks, nearest the root first, then by id (only `deactivate_user` needs them);
3. row locks: the decision's `FOR SHARE` locks on the caller's user, operator and grant rows, then the rows being changed.

No guarded operation takes an advisory lock after a row lock. This is the order ADR-0043 already fixed for tenant operations (commit `adc867b`, "take administrator locks before the denied user's row lock"), with the platform lock placed in front of it.

*5. Authorization relative to the lock.* After the platform lock and after any administrator locks, before any change. A caller whose own authority a concurrent operation just removed is therefore judged against what that operation committed, not against what was true when the request arrived. A route guard that ran earlier is a pre-check only.

*6. Recheck after the mutation.*

1. Before changing anything, run the predicate and record `had_owner`.
2. Apply the change and flush.
3. Run the predicate again. If `had_owner` and no row is returned, raise `LastPlatformOwnerError`.

The check is on the resulting state, not on a prediction of it, so it needs no case analysis of which change removes which owner, and one operation that changes several rows (operator revocation) is checked once, at the end.

*7. Failure rolls back everything.* `LastPlatformOwnerError` leaves the `session_scope()` block as an exception. The mutation and the success audit row were written to that one transaction and are rolled back together; no partial state and no "done" evidence survives. After the rollback, the operation writes one `denied` row with reason `last_platform_owner` through the separate-transaction variant (section 8). If that second write fails, the refusal still stands, the error is logged, and the caller still receives the refusal.

*8. Bootstrap and recovery.*

| | Ordinary operator action | Bootstrap | Recovery |
|---|---|---|---|
| Caller | `UserCaller` | `SystemCaller(PLATFORM_BOOTSTRAP)` | `SystemCaller(PLATFORM_BOOTSTRAP)` |
| `platform_can()` | Required | Not evaluated | Not evaluated |
| No-self-service, anti-amplification | Apply | Not applicable (no acting person) | Not applicable |
| Takes the platform lock | Yes | Yes; the "no operator row exists" check runs under it, so two concurrent bootstraps cannot both enroll | Yes |
| Last-owner recheck | Yes | Trivially satisfied (it only adds) | **Yes.** `recover` suspending the only owner is refused unless the same invocation enrolls and grants a replacement, and the whole invocation is one transaction checked once at the end |
| May revoke or delete | Revoke yes, delete never | No | No |
| Entry point | Core function; opt-in HTTP route | CLI only | CLI only |

*9. Interactions.*

- *Deactivate a user who is an operator.* The operator row and the grants are untouched; the predicate turns false for that operator through `u.is_active`. Refused if it would empty the owner set. Reactivating the user restores ownership without any grant change, and is audited as a user reactivation.
- *Suspend an operator.* Grants stay; no authority until reactivation. Grants may be added to or revoked from a suspended operator; neither changes the predicate while the operator is suspended.
- *Revoke a grant on a suspended operator, or on an operator whose user is inactive.* That operator is not an owner at the time, so the recheck passes; the consequence appears only when the operator would have been reactivated.
- *Revoke an operator.* Terminal. All live grants are revoked in the same transaction and the recheck runs once.
- *Reactivate an operator whose user is inactive.* Permitted; confers nothing until the user is also reactivated.
- *Deactivate a user who is both the last owner and a tenant's last administrator.* Both guards run; the first violation found is reported. Neither masks the other, because both are verified on the flushed state before commit.

**Required concurrency tests (PostgreSQL, real locks, two connections; none exists yet).**

| Test | Asserts |
|---|---|
| Two owners, each revoking the other's `platform.authority:manage`, started together | Exactly one commits; the second is refused by authorization (its own grant is gone), not by a constraint error; one owner remains |
| Same, with operator suspension; same, with operator revocation; same, with user deactivation; and each mixed pair | One owner remains in every pairing |
| Three owners; two concurrent operations each removing a different one of the last two | Both orderings forced with a barrier; the later one is refused with `LastPlatformOwnerError`; one owner remains |
| Ordering A: removal commits, then a platform mutation by the removed owner | The mutation is refused |
| Ordering B: a platform mutation holds its decision locks, then removal starts | Removal waits, then commits; the mutation stands |
| Deactivation of a user who is an administrator of tenants at different depths, concurrent with an ADR-0043-guarded removal in one of those tenants | Completes without deadlock when locks are taken in the stated order; both invariants hold afterwards |
| Deliberately inverted lock order in a test-only path | PostgreSQL reports a deadlock, one transaction is aborted, neither invariant is violated, and a retry succeeds. Shows that a deadlock fails closed |
| Forced failure after the mutation and before commit | Neither the change nor the success audit row exists |
| Forced `LastPlatformOwnerError` | No change, no success row, exactly one `denied` row |
| Forced failure of the `denied` write | The refusal is still returned; no state changed |
| Two concurrent bootstraps | One enrolls; the other sees the row and refuses or reports "already bootstrapped" |
| `recover` suspending the sole owner without a replacement | Refused |

**Negative controls.** Remove the advisory lock: the "last two owners" test must end with no owner in some run. Remove the recheck: the sequential last-owner revocation must succeed. Move authorization before the lock: the "each revoking the other" test must let both commit.

**What the invariant does not do.** It preserves; it does not create. A fresh deployment has no owner until bootstrap. It does not require two owners, although the runbook recommends it. It does not constrain tier-0 access to the database, where a row can be changed without the lock.

### 7. HTTP and CLI boundaries

**Enforcement is in Core.** Every operation below is a Core function that takes a required, keyword-only `caller` and calls `authorize_platform_caller` inside its own transaction. A route adds no decision; it declares the same permission so that an unauthorized request is refused before the handler runs.

**A fourth route policy kind**, `platform_permission`, declared by `require_platform_permission(PlatformPermission.X)` in `saas_os/api/dependencies.py` and registered in the identity registry of `saas_os/api/route_policy.py` like the existing three. Its chain:

1. Authentication: the existing `get_current_actor`, including the ADR-0044 same-origin check for cookie-authenticated unsafe methods. Sessions only.
2. Rate limit keyed by actor and path, failing closed on a backend error as the tenant chain does.
3. `platform_can()`.

There is no tenant resolution: a platform route never takes its authority from a tenant in the path. A caller who is not an active operator receives the same `404` an unknown path would produce; an operator without the permission receives `403`. A refused request by an operator is recorded in the platform audit table.

Resolution rules are extended: `platform_permission` together with a tenant `permission` on one route is a conflict; two different platform permissions on one route is a conflict.

**The router.** `build_platform_admin_router()` in a new `saas_os/api/platform_admin/` package, prefix `/v1/platform`.

- Never mounted by `build_platform_app()`, by `saas_os/api/main.py` or by the consumer scaffold.
- **Two opt-ins.** A product mounts it in code, and the deployment sets `PLATFORM_ADMIN_HTTP_ENABLED=true`. If the router is mounted and the setting is not `true`, startup fails closed in the same lifespan step that checks route policies. A product cannot expose it by a stray `include_router`, and an operator cannot expose it by configuration alone.
- **Fresh session for authority changes (decision D2).** A state-changing route gated by `platform.authority:manage` requires that the presenting session is at most 900 seconds old: `now − core.sessions.created_at ≤ 900`.
  - *One limit.* The maximum is 900 seconds. The setting `PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS` may lower it for a deployment (minimum 60) and may not raise it: a value above 900 or below 60 is a configuration error that stops startup. The 3600-second ceiling in revision A.1 is withdrawn; there is no second limit.
  - *Enforcement point.* The `platform_permission` dependency, for routes declared with `fresh_session=True`. It runs after authentication, which already produced the `core.sessions` row through `validate_session`, and before `platform_can()`. An older session receives `401` with a distinct error code, and the refusal is written to the platform audit. A startup check fails if a state-changing route carries `platform.authority:manage` without `fresh_session=True`.
  - *What it requires.* A new SaaS OS session: the operator logs out or lets the client start a new login, and the OIDC callback issues a new session row. Nothing else.
  - *What it does not prove.* It does not prove that the person authenticated at ZITADEL recently. The identity provider may complete the new login from its own existing session with no prompt. Session age is a property of the SaaS OS session and is described as nothing more. Requiring actual re-authentication (`prompt=login`, `max_age`, and a validated `auth_time` claim) makes authorization depend on an identity-provider claim and stays deferred to its own decision.
  - *Where it does not apply.* It is a route rule. A Core function has no session to measure, so an in-process call and the recovery command are not subject to it. It bounds what a stolen older session can do to platform authority over HTTP.
- Typed response models, bounded and paginated lists, pagination in the query, not in Python.
- The reference edge routes all of `/v1/*` to the backend (`saas_os/infra/edge/routing.py`). Restricting `/v1/platform` by network at the edge is a deployment choice the runbook describes; it is an additional layer, not the control.

| Operation | Core permission | HTTP (opt-in router) | CLI / operator |
|---|---|---|---|
| List / read tenants | `platform.tenant:read` | yes | — |
| Create tenant (root, or child of a `PENDING` or `ACTIVE` parent) | `platform.tenant:create` | yes | first-tenant bootstrap (existing; root only) |
| Suspend / reactivate tenant | `platform.tenant:suspend`, `:reactivate` | yes | — |
| Move tenant | `platform.tenant:move` | **no** | operator tooling |
| Mark tenant deleted | `platform.tenant:delete` | **no** | operator tooling |
| Purge tenant | none (`TENANT_PURGE`) | **never** | operator tooling |
| Erase identity | none | **never** (import-fenced) | operator tooling |
| Resolve user | `platform.user:read` | yes | — |
| Deactivate / reactivate user | `platform.user:deactivate`, `:reactivate` | yes | — |
| Revoke a user's sessions | `platform.session:revoke` | yes | — |
| Revoke a user's API keys | `platform.api_key:revoke` | yes | — |
| Flags: read / define / override | `platform.feature_flag:*` | yes | — |
| Commercial overview | `platform.billing:read` | yes | — |
| Read platform audit | `platform.audit:read` | yes | — |
| List operators and grants | `platform.operator:read` | yes | — |
| Enroll / suspend / reactivate / revoke operator; grant / revoke permission | `platform.authority:manage` | yes, fresh session | recovery command (enroll, grant, suspend only) |
| Owner bootstrap, recovery | none (`PLATFORM_BOOTSTRAP`) | **never** | `saas_os.api.platform_bootstrap` |
| Migrations, backup, restore, pin update | none | **never** | existing CLIs |

**Why move and delete have no route.** Moving a tenant under another changes who administers it: an operator who also administers the new parent would gain authority over the moved tenant. `→ DELETED` cannot be undone; its only exit is purge. Both keep a Core permission so that they are authorized and audited when an operator runs them, and both stay off the network. `move_tenant` additionally refuses a caller who is a member of the new parent or of any of its ancestors.

**Operator tooling for purge, erasure, move and delete.** Today these are Python calls made by hand. Where a packaged operator command for them lives is a layering question (`saas_os.api` is forbidden to import the erasure module) that this ADR does not settle; see "Deferred".

### 8. Platform audit

**`core.platform_audit_log`** — a new table, `GLOBAL`, `SECURITY_RETAIN`.

| Column | Notes |
|---|---|
| `id`, `created_at` | |
| `actor_type` | `user` or `system`, with a pairing CHECK like `core.audit_log` |
| `actor_user_id` | Required for `user`; `NULL` for `system` |
| `system_authority` | Required for `system` |
| `action` | One of the actions listed or named in section 5b, for example `platform.operator.enroll`, `platform.grant.create`, `platform.tenant.suspend` |
| `target_type`, `target_id` | What was acted on |
| `target_tenant_id` | Nullable FK `core.tenants.id`, set when the target is or belongs to a tenant. Deliberately not named `tenant_id`: the column does not make the row tenant-owned, and the isolation audit keys on that name |
| `outcome` | `success`, `denied` or `failure` |
| `reason` | Bounded text supplied by the operator where the operation requires one |
| `correlation_id` | From the ambient request context, as `core.audit_log` does |
| `metadata` | Validated by the existing `saas_os.core.audit_log.metadata.validate_metadata`: fixed-shape, no credentials, no customer content |

- **Writes.** `record_platform_event_in_transaction(session, *, caller, …)` adds the row to the mutation's own transaction and never commits, so the change and its evidence commit or roll back together. Actor columns are derived from the caller, so evidence cannot name a different actor than the one authorized. Refusals are written by a separate-transaction variant, because evidence of a refusal must survive the refusal (ADR-0031 section 3).
- **Immutability, and its limits.** The application role holds `INSERT` and `SELECT` on this table and nothing else, the mechanism `core.audit_log` uses. Because `ALTER DEFAULT PRIVILEGES IN SCHEMA core` (migration `e99c76057719`) grants the application role `SELECT, INSERT, UPDATE, DELETE` on every new table automatically, the migration that creates this table must `REVOKE UPDATE, DELETE` explicitly, as the `core.audit_log` migration does, and a migration test must assert the resulting privileges. What this gives: no code running as the application role can change or remove a row once written. What it does not give:
  - *It does not authenticate an insert.* Any in-process code can insert a row that describes something that did not happen. Evidence is trustworthy to the extent that only `record_platform_event_in_transaction` writes it; an architecture test can pin that for this repository and for nothing else.
  - *It does not bind the migrations role*, which owns the table and can update, delete, truncate or drop it. That role is tier 0.
  - *It is not tamper-evident.* There is no hash chain and no external copy; a row altered by tier 0 leaves no trace in the table.

  A trigger that rejects `UPDATE` and `DELETE` for every role would narrow the second point and is listed under "Deferred", because it should be decided for both audit tables together.
- **Oversight reads are audited, by two rows** (amended 2026-10-13; the access path is section 9d). Every oversight call writes an *attempt* row, committed in a transaction of its own before anything is read, and, when the read succeeds, a *completion* row in the read's own transaction. The attempt row records the actor, the action, the page cursor and the requested page size. The completion row records the number of entries returned and the id of the attempt row (`attempt_id` in its metadata); `correlation_id` keeps its meaning, the ambient request id, and is not the link. The two rows carry different actions -- the operation's audit action for the completion, the same action with the suffix `_attempt` for the attempt -- so a count of completed reads never counts an attempt; both have outcome `success`, the attempt's meaning that the read was authorized and recorded, not that it returned anything. A read that fails, or whose caller loses the authority between the two transactions, writes no completion row; the attempt row remains. An attempt with no completion, `denied` or `failure` row after it is a read that did not complete. Each row records a target id only for a call that named one target (a tenant's flag overrides, one user, one tenant); the attempt row never carries `target_tenant_id`, which references an existing tenant, because whether the tenant exists is not known before the read. Neither row ever records the returned values, and for a user resolved by `(issuer, subject)` it records the resolved user id or "not found", never the issuer or subject, so the audit table does not become a second copy of identity data. What a row does disclose to a reader holding `platform.audit:read` is that a given operator looked at a given tenant or user at a given time; that is the purpose of the row.
- **Dual evidence for tenant-affecting operations.** A platform suspension, reactivation, move, deletion or flag override writes a platform audit row and, in the same transaction, a row in the affected tenant's own `core.audit_log` naming the operator as a `user` actor. The tenant's administrators can see in their own trail that the platform acted on them. The tenant row is written under that tenant's RLS scope through `bind_tenant_scope`.
- **Operator logins.** When the user who just logged in is an enrolled operator, the OIDC callback writes `platform.operator.session_issued`. This is the first durable login record SaaS OS has, limited to the population where it matters most.
- **Reads.** Gated by `platform.audit:read`, service function plus route, filterable by time, actor, action and target tenant.
- **Human actors.** No platform operation performed by a person is recorded as `system`. System rows exist only for the bootstrap and recovery command, provisioning and purge.

### 9. Tenant isolation and RLS

No existing policy, role or session variable changes. No `BYPASSRLS` role, no `SECURITY DEFINER` function and no second GUC is introduced. One new policy shape is added, for the three platform tables only (9b, decision D1). It is an architectural addition to ADR-0002 and ADR-0030, stated as one in "Reconciliation" and recorded in ADR-0030's amendment of 2026-10-12. It is defence in depth. It is not an authorization boundary, and Core authorization is mandatory whether or not it is present.

#### 9a. The database as it actually is

Verified at `d5eb2c9`:

- The application connects as one role, created `NOSUPERUSER NOBYPASSRLS` (`saas_os/infra/db/init/01-create-app-role.sh`) and checked at startup (`saas_os/infra/db/role_guard.py`). Migrations run as a different, privileged role that owns the tables.
- That application role is granted `SELECT, INSERT, UPDATE, DELETE` on every table in `core` by default privileges. A table is narrower only where its migration revokes something.
- Tenant isolation in the database is one policy shape, `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid`, with `FORCE ROW LEVEL SECURITY`, on tables classified `TENANT_OWNED`.
- `app.tenant_id` is set by application code, transaction-locally, through `tenant_session_scope()` or `bind_tenant_scope()`. `bind_tenant_scope`'s own documentation says it "grants nothing `tenant_session_scope()` does not already grant (any caller can open a session scoped to any tenant it names)". The variable is not a credential. RLS in this architecture protects against application bugs that forget a predicate; it does not protect against application code that names the wrong tenant, and it does not distinguish one in-process caller from another.
- Tables classified `GLOBAL` (`core.users`, `core.sessions`, `core.tenants`, `core.permissions` and others) have no policy. Any transaction of the application role reads and writes them whatever tenant is bound.

**Consequence.** There is one database principal for all application code. The database cannot tell a request from a tenant administrator from a request from a platform operator. Whatever separates them is decided in Core. For the platform tables the database can enforce three things: which statement types the application role may run at all, referential and CHECK constraints, and, through D1, that the rows are unreachable from a transaction bound to a tenant. Everything else in the table below is application-level authorization and is labelled as such.

#### 9b. Isolation matrix for the platform tables

| | `core.platform_operators` | `core.platform_grants` | `core.platform_audit_log` |
|---|---|---|---|
| Classification (ADR-0030 registry) | `GLOBAL`, with reason: "platform authority; exists independently of any tenant" | `GLOBAL`, same reason | `GLOBAL`, with reason: "platform evidence; `target_tenant_id` is a reference, not ownership" |
| Classification (ADR-0002) | Not tenant-owned data; outside the tenant policy by definition, like `core.users` | Same | Same |
| Retention class | `SECURITY_RETAIN` | `SECURITY_RETAIN` | `SECURITY_RETAIN` |
| Canonical tenant RLS | Does not apply: no `tenant_id` to compare | Does not apply | Does not apply |
| Policy (D1) | Tenant-context exclusion, `ENABLE` and `FORCE` | Same | Same |
| Default-privilege revocation in the creating migration | `REVOKE DELETE` | `REVOKE DELETE` | `REVOKE UPDATE, DELETE` |
| Privileges never granted by default and not added | `TRUNCATE`, `REFERENCES`, `TRIGGER` | Same | Same |
| Application role privileges | `SELECT, INSERT, UPDATE`; `DELETE` revoked | `SELECT, INSERT, UPDATE`; `DELETE` revoked | `SELECT, INSERT`; `UPDATE, DELETE` revoked |
| Why `UPDATE` is needed | Status transitions; and `SELECT … FOR SHARE` requires it in PostgreSQL | Setting `revoked_at`; and `FOR SHARE` | Not needed; rows are never locked or changed |
| Migrations role | Owner; unrestricted (tier 0) | Same | Same |
| Any other database role | None exists; none is created | Same | Same |
| Core modules allowed to touch the table | `saas_os.core.platform_authority` only | Same | Same, through its audit functions |
| Enforced how | Import-linter contract and an architecture test that no other module imports the models. **Application-level and static** | Same | Same |

**D1, the tenant-context exclusion policy (approved; applied when this ADR is implemented).** On each of the three tables:

```sql
ALTER TABLE core.platform_operators ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.platform_operators FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_operators_no_tenant_context ON core.platform_operators
  USING (NULLIF(current_setting('app.tenant_id', true), '') IS NULL);
```

With no separate `WITH CHECK`, the expression governs reads and writes alike. It uses the existing variable, the existing `NULLIF` normalisation and the existing role. Referential-integrity checks are not subject to row security in PostgreSQL, so foreign keys to and from these tables are unaffected.

*Behaviour for each state of `app.tenant_id`.*

| State of the variable in the transaction | How it arises | Platform tables | Tenant-owned tables (unchanged, for comparison) |
|---|---|---|---|
| Never set on this connection | A fresh connection inside `session_scope()` | Visible and writable | No rows |
| Empty string | PostgreSQL resets a transaction-local setting to `''` when the transaction that set it ends; `bind_tenant_scope` restores `''` on leaving a block | Visible and writable (`NULLIF` maps it to `NULL`) | No rows |
| A tenant's UUID | `tenant_session_scope()` or inside a `bind_tenant_scope` block | **No rows; every insert and update rejected** | That tenant's rows |
| A non-empty value that is not a UUID | Not produced by any SaaS OS code path, which binds only `uuid.UUID` values; possible only through a direct `set_config` | **No rows; writes rejected.** The policy compares for `NULL` and never casts, so it cannot raise | The cast to `uuid` raises an error |
| Cleared by code (`set_config('app.tenant_id', '', true)`) | Any application code can do this | Visible and writable | No rows |

The last row is the limit of the policy, stated without qualification: the variable is set by application code and is not a credential. D1 fails closed for anything that is not "no tenant bound", and it cannot tell why no tenant is bound.

- *What it enforces.* Every tenant-scoped Core function runs inside `tenant_session_scope(tenant_id)`. The database, not a convention, guarantees that none of them can read or change platform authority or platform evidence, whatever bug they contain.
- *What it does not enforce.* It does not distinguish trusted platform code from any other code running as the same database role. It is not a boundary against code that opens an untenanted transaction, or that clears the variable. It does not know who the caller is, so it cannot replace `platform_can()`: an untenanted transaction of the application role sees every platform row, and the only thing that decides whether the acting person may use them is Core authorization.
- *What it costs.* A second policy shape, where ADR-0002 and ADR-0030 describe one. The isolation registry's `GLOBAL` class is documented as "deliberately not RLS-scoped"; ADR-0030's amendment of 2026-10-12 keeps the three tables `GLOBAL` (they are not tenant-owned) and amending that wording to "not scoped by the tenant policy", with the exclusion policy recorded per entry. The RLS coverage sweep must recognise the shape and assert it on exactly these three tables. It also imposes the ordering rule of 9c on platform code.
- *Data migrations.* A later migration that reads or writes these tables must run with no tenant bound. `FORCE` applies to the owning role unless it is a superuser.

**How tenant and support-access callers are kept out (items 5 and 6 of the review, answered together).**

| Layer | Mechanism | Kind |
|---|---|---|
| Vocabulary | Platform permissions are not rows in `core.permissions`; no role, delegation, deny or support-access grant can name one | Structural |
| Decision | `can()` never reads platform tables; `platform_can()` never reads tenant authority; `ServiceAccountCaller` is refused before any read | Application-level, pinned by an import contract |
| Routes | A tenant route resolves a tenant and calls `can()`; it has no code path to `saas_os.core.platform_authority`. Support access is evaluated only inside `can()` | Application-level |
| Database | D1: a tenant-bound transaction cannot see or write the rows | Database-enforced defence in depth; not an authorization decision |
| Database | No `DELETE`; no `UPDATE` on the audit table | Database-enforced |

Authorized platform operations reach the tables through an ordinary `session_scope()` with no tenant bound, as the application role. That is the same access path `core.users` and `core.sessions` have today. Nothing is bypassed, because nothing was in the way: these rows were never under the tenant policy.

#### 9c. Ordering rule for platform transactions

A platform operation that also writes tenant-owned rows (the dual-evidence audit row, section 8; the administrator guard in `deactivate_user`) does so inside `bind_tenant_scope(session, tenant_id)` blocks within its one transaction. The rule: **platform tables are read and written only while no tenant is bound; tenant-owned tables only inside a bind block; a bind block never contains a platform read or write.** The decision's `FOR SHARE` locks are taken before the first bind block and are held to the end of the transaction regardless of the variable's value. `bind_tenant_scope` restores the previous binding on exit and PostgreSQL clears the variable at commit or rollback, so no binding outlives the transaction. `bind_tenant_scope` is documented today as existing for one need, the `can()` decision; this is a second use and its documentation and the ADR-0022 allowlist must say so.

#### 9d. Operational oversight: access path

Oversight is the "distinct, explicitly audited code path" ADR-0002 and `docs/MULTI-TENANCY.md` section 5 commit to. There are two kinds of read.

**Reads of global tables only** — tenant registry, user resolution, operators and grants, platform audit, flag catalog. Two transactions -- the attempt, then the read with its completion row, as in the path below without its step 4 -- no tenant bound, one bounded query each. No tenant context is ever set.

**Reads that enter tenant scopes** — the commercial overview (`core.billing_subscriptions`, tenant-owned by the service tenant) and one named tenant's flag overrides (`core.feature_flag_tenant_overrides`, tenant-owned). The path, in two transactions, each opened with `session_scope()` and no tenant bound (amended 2026-10-13; every oversight read follows steps 1, 2 and 5 to 7, and a read of global tables only has no step 4):

1. *The attempt transaction.* `authorize_platform_caller(caller, session=…, operation=…)`, then insert the attempt row (section 8), then commit. Nothing protected is read in this transaction. If the caller is not authorized the transaction rolls back, no attempt row exists, and the refusal is recorded as `denied`. If the row cannot be inserted or the commit fails, the call raises and nothing has been read. This writer is fail closed; the best-effort refusal writer is never used for it.
2. *The read transaction.* `authorize_platform_caller` again. The attempt's decision ended with its transaction, so the authority may have been revoked since; this decision holds the caller's user, operator and grant rows `FOR SHARE` until the transaction ends, so the authority cannot be revoked part-way through the page.
3. Read one page of `core.tenants` by keyset on `id`, excluding `PURGED` tombstones, with `LIMIT` equal to the page size.
4. For each tenant on the page: enter `bind_tenant_scope(session, tenant.id)`; run the one fixed, parameterised query for the projection, with its own `LIMIT`; leave the block. The tenant policy filters every row; the query also carries the explicit `tenant_id` predicate, as Core queries do.
5. With no tenant bound (section 9c), insert the completion row: the number of entries returned and the attempt row's id.
6. Commit.
7. Return. The data leaves the function only after the completion row is durable.

It never issues a statement that spans tenants, and there is no function that takes a table name or a column list.

**Does the existing mechanism support this safely?** Yes, as far as inspection can show. `administrators.py::find_administrator` already iterates tenants inside one transaction with `bind_tenant_scope`, and `can()` does the same over an ancestor chain. The path introduces a new caller of an existing primitive, not a new trust boundary: the variable was always set by trusted application code naming a tenant. What is new is *who decides which tenants are named*: until now, a tenant was named because the actor had authority in it, and here it is named because the actor holds a platform permission. That is the substance of constraint 4, and it is the reason the projection is fixed and minimal.

**Authorization required before each tenant-scoped read.** The decision of step 2, pinned by its locks; the decision of step 1 gates the attempt row only. No tenant permission is consulted and none could grant the read. `can()` is not called.

**Tenant status.** RLS does not look at tenant status, so the read works for a `SUSPENDED` or `DELETED` tenant; that is intended, since those are the tenants an operator most needs to see. `PURGED` tenants are skipped; they have no rows. A tenant cannot opt out of oversight, and the consumer guide must say so to products, which owe the same statement to their customers.

**Support access.** Not consulted, not required, not created. An oversight read is not a support-access session and confers none of its abilities; conversely, a support grant does not widen an oversight projection. Anything beyond the projection requires the tenant-approved mechanism.

**Request limits (decision D3).** A request above a maximum is rejected with a validation error. It is never clamped, because a silently shortened page looks like a complete answer.

| Read | Default | Maximum | Query behind it, as verified against the schema at `d5eb2c9` |
|---|---|---|---|
| Tenant registry page | 50 | 200 | Keyset on `core.tenants.id` (primary key), `LIMIT n`. One statement |
| Operational overview, tenants per call | 25 | 50 | The same keyset page, then per tenant two `set_config` calls and one query: at most 150 statements per call, a constant |
| Subscriptions per tenant in the overview | 10 | 10 | `WHERE tenant_id = :t ORDER BY updated_at DESC LIMIT 10`, joined to the global `core.billing_plans` for the plan key. `ix_billing_subscriptions_tenant_id` exists; there is no index that also covers `updated_at`, so PostgreSQL sorts that one tenant's subscription rows to take ten. The work is bounded by one tenant's subscription count, not by the table |
| Sessions per resolved user | 50 | 50 | `WHERE user_id = :u ORDER BY created_at DESC LIMIT 50`, on `ix_sessions_user_id` |
| Live-session count per user | — | reported as an exact number up to 50, otherwise "more than 50" | A count over `LIMIT 51`, so it cannot scan an unbounded number of rows |
| Platform audit page; operator and grant list page | 50 | 200 | Keyset on the primary key |

Nothing iterates beyond one page per call: the caller asks for the next page with the cursor from the previous one, and each call is authorized, audited (one attempt row and one completion row) and rate-limited on its own. No oversight function loops over the whole registry. The one place this design does scan the registry is `deactivate_user` (section 11c), which is not an oversight read, returns no tenant data, and is treated there.

The read transaction is read-only apart from the completion row and should carry a statement timeout. The repository has no per-transaction timeout helper today; that is an implementation detail for Phase C to settle, not something this ADR asserts exists.

**Accepted deferral (owner decision, 2026-10-13).** Phase C did not settle it: no timeout helper was built and neither oversight read transaction carries a statement timeout. The owner accepted deferring this Phase C responsibility. The requirement is unchanged and outstanding: both oversight read transactions must carry a statement timeout before any of them is reachable over HTTP, that is, before Phase D. Rationale for the deferral: Phase C adds no route, so the reads are reachable only by in-process callers that already hold `platform.tenant:read` or `platform.billing:read`; each read is bounded by its page cap and by one indexed query per tenant; and a per-transaction timeout helper is a new mechanism in `saas_os.infra.db` that deserves its own review rather than being added at the end of this phase. What remains exposed until then: a slow or blocked oversight read holds its connection, and the attempt row it already committed, for as long as the database lets it.

**Implemented before Phase D (2026-10-13); the deferral above is closed.** `set_local_statement_timeout(session, milliseconds)` in `saas_os.infra.db` sets PostgreSQL's `statement_timeout` with `set_config(..., is_local => true)` and a bound parameter, so it lasts for one transaction and never reaches the next user of a pooled connection. The value is the setting `PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS`: default 5000, accepted between 100 and 60000; no value disables it. `build_platform_app()` validates it at startup; any other process validates it on the first oversight read, before the attempt row, so an invalid value fails closed there too. *Both* transactions of an oversight read carry it, not only the read transaction this section names: the attempt transaction authorizes under row locks and inserts into the platform audit table, and while implementing the read's timeout a lock held by another transaction was observed to hold an attempt without limit. A statement or lock wait that exceeds the value is cancelled by PostgreSQL and the call raises `OversightReadTimeoutError`, which is not a refusal and whose `stage` says which transaction was cancelled (`attempt`: no row exists; `read`: the attempt row remains). The timeout bounds each statement, not the transaction: the commercial overview runs one statement per tenant on the page, so its worst case is the page size times the value, and PostgreSQL 16 has no transaction-wide timeout. It is applied to nothing else: the writers of `denied` and `failure` rows, and every other platform operation, wait for locks as they did (in the deferred ledger).

**Failure behaviour.**

| Failure | Result |
|---|---|
| Authorization refused in the attempt transaction | Nothing read; no attempt row; one `denied` audit row, written separately |
| Attempt insert or its commit fails | Error; the read transaction never opens; nothing read; no row of any kind, since nothing happened that evidence could describe |
| A statement of the attempt transaction exceeds the statement timeout | `OversightReadTimeoutError`; as the row above: the read transaction never opens, nothing read, no row of any kind |
| A statement of the read transaction exceeds the statement timeout | `OversightReadTimeoutError`; the read transaction is rolled back; nothing returned; the attempt row remains; no completion row; for the commercial overview a `failure` row with reason `statement_timeout`, written separately (best effort) |
| Authority revoked between the two transactions | Refused by step 2; nothing returned; the attempt row remains; no completion row; one `denied` row, written separately |
| The read, a scope binding or a tenant query fails | The read transaction is aborted and rolled back; the variable is cleared by the rollback; no partial page is returned; the attempt row remains; no completion row; for a read that enters tenant scopes a `failure` row is written separately (best effort) |
| Completion insert fails | As the row above: rolled back, nothing returned, the attempt row remains |
| Commit of the read transaction fails | No data returned; the completion row is not durable; the attempt row remains |
| A named tenant does not exist | Both rows are committed, the completion with `returned: 0`; then `TenantNotFoundError`. An unauthorized caller is refused in step 1, before the lookup, and learns nothing about existence |

- **Customer data.** No platform function returns rows of a tenant-owned table other than the projections of section 4. The projections are fixed in code; there is no generic "read table X for tenant Y" function.
- Each untenanted `session_scope()` call site added by this work must be entered in the ADR-0022 allowlist with its reason.

**The audit trail of a tenant is not exposed across tenants by this ADR.** Reading `core.audit_log` for arbitrary tenants would show who did what inside a customer's organization, which is closer to customer data than to operational oversight. It is listed under "Deferred" as a separate decision.

### 10. ZITADEL `IAM_OWNER` and other tier-0 authority

SaaS OS authenticates a person by trusting `(issuer, subject)`. A holder of `IAM_OWNER` can reset a subject's credentials or control signing keys and so obtain any user's session, including a platform owner's. SaaS OS cannot prevent this and does not claim to. The same is true of the migrations database role and of host access.

Controls around that boundary (decided; none implemented):

1. **Documentation.** A tier-0 section in `docs/SECURITY.md` and `docs/RUNBOOKS.md` naming each tier-0 credential, who should hold it, and that holding it is equivalent to holding every platform and tenant authority.
2. **Detection.** `platform.operator.session_issued` (section 8) gives each operator, and anyone reading the platform audit, a record of operator logins. A takeover through the identity provider produces a login the real operator did not make.
3. **Bounded exposure.** The fresh-session requirement on authority changes (section 7).
4. **Response.** Deactivating a user and revoking sessions (section 11) take effect on the next request. The recovery command suspends a compromised owner without depending on any other owner.
5. **Independent evidence.** ZITADEL's own event log is the evidence source for actions taken with `IAM_OWNER`; the runbook says where it is and that it must be retained.
6. **The bootstrap PAT.** `docker-compose.prod.yml` provisions an `IAM_OWNER` personal access token for the `bootstrap` machine user with an expiry in the year 2100. Removing or expiring it after the identity bootstrap would narrow tier 0. That is a deployment change outside this ADR, listed under "Deferred" for its own approval.

Requiring multi-factor evidence (an `amr` or `auth_time` claim) for operator sessions would be a further control. It makes authorization depend on an identity-provider claim, which ADR-0005 has so far avoided, so it is deferred to its own decision.

### 11. User deactivation, session revocation and API keys

#### 11a. What ADR-0031 says, and what changes (decision D6)

ADR-0031 section 5, accepted, reads: *"Session contract: deactivation does not revoke session rows. While the user is inactive the session is unusable; it still expires on its own schedule, and reactivating the user makes an unexpired session valid again."* Its "deferred" list adds: *"There is no user-deactivation operation (`is_active` is set by an operator) and no session revocation on deactivation."*

The implementation matches that text. `validate_session` (`saas_os/core/identity/sessions.py`) refuses a session whose row is revoked or expired, and then refuses one whose user is missing or inactive, reading both rows on every request with no cache. Nothing writes `is_active`, and nothing sets `revoked_at` except a user's own logout. Sessions last twelve hours from issue. A revoked session row is deleted by the cleanup job after `SESSION_REVOKED_GRACE_PERIOD_SECONDS`.

ADR-0031 wrote that contract for a system with no deactivation operation; it describes what happens when an operator edits the column by hand. This ADR adds the operation, and the approved replacement contract is:

> Deactivating a user revokes every live session and every unrevoked user-owned API key of that user in the same transaction. Reactivating a user restores neither: the user authenticates again and is issued new keys. A revocation takes effect on the next request that presents the credential.

This **replaces an accepted statement** with a stricter one. The amendment has been written into ADR-0031 as the dated section "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)", which quotes the sentence it replaces and marks it as still describing the code until Phase C. No incompatibility with the implementation was found: both tables already have `revoked_at`, both validators already honour it, and no code depends on a credential surviving a deactivation.

#### 11b. Operations

- `deactivate_user(user_id, *, caller, reason)`: requires `platform.user:deactivate`. One transaction, specified step by step in 11c.
- `reactivate_user(user_id, *, caller, reason)`: requires `platform.user:reactivate`. In one transaction, under the platform-owners lock: locks the user row exclusively; revokes every session and every user-owned API key of that user that is still unrevoked; sets `is_active = true`; writes the audit rows. The revocation step is redundant if deactivation and the issuance rules of 11d worked, and is kept so that "reactivation restores no credential" does not depend on them.
- `revoke_user_sessions(user_id, *, caller, reason)`: requires `platform.session:revoke`. Revokes every live session and changes nothing else. It is a separate permission so that incident response can be given to someone who may not deactivate, and it is never refused by either invariant, because it removes no authority.
- `revoke_user_api_keys(user_id, *, caller, reason)`: requires `platform.api_key:revoke`. Specified in 11f.
- **No implication between these permissions.** `platform.user:deactivate` revokes sessions and keys only as part of a deactivation and cannot be used to revoke them alone. `platform.session:revoke` does not touch keys. `platform.api_key:revoke` does not touch sessions and cannot deactivate.
- **No self-deactivation.** A caller may not deactivate their own user. The check is in the Core function, so it covers the route and every other entry. A caller may revoke their own sessions; that is a logout everywhere.

#### 11c. Deactivation: transaction, locks and the tenant-discovery problem (decision D4)

`deactivate_user` must preserve the last platform owner (section 6) and, as ADR-0043 requires of any deactivation function, the last tenant administrator of "each tenant the user is an active member of".

**The problem.** `core.tenant_memberships` is tenant-owned. No query can list a user's memberships across tenants; `docs/MULTI-TENANCY.md` section 5 states that Core deliberately has no such lookup, and `erase_user_identity` makes its caller supply the tenant ids. A caller-supplied list is not acceptable here, because an incomplete list silently skips the guard. No global membership index is introduced. Discovery is a scan of the tenant registry under the ordinary tenant policy. D4 allows that only if the scan is shown to be safe under concurrency, and two scans by themselves show nothing. What follows is the strategy and the argument for it.

**Facts the argument rests on, each read from the code at `d5eb2c9`.**

- F1. `can()` locks the evaluated actor's `core.users` row `FOR SHARE` for the rest of its transaction (`saas_os/core/rbac/authorization.py::_decide`, through `lock_user_is_active`), before it evaluates any grant, whenever the target tenant is not closed.
- F2. The administrator guard counts a user only through `can()` (`administrators.py::is_administrator`), and only if that user has an ACTIVE membership of that exact tenant (`find_administrator`, `_is_active_member`; ADR-0043 rule 5). So a transaction that relied on user U being an administrator of tenant T holds `FOR SHARE` on U's row until it ends, and U's membership in T was committed before that transaction read it.
- F3. A guarded mutation takes the administrator advisory lock of its own tenant as its first statement, before authorization. Read directly for membership suspension and revocation (`identity/service.py::_transition_membership_status`); taken from ADR-0043's text for the other guarded mutations, not re-read one by one.
- F4. ADR-0043 already contains this shape. `create_deny` locks the denied user's row exclusively, and takes the administrator locks of the tenants it reaches before that row lock; the opposite order produced a real deadlock in CI and was corrected (commit `adc867b`).

**The transaction.** One transaction, opened with no tenant bound.

1. Take the platform-owners advisory lock.
   - *Preliminary authorization.* Read, without row locks, whether the caller is an active operator holding `platform.user:deactivate`, and refuse now if not. This is not the decision; step 4 is. It exists so that a caller with no authority cannot make Core scan the registry. Revision A.2 omitted it.
   - *Ceiling check (ruling R1).* Count the non-purged tenants with a bounded query (`LIMIT ceiling + 1`). If the count exceeds the ceiling, refuse now, before any tenant scope is bound.
2. *First scan.* Page through `core.tenants` by keyset, skipping `PURGED`. For each tenant, inside `bind_tenant_scope`, run one existence query for an ACTIVE membership of U. No row locks. The result is the set S1. Nothing from the scan is returned to the caller.
3. Take the ADR-0043 administrator advisory locks of the tenants in S1, nearest the root first, then by id, and record each tenant's administrator (`guard_tenants`).
4. Authorize the caller (`authorize_platform_caller`), and refuse a caller acting on themselves.
5. Lock U's `core.users` row exclusively (`lock_user_is_active(exclusive=True)`). This waits for every transaction that holds the row `FOR SHARE`.
6. *Second scan*, as step 2, giving S2. Each scan counts the tenants it visits and raises the ceiling refusal if the count passes the ceiling, which can happen if tenants were created since step 1. If S2 contains a tenant that is not in S1, raise a retryable error and roll back; nothing has changed. The operation retries the whole transaction a small fixed number of times and then reports the failure.
7. Record `had_owner`. Set `is_active = false`. Revoke U's live sessions and U's unrevoked API keys (11d). Flush.
8. Run the ADR-0043 verification for each tenant in S1, then the last-owner recheck.
9. Write the audit rows. Commit.

The order of locks is the fixed order of section 6: platform lock, administrator locks, row locks. The exclusive lock on U's row is taken after every advisory lock, which is the order F4 arrived at.

**Why no tenant that had an administrator is left without one.** Take any tenant T that has an administrator before the deactivation. Where could deactivating U leave T with none?

- *T is in S1.* The transaction holds T's administrator lock from step 3. By F3, every guarded mutation in T either committed before step 3, in which case step 3 recorded the state it left and step 8 checks against it, or waits until this transaction ends and then evaluates U as inactive. If U was T's only administrator, step 8 refuses.
- *T is in S2 but not in S1.* Step 6 aborts.
- *T is in neither, and some other transaction X relied on U as T's administrator.* By F2, X held `FOR SHARE` on U's row and saw a committed membership of U in T. Either X held its lock before step 5 was granted, so X ended before step 5 returned, and the membership it saw was committed before step 6 began; then step 6 finds T, unless that membership was meanwhile suspended or revoked, which is itself a guarded mutation that verified T keeps an administrator. Or X asked for its lock after step 5, so it waits until this transaction ends and then reads `is_active = false` and does not count U. In neither case does a removal succeed on the strength of U while T goes unguarded.
- *U becomes an active member of T after step 6.* From step 5 to the end, nobody can count U anywhere, because counting requires the `FOR SHARE` lock this transaction blocks. Afterwards U is inactive and counts nowhere. T's other administrators were not touched by this transaction.

**What remains outside the argument.**

- *A tenant that had no administrator.* If T has none, and U is made its first administrator by a transaction that commits while U is being deactivated, T ends with no active administrator. ADR-0043 states the same limit for its own guards ("this rule never invents an administrator"; a guard whose recorded administrator is `None` verifies nothing), and the same interleaving exists today between a role assignment and a membership revocation. The deactivation gives the guarantee ADR-0043 gives, not a stronger one.
- *F3 for every guarded mutation* is taken from ADR-0043, not from reading each function.
- *A deadlock that is not eliminated.* If U, while being deactivated, is running a guarded mutation in a tenant outside S1 by authority inherited from an ancestor, and that mutation reaches a descendant that is in S1, it holds `FOR SHARE` on U's row (as the actor) while waiting for the descendant's administrator lock; this transaction holds that lock and waits at step 5. PostgreSQL aborts one of the two. Nothing is left half-done, and a retry succeeds, but a caller sees a database error. `guard_last_administrator` takes descendant locks after authorization by design, so this ADR cannot remove the cycle without changing ADR-0043's own ordering, and does not propose to.
- *Statement visibility.* The argument assumes READ COMMITTED, which is what the application runs at: the second scan's statements start after step 5 returns and see everything committed before that.

**This is an argument from reading code, not a proof and not a test result.** D4's condition is met at the level of design; it is not met at the level of evidence until Phase C. The blocking acceptance criteria for `deactivate_user` are in "Phase C" below: the operation must not be exposed, in Core's public surface or over HTTP, until the race tests listed there exist and pass against PostgreSQL. If one of them fails and cannot be fixed with these primitives, `deactivate_user` is withdrawn from the phase and the incident path is session and key revocation only.

*An optional strengthening, not required by the argument.* `add_tenant_membership` and `reactivate_membership` do not lock the subject user's row today (`accept_invitation` does, through `require_active_user`, because the subject is the caller). Having them take it `FOR SHARE` would make S2 exact instead of merely sufficient and would remove most retries at step 6. It is a small change to two Core functions and is left to Phase C to adopt or not.

*Cost.* Two passes over the tenant registry per deactivation, each one variable change and one indexed existence query per tenant, while holding the platform lock, and the administrator locks of S1 for the second pass. The work is proportional to the number of tenants. Deactivation is rare and the platform lock blocks only other authority changes, but without a bound this is unbounded work behind one request.

**The scan ceiling (ruling R1).**

- *Setting.* `PLATFORM_DEACTIVATION_MAX_TENANTS` (working name), an integer number of tenants. Default 10 000 when unset. This ADR specifies the setting; it does not add it. No configuration mechanism is introduced in this phase.
- *Validation.* Read once at startup like the other Core settings. A value that is not an integer, or is less than 1, is a configuration error that stops startup. There is no upper limit: a deployment may raise the ceiling and accepts the longer lock hold that follows. There is no value that means "unlimited".
- *What is counted.* Non-purged rows of `core.tenants`, the population the scan must visit. Not the tenants the user belongs to, which is what the scan exists to find out.
- *Refusal.* If the population exceeds the ceiling, at the check in step 1 or during either scan, `deactivate_user` raises `DeactivationScanLimitError` and the transaction rolls back. Nothing is changed: the user stays active, no session or key is revoked.
- *Never partial.* The operation does not truncate the scan, skip tenants, sample, or proceed on the tenants it managed to visit. An invariant check over part of the registry is not a check. The only outcomes are a complete scan or a refusal.
- *Evidence.* A refusal writes one `denied` row for `platform.user.deactivate` in a separate transaction, with reason `registry_scan_limit` and the configured ceiling in its metadata. It does not record a tenant count beyond "exceeds the ceiling", because none was established. A successful deactivation records the number of tenants visited in each pass.
- *Other failures.* A database error or a lost connection during a scan rolls the transaction back and is recorded as `failure`. Reaching the retry limit of step 6 is reported as a retryable error and recorded as `failure`. Neither leaves the user partly deactivated.
- *Over HTTP.* A distinct error code, so that a dashboard can tell the operator to use credential revocation. The status code is a Phase D detail.
- *When refused.* The deployment has more tenants than it is configured to scan. The operator's choices are to revoke the user's sessions and API keys and disable the subject at the identity provider, which need no scan, or to have the ceiling raised and the application restarted.
- *What the ceiling is not.* It bounds work. It says nothing about whether the locking of this section is correct, and it does not replace the Phase C race tests. A deployment under the ceiling gets exactly the argument above, with exactly its open points.

*Disclosure.* A refusal names the tenant whose last administrator the user is. That tells the operator one fact about one tenant's membership. The operator needs it to act, and it is recorded in the `denied` audit row.

**Consequence.** A user who is the last administrator of a tenant cannot be deactivated until that tenant has another administrator. For an incident involving such an account, the response is `revoke_user_sessions`, disabling the subject at the identity provider, and `revoke_user_api_keys` (11f).

#### 11d. Credentials: sessions and API keys (decisions D6 and D7)

**Sessions.** Step 7 runs `UPDATE core.sessions SET revoked_at = now() WHERE user_id = :u AND revoked_at IS NULL`. `core.sessions` is global and indexed on `user_id`.

*A racing login.* `issue_session` reads `is_active` with an unlocked `session.get` and then inserts. A login that read `true` just before the deactivation committed can insert a live session row afterwards. That row cannot be used while the user is inactive, because `validate_session` checks the user on every request; the risk is only that it would become usable on reactivation. Two measures close it, and both are required:

1. `issue_session` reads the user through `lock_user_is_active` (`FOR SHARE`) in the inserting transaction. An issuance in flight then makes step 5 wait, and its row is committed and visible to step 7; an issuance that starts after step 5 waits, reads `is_active = false` and refuses. This is a change to one Core function, in Phase C.
2. `reactivate_user` revokes any session still unrevoked before it sets `is_active = true` (11b).

**API keys.** Facts read from the code:

- `core.api_keys` is classified `GLOBAL` and has no row-level security: a key is resolved by its hash before any tenant is known (`saas_os/core/tenancy/isolation.py`; `saas_os/core/api_keys/service.py`). All of a user's keys, in every tenant, are therefore reachable in one statement with no tenant scan.
- `validate_api_key` is the only function that authenticates a key. It refuses a revoked or expired key, a key whose tenant does not admit principals, and a user-owned key whose owner is missing or inactive, reading the owner on every call with no cache. The owner read is unlocked and in its own transaction.
- No SaaS OS HTTP path authenticates with an API key. `saas_os/api` accepts session credentials only; API-key request authentication is ADR-0040 gap G3, a separate track. A product may call `validate_api_key` itself.
- `create_api_key` requires an active caller under a `FOR SHARE` lock on the caller's row (`require_active_user`). `rotate_api_key` inserts a new key for the old key's owner; when the caller is an administrator acting on another user's key, the owner's row is neither read nor locked.
- There is no index on `core.api_keys.user_id`.

*Design (option 1 of D7: transactional revocation).* Step 7 also runs `UPDATE core.api_keys SET revoked_at = now() WHERE user_id = :u AND revoked_at IS NULL`. Revocation is permanent in the existing model: nothing clears `revoked_at`, so a revoked key cannot return on reactivation, and a user who is reactivated must be issued new keys by the existing, separately authorized, operations. The live owner check in `validate_api_key` stays as a second, independent refusal.

*Races.*

- A key being created by U: `create_api_key` holds `FOR SHARE` on U's row, so step 5 waits for it and step 7 revokes the key it committed. A creation that starts later waits and is refused.
- A key of U being rotated by an administrator: not serialized today. Required change, Phase C: `rotate_api_key` locks the key owner's user row `FOR SHARE` and refuses when the owner is inactive. Without it, a rotation can commit a new key for U after step 7; that key is refused by `validate_api_key` while U is inactive, and is removed by `reactivate_user`'s revocation step, but the design does not rely on that alone.
- A validation in flight: `validate_api_key` may return a key an instant before the revocation commits. The request it authenticated then reaches `can()`, which reads U's row under lock and refuses once the deactivation has committed. There is no window in which a mutation is authorized for a deactivated user.

*Dependency on the API-key authentication track.* None for the guarantee itself: the keys are revoked in the database whatever authenticates them. One constraint is placed on that track and recorded here so that it is not lost: any future request-authentication path must authenticate through `validate_api_key` and must not resolve a key by another route. If G3 is ever implemented with its own lookup, that lookup must honour `revoked_at`, which this design sets.

*Evidence.* The platform audit row for the deactivation records the number of sessions and the number of keys revoked. In the same transaction, for each tenant that had a key revoked, one `api_key.revoke` row per key is written to that tenant's own `core.audit_log` inside `bind_tenant_scope`, naming the operator as a `user` actor, as section 8 requires of every operation that changes a tenant's state. The tenants concerned are read from the revoked key rows themselves; no discovery is needed. Key hashes and names are not recorded.

*Schema.* An additive index on `core.api_keys (user_id) WHERE user_id IS NOT NULL`, so that the revocation is not a sequential scan. Phase C.

#### 11e. When it takes effect, and compatibility

- *Sessions.* The next request presenting the session fails in `validate_session`. A request already past authentication when the change commits runs on, except that any Core mutation it attempts re-evaluates `can()` or `platform_can()` under lock and is refused.
- *API keys.* The next `validate_api_key` call refuses the key as revoked.
- *Identity provider.* Disabling a user at the identity provider alone does not end a SaaS OS session, which lasts up to twelve hours. The runbook states that incident response starts in SaaS OS.
- *Direct edits.* A deployment that sets `is_active` by SQL gets ADR-0031's old behaviour for that edit: the database revokes nothing. The amendment says that the contract belongs to the operation, and the runbook tells operators to use it.
- *Behaviour changes for consumers.* A reactivated user must log in again and needs new API keys. An administrator can no longer rotate the key of an inactive user. `issue_session` takes a row lock it did not take. None of these breaks shipped code; each changes an observable outcome and is listed in the ADR-0031 amendment.
- *Existing tests.* `tests/core/rbac/test_authorization_transaction_race_integration.py` already forces both orderings of a user-deactivation race by changing the column directly; those tests stay valid.

#### 11f. Revoking a user's API keys without deactivating (ruling R2)

**Why it exists.** A user who is a tenant's last administrator cannot be deactivated (11c), and a deployment above the scan ceiling cannot deactivate anyone. In both cases session revocation leaves the user's API keys working. `platform.api_key:revoke` is the eighteenth permission and exists for this one act.

**Scope of the permission.**

| It allows | It does not allow |
|---|---|
| Setting `revoked_at` on every unrevoked **user-owned** API key of **one named user**, in every tenant | Creating or rotating a key; reading or returning a key's secret, hash, name or tenant; listing a user's keys; revoking one chosen key and leaving others; revoking a service account's keys; deactivating, reactivating or resolving a user; revoking sessions; any other credential |

Service-account keys are machine credentials owned by one tenant and managed by that tenant's administrators under `(api_key, revoke)`. They are outside this permission.

**Operation.** `revoke_user_api_keys(user_id, *, caller, reason) -> int`.

- *Target.* Exactly one `user_id`, required. There is no "all users", no filter, no list. A user id that does not exist is refused with a not-found error. The target may be the caller: revoking one's own keys removes no authority.
- *Reason.* Required, bounded, non-empty, recorded.
- *Caller.* `UserCaller` holding `platform.api_key:revoke`, through `authorize_platform_caller` with operation key `api_key.revoke`. `ServiceAccountCaller` is refused. No system purpose is accepted.
- *Transaction.* One, opened with no tenant bound:
  1. Authorize the caller; the decision's `FOR SHARE` locks hold to the end.
  2. Lock the target's `core.users` row exclusively. This waits for a key creation by that user that is in flight (`create_api_key` holds the row `FOR SHARE`), so the key it commits is revoked too.
  3. `UPDATE core.api_keys SET revoked_at = now() WHERE user_id = :u AND revoked_at IS NULL RETURNING id, tenant_id`.
  4. Write the platform audit row.
  5. For each returned key, inside `bind_tenant_scope(session, tenant_id)`, write one `api_key.revoke` row to that tenant's `core.audit_log`, naming the operator as a `user` actor. The ordering rule of 9c applies: the platform row is written before the first bind block.
  6. Commit. Return the number of keys revoked.
- *No platform-owners lock and no administrator locks.* The operation changes no authority and is refused by neither invariant. It takes no advisory lock, so it cannot enter the lock-order cycle of 11c.
- *Result.* A count. Not the key ids, names or tenants.

**Evidence.**

| Row | Contents |
|---|---|
| Platform audit, `platform.api_key.revoke`, `success` | Actor; target type `user` and the user id; reason; number of keys revoked; number of distinct tenants affected. No key id, name, hash or tenant id |
| Tenant audit, `api_key.revoke`, one per key | Actor (the operator, as a `user`); the key id as resource id; the same metadata shape the existing `revoke_api_key` writes, plus a marker that the platform acted. Visible to that tenant's own administrators |
| Platform audit, `denied` or `failure` | Written separately; actor, target user id, reason code |

**Tenant isolation and customer data.** `core.api_keys` is a global table by existing classification, so the statement in step 3 crosses no row-level-security boundary and needs no tenant scope. The operation reads only `id` and `tenant_id` of the rows it revokes, uses them to write evidence into the tenants concerned, and returns neither to the caller. An operator learns how many keys a user had, and nothing about where. This is not an oversight read and adds no projection: `platform.user:read` does not report API keys, and this ADR does not change that.

**What it is not.** It is a point-in-time revocation. The user is still active. A user with a live session and the tenant permission `api_key:self_manage` can create a new key a moment later, and a tenant administrator can still rotate. An incident response therefore revokes sessions as well, and the runbook says so. Revocation is permanent: nothing clears `revoked_at`.

**Failure behaviour.** Any failure, in the update, in an audit write or at commit, rolls back the whole transaction: no key is revoked and no success row exists. The caller receives an error and repeats the operation. There is no partial outcome in which some keys are revoked and others are not.

**Bootstrap and existing operators.** The permission is an explicit entry in `BOOTSTRAP_PERMISSIONS` (section 6). It is implied by no other permission and implies none. An operator who holds `platform.session:revoke` or `platform.user:deactivate` does not hold it. In a deployment bootstrapped before a permission existed, nobody holds that permission until the recovery command grants it.

**Dependencies, none implemented here.**

- *Index.* `core.api_keys` has no index on `user_id`. The additive index of 11d is required for this operation too.
- *Validation.* The guarantee depends on every authentication of a key honouring `revoked_at`. `validate_api_key` does, on every call, with no cache. Any future request-authentication path (ADR-0040 gap G3) must do the same; that constraint is recorded in 11d.
- *Number of keys.* Nothing read in the schema or in `create_api_key` limits how many keys a user may hold. The update and the per-key audit rows are therefore not bounded by a constant. Phase C must establish whether a limit exists and, if none does, either bound the transaction or state the cost.
- *Closed tenants.* Whether `core.audit_log` accepts a row for a tenant that is `DELETED` or `PURGING` was not verified. If it does not, a key in such a tenant is still revoked and the platform row still counts it, and the per-key tenant row is omitted for that tenant; Phase C must confirm which.

### 12. Tenant lifecycle functions

The four caller-less functions gain a required, keyword-only `caller`, as ADR-0031 did for the rest of Core. This is a breaking change for consumers at the commit that makes it (see "Consequences").

| Function | Accepted callers |
|---|---|
| `create_tenant` | `UserCaller` with `platform.tenant:create`; `SystemCaller(PROVISIONING)`. Each subject to the parent rule of 12a |
| `transition_tenant_status` → `ACTIVE` from `PENDING` | as `create_tenant` |
| → `SUSPENDED` | `UserCaller` with `platform.tenant:suspend`; or the tenant's own administrator under the self-service rule below |
| → `ACTIVE` from `SUSPENDED` | `UserCaller` with `platform.tenant:reactivate` |
| → `DELETED` | `UserCaller` with `platform.tenant:delete` |
| → `PURGING`, `PURGED` | `SystemCaller(TENANT_PURGE)` |
| `move_tenant` | `UserCaller` with `platform.tenant:move`, not a member of the new parent's chain |
| `purge_tenant` | unchanged entry conditions; attribution through its caller |

#### 12a. Parent rule for tenant creation (decision D5)

**What exists.** `create_tenant(name, *, parent_id=None)` accepts any parent that exists and is not closed, from anyone. `SUSPENDED` counts as open. Three flows in the repository create tenants: the first-tenant bootstrap command (a root tenant, then `PENDING → ACTIVE`); the reference consumer's seed scenarios, which create roots and then children and grandchildren under tenants they created moments earlier and never activate, so every parent is `PENDING`; and a personal root tenant per user. No accepted ADR says who may attach a child to an existing tenant. ADR-0040 leaves tenant creation to this decision.

**Why the parent matters.** A child placed under a tenant is inside that tenant's hierarchy: its ancestors' SUBTREE administrators administer it, it counts against the ancestors' depth, and the billing hierarchy lets relationships follow the tree. A caller who can choose any parent can attach a tenant they control beneath somebody else's.

**The rule.**

| Caller | Root tenant (`parent_id` is `None`) | Child of a `PENDING` parent | Child of an `ACTIVE` parent | Child of a `SUSPENDED` parent | Child of a closed parent |
|---|---|---|---|---|---|
| `SystemCaller(PROVISIONING)` | Allowed | Allowed | **Refused** | Refused | Refused (existing) |
| `UserCaller` with `platform.tenant:create` | Allowed | Allowed | Allowed | **Refused** | Refused (existing) |
| A tenant administrator, by any tenant permission, delegation or support access | Refused | Refused | **Refused** | Refused | Refused |
| `ServiceAccountCaller`; any other system purpose; a missing caller | Refused | Refused | Refused | Refused | Refused |

- *Provisioning may build what it has just created and has not yet handed over.* A `PENDING` tenant has never been activated; only provisioning or an operator can activate it. Allowing a provisioning caller to attach children there preserves the bootstrap and every seed flow in the repository without change, and gives it no reach into a tenant that is in use. A request-supplied parent id that names an active tenant is refused in Core, whatever the product's endpoint did or did not check.
- *An operator may attach a child to an active tenant.* This is an explicit, authorized, audited act by a person, with dual evidence in the parent's own audit trail.
- *Nobody attaches a child to a suspended tenant.* A suspended tenant is frozen pending a decision about it. This is a new refusal: today the function allows it. It is a tightening of behaviour that no flow in the repository uses.
- *Tenant administrators have no path (ruling R3).* For the initial release, the only caller that can create a child beneath an `ACTIVE` tenant is a platform operator holding `platform.tenant:create`. `create_tenant` never consults `can()`, so no tenant role, SUBTREE role, delegation or support-access grant can authorize it. No tenant permission for child creation is introduced, and no other path is added in its place.

**Enforcement inside Core.** `create_tenant(name, *, parent_id=None, caller)`, in one transaction:

1. *Caller type.* `require_caller`; anything but a `UserCaller` or a `SystemCaller` is refused before any read.
2. *Hierarchy locks.* When a parent is named, the locks the function already takes: the hierarchy-wide advisory lock, then the per-node lock on the parent (`_lock_hierarchy_globally`, `_lock_hierarchy_nodes`). They keep a concurrent `move_tenant` from changing the parent's ancestry underneath the creation. They are advisory locks and are taken before any row lock, consistent with section 6.
3. *Parent state.* Read the parent row with a row lock that makes a concurrent status transition wait (the existing `lock_open_tenant` takes the row `FOR SHARE`; whether it can be reused as it is, or whether `transition_tenant_status` needs to be checked against it, is for Phase C to confirm). The status used below is the one read here, not one supplied by the caller. A parent that does not exist is `TenantNotFoundError`, as today.
4. *Authorization.* `authorize_platform_caller` with operation key `tenant.create_root` or `tenant.create_child` (section 5b). For a `UserCaller` this is `platform_can()` under `FOR SHARE` locks.
5. *Parent rule.* The caller type and the status read in step 3 select one cell of the table above. `PENDING`: allowed. `ACTIVE`: allowed for an operator, refused for provisioning. `SUSPENDED`, `DELETED`, `PURGING`, `PURGED`: refused. A status value the function does not recognise is refused.
6. *Existing checks*, unchanged: hierarchy depth, ancestry rows.
7. *Evidence*, in the same transaction: a platform audit row `platform.tenant.create` with the new tenant as target and the parent id and the parent's status in its metadata; a `tenant.create` row in the new tenant's audit; and, when there is a parent, a row in the parent's audit recording that a child was attached and by whom. For an operator the actor is the person. For provisioning the actor type is `system` with the purpose.

*Fail closed.* Every refusal happens before the tenant row is inserted. A refusal writes one `denied` row separately, with a reason code that distinguishes `parent_active_requires_operator`, `parent_suspended` and `parent_closed`. A failure in any evidence write rolls back the creation.

**What stops provisioning from reaching further.**

- *Moving.* `move_tenant` accepts no system purpose. A provisioning caller cannot create a tenant in an allowed place and then move it under an active one.
- *Activation is not attachment.* `PENDING → ACTIVE` changes a status, not a parent.
- *Chains.* A provisioning caller can extend a chain only below a `PENDING` tenant. A `PENDING` tenant under an active parent exists only if an operator put it there.
- *What this does not close.* `PROVISIONING` is already accepted by membership and role creation for any open tenant (section 5a). The parent rule closes the route through *creation*, and in particular the one driven by request input. It does not make a provisioning caller harmless to existing tenants; narrowing that is the deferred item it was in revision A.1.

**Impact on existing flows.** What the repository shows, and what it cannot show.

- *Verified in this repository.* No SaaS OS route creates a tenant. The first-tenant bootstrap creates a root. The reference consumer's scenarios create children only under tenants that are still `PENDING`, and one personal root per user. None of these creates a child beneath an `ACTIVE` parent, and each needs only the new `caller` argument.
- *Not knowable from this repository.* Whether a consuming product creates children beneath active tenants. `create_tenant` takes no caller today, so any product code may be doing so.
- *A product that activates a parent and then seeds children with a provisioning caller* will be refused. It must create the children before activating the parent, or have an enrolled operator create them.
- *A product whose sign-up flow attaches each new customer beneath an existing active tenant* (a reseller or a holding company, for example) will be refused when it uses a provisioning caller. In the initial release that flow requires an operator for each child, or a structure in which customers are roots.
- *A product whose tenant administrators create departments or sub-organizations at run time* loses that ability when it moves its pin past the commit that adds the caller. There is no replacement in the initial release. This is the largest consumer impact in this ADR; it is deliberate, it is stated in the consumer guide and in the upgrade notes of that commit, and it is the reason a tenant-scoped permission for child creation is listed under "Deferred" as a decision that product demand may reopen.
- Refusing a `SUSPENDED` parent is new for every caller.

All of them write their evidence in the same transaction as the change. Today create, move and suspend write none, and the deletion event is written after commit. The existing lifecycle fences and the ADR-0043 descendant guard are kept as they are.

**Nothing is disclosed to a caller without authority (added 2026-10-13, before Phase D).** `transition_tenant_status` selects its operation from the status it reads, so it cannot authorize before it reads; as first implemented it reported a missing tenant or an invalid edge before authorizing, to anyone, with no `denied` row, after taking the administrator locks and the tenant's row lock. It now applies a *preliminary gate* before the tenant is read or locked: from the target status alone it derives the operations that target can select (`ACTIVE`: activation or reactivation; every other reachable status: one), and refuses a caller who could be authorized for none of them. A target no edge of the graph leads to (`PENDING`) selects nothing: it is refused as an invalid request, in the same words for every caller and every tenant, before the gate and before anything is read. The gate passes a system purpose one of them accepts, a person who holds the platform permission of one of them (evaluated without holding any lock afterwards), and, when suspension is among them, a person with a membership of exactly that tenant, the only people the self-service rule can admit. It reads no tenant row and takes no tenant row lock or administrator lock. A caller it refuses gets `PlatformNotAuthorizedError` and one `denied` row, identically for a tenant that does not exist and for one in any status. The row carries the target status, the candidate operations and the marker `stage: preliminary`; for an `ACTIVE` target, where two operations are candidates, its action is `platform.tenant.activate`. *The gate is not the decision.* The caller is authorized again inside the transaction, after the administrator locks and the tenant's row lock, in the order this ADR fixes, so authority revoked after the gate does not carry the transition. Where the target fixes the operation that decision is made before a missing tenant or an invalid edge is reported, so those two errors reach only a caller who holds the authority the transition needs. *Residual, accepted:* for an `ACTIVE` target the operation depends on the status read, so a missing tenant or an invalid edge is reported before the operation is known. It is reported only to a caller who holds, inside the transaction and under its locks, the authority for activation or for reactivation (the provisioning purpose included); such a caller can learn that a tenant does not exist, its status when the edge is invalid (the error names it), or that it needs the other of the two. A caller who holds the authority a transition needs learns, as before, that the tenant is missing or the edge invalid, which that caller needs in order to act. *Three behaviours changed for existing callers.* A system purpose that the target does not accept (provisioning asked to suspend or delete) is now refused, where it was told that the tenant was missing or the edge invalid. A request for a target no edge leads to is `InvalidPlatformRequestError` for everyone, where it was `TenantNotFoundError` or `InvalidTenantTransitionError`. And because the self-service rule admits a member only of a tenant that admits its principals, a member who repeats the suspension of an already suspended tenant is refused (`PlatformNotAuthorizedError`, one `denied` row naming that member), where the invalid edge was reported.

**Tenant self-service suspension (constraint 8)**

- A new tenant-scoped permission, `tenant:suspend`, in the tenant catalog. It is a tenant permission evaluated by `can()`, not a platform permission.
- **Who.** A `UserCaller` who is an ACTIVE member of that exact tenant and holds `tenant:suspend` there through an ordinary membership role. A delegation does not satisfy it. A support-access grant does not satisfy it: `("tenant", "suspend")` joins the action-level support exclusions next to the billing mutations. A service account does not satisfy it.
- **What.** `ACTIVE → SUSPENDED` of the caller's own tenant only. Not a descendant, not deletion, not purge.
- **Safeguards.** A required reason; the caller confirms by supplying the tenant id in the request body as well as the path; the ADR-0043 guard for descendants applies unchanged; the designated platform tenant (`PLATFORM_TENANT_ID`) cannot be self-suspended, because it owns the deployment's merchant account.
- **No self-reactivation.** A suspended tenant admits none of its own principals, so nobody in it can reactivate it. Reactivation requires `platform.tenant:reactivate`. This is stated in the route's documentation and is the main reason for the confirmation step.
- **Not granted by default.** No existing role receives `tenant:suspend`. The first-tenant bootstrap's owner role is unchanged.
- **Route.** An opt-in tenant router under the existing chain (`require_permission("tenant", "suspend")`), not part of the platform-admin router.

### 13. Feature flags

- `create_flag` takes a caller: `platform.feature_flag:define`, or `SystemCaller(PROVISIONING)` for a product's seed code.
- `set_tenant_override` and `remove_tenant_override` take a `UserCaller` with `platform.feature_flag:override`, and write dual evidence (section 8) in the same transaction. A tenant override changes what a tenant may do, and the self-learning kill switch is a flag, so no system purpose is accepted.
- `evaluate_flag` and the read functions used at run time are unchanged.

### 14. Failure behaviour

| Situation | Behaviour |
|---|---|
| Missing or wrongly typed caller | `CallerTypeError` before any read |
| Database unavailable during a platform decision | The decision raises; the route answers `503`; nothing is treated as allowed |
| Rate-limit backend unavailable | `503`, as the tenant chain does |
| Platform audit row cannot be written | The transaction rolls back; the operation did not happen |
| Router mounted without `PLATFORM_ADMIN_HTTP_ENABLED=true` | Startup fails |
| A route with no policy, or with both a tenant and a platform policy | Startup fails |
| A change would remove the last platform owner | `LastPlatformOwnerError`; rolled back |
| A deactivation would remove a tenant's last administrator | `LastTenantAdministratorError` naming the tenant; rolled back |
| Unknown permission string in a grant row | Treated as no grant; the CHECK prevents it from being stored |
| Deadlock between two guarded transactions | PostgreSQL fails one; nothing changed; retry |
| A system purpose presented to an operation that does not list it | Refused before any write; `denied` audit row |
| A platform read or write attempted while a tenant is bound | The database returns no rows or rejects the write; the operation fails closed |
| Oversight request above a page maximum | Rejected with a validation error; not clamped |
| Membership created during `deactivate_user` | Aborted with a retryable error; nothing changed |
| Tenant registry larger than the scan ceiling | `deactivate_user` refuses with `DeactivationScanLimitError`; no partial scan; `denied` row with the ceiling |
| Scan ceiling setting missing | Default 10 000 |
| Scan ceiling setting not an integer, or below 1 | Startup fails |
| Oversight statement timeout setting missing | Default 5000 ms |
| Oversight statement timeout setting not an integer, or outside 100 to 60000 | Startup fails |
| `revoke_user_api_keys` fails at any step | Whole transaction rolled back; no key revoked; `failure` row |
| `revoke_user_api_keys` for a user id that does not exist | Not-found error; nothing written but the refusal row |
| A tenant administrator, or a provisioning caller, creates a child beneath an `ACTIVE` parent | Refused in `create_tenant`; `denied` row |
| Session older than 900 seconds on an authority-changing route | `401` with a distinct code; `platform_can()` is not evaluated; refusal audited |
| `PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS` above 900 or below 60 | Startup fails |
| Provisioning caller names an `ACTIVE` or `SUSPENDED` parent | Refused in `create_tenant` on the status read under lock; `denied` audit row |
| Bootstrap list contains a value outside the vocabulary, or a duplicate | The command exits before any write |
| Recovery would suspend the only owner without a replacement | Refused; nothing changed |

### 15. Threat scenarios

| Threat | Mitigation in this design | Residual |
|---|---|---|
| Unauthorized first owner | Bootstrap is a command run with the application role's credentials, refuses when any operator exists, needs a production confirmation, and is audited | Whoever holds the deployment's credentials can run it on a fresh deployment; that is tier 0 |
| Tenant administrator becomes platform operator | Disjoint storage and vocabulary; `platform_can()` reads no tenant data; platform permissions are not in `core.permissions` | None identified |
| Root-tenant SUBTREE role used as a global administrator | Not created by this design. A product that parents every tenant under one tenant creates this itself; the consumer guide warns against it | Product choice |
| Platform operator reads customer data | No function returns tenant rows beyond fixed projections; support access remains tenant-approved | In-process product code can; see section 1 |
| Platform operator gains tenant authority by moving a tenant | Move has no route, is authority-class, refuses a caller in the new parent's chain, and writes dual evidence | Two colluding operators |
| Same identity, second deployment | Grants live in each database | A cloned database carries its grants |
| Operator grants themselves more | No self-grant; anti-amplification | Two colluding owners |
| Stolen operator session | Fresh-session rule for authority changes; session revocation and deactivation effective on the next request; operator logins recorded | Up to the session lifetime for non-authority operations |
| Owner lockout | Last-owner invariant; recovery command | Tier 0 must be available |
| Recovery used as a backdoor | It requires tier-0 access already; every run is audited and logged at warning level; it can only enroll, grant and suspend | Detection, not prevention |
| Revocation not taking effect | Decisions lock the rows they read in the mutation's transaction; sessions and `is_active` are read on every request | None identified |
| Audit gaps | Same-transaction platform audit; dual evidence; human actor mandatory | Rows are protected from the application role only |
| Accidental exposure of the router | Two opt-ins; startup failure; architecture test that the default app has no platform route | A deployment that sets both deliberately |
| Route-only enforcement bypassed by an internal call | Authorization is inside each Core function | In-process code constructing a `SystemCaller` (below) |
| `IAM_OWNER` takeover of an owner's subject | Section 10 | Accepted tier-0 risk |
| A tenant-scoped code path reads or alters platform grants through a bug | Import contract; the exclusion policy (D1) refuses it in any tenant-bound transaction | Code that opens an untenanted transaction or clears the variable; D1 is not an authorization boundary |
| Forged platform audit rows | Only one function writes them, pinned by an architecture test; no `UPDATE` or `DELETE` | In-process code can insert; tier 0 can alter; no tamper evidence |
| A request path obtains system authority | No request input is parsed into a purpose; no router imports `SystemCaller`; one declared operation table | A product's own handler that constructs a `SystemCaller` deliberately |
| `PROVISIONING` used to do an operator's work | The matrix of section 5a, checked at run time per operation and per transition | Its existing reach into tenant authority (section 5a), unchanged |
| Oversight used to harvest tenant data | Fixed projections; page maxima; per-actor rate limit; an attempt row committed before each read and a completion row with the count after it | An operator paging the whole registry over time; visible in the audit |
| A reactivated user regains an old session or API key | Deactivation and reactivation both revoke sessions and user-owned keys; issuance locks the user row | A deployment that edits `is_active` by SQL |
| A sign-up endpoint passes an attacker-chosen parent tenant | Provisioning may create only roots and children of `PENDING` tenants, checked in Core under lock (section 12a) | Provisioning's existing reach into open tenants through membership and role creation |
| Deactivation leaves a tenant with no administrator through a race | Section 11c: locks, two scans and the argument for them; blocking race tests in Phase C | Unproven until those tests run; a tenant that had no administrator is not protected, as in ADR-0043 |
| An operator revokes a user's API keys to disrupt a tenant | Separate permission; required reason; a row per key in the tenant's own audit, so the tenant sees who did it | The keys are gone; the tenant must issue new ones |
| An unauthorized caller makes Core scan the registry | Preliminary authorization before the scan; scan ceiling | In-process code |
| A tenant administrator grows the hierarchy beneath their tenant without the platform | No tenant path to child creation in the initial release | — |
| Operator suspends themselves or the last owner to cause lockout | No self-service; last-owner recheck; recovery command | Tier 0 must be available |

**The `SystemCaller` boundary.** A `SystemCaller` remains a value any in-process code can construct. This design does not change that. Section 5a gives the purpose-to-operation matrix, the run-time checks that enforce it, the static checks that support it, and the limit of the claim. The static guard is evidence about this repository's own code, not a control over a consumer's, and neither it nor a purpose value is a run-time security boundary.

## Reconciliation with existing ADRs

Where the amendments stand:

- **Written (2026-10-12).** ADR-0002, ADR-0022, ADR-0030, ADR-0031, ADR-0040 and ADR-0043 each carry a section "Amendment (2026-10-12): reconciliation with ADR-0045 (platform authority)", with short markers on the sentences it supersedes. Those sections are the authoritative wording of the amendments; the rows below summarise them.
- **Still to be done with the code, not in an ADR.** The `_ALLOWLIST` entries ADR-0022's amendment calls for, and the isolation-registry entries ADR-0030's amendment calls for, are written in the phase that adds each function or table.
- **No amendment needed.** ADR-0029, ADR-0005, ADR-0044, ADR-0042, ADR-0015 and ADR-0016.

Every amendment records a decision. None describes implemented behaviour: until the phase named for each item ships, the amended ADRs' own bodies describe the code.

| ADR | Change | Why | Changes an accepted invariant? | Migration or consumer impact | Needs separate approval? |
|---|---|---|---|---|---|
| **0040** Reusable HTTP capabilities | Record that G1 is decided by ADR-0045. Its "never a route" row is narrowed: tenant create, suspend, reactivate and flag administration become routable only through the opt-in platform-admin router; move, delete, purge, erasure and bootstrap stay never-a-route. Contract rule 2 (`/v1/tenants/{tenant_id}/…`) gains the `/v1/platform/…` prefix for platform routes | ADR-0040 itself asks for this decision (questions 1–5 under G1) | It changes a classification ADR-0040 made conditional on "until a platform-authority model exists". Rule 1 (opt-in) and rule 3 (one policy per route) are kept | New public routes under `/v1`, contract once a product calls them | Covered by accepting this ADR |
| **0030** Foundation enforcement | A fourth route policy kind, `platform_permission`, with its conflict rules; three new `GLOBAL` entries in the isolation registry | The existing three kinds cannot express a caller with no tenant | It extends "exactly one policy, of three kinds" to four. Fail-closed startup is kept. Under D1 the registry's `GLOBAL` class, documented as "deliberately not RLS-scoped", gains three tables that carry the exclusion policy. Decided: keep them `GLOBAL`, reword the class to "not scoped by the tenant policy", and record the policy on each entry | None for existing routes or tables | Covered by accepting this ADR (D1 approved) |
| **0031** Authority and evidence | One new `SystemAuthority` purpose (`PLATFORM_BOOTSTRAP`); one new reviewed construction site; tenant lifecycle and feature flags gain callers and same-transaction evidence, closing its "Feature flags and tenant lifecycle" and "User deactivation" deferrals; `("tenant", "suspend")` joins the action-level support exclusions; the static guard is hardened | Those deferrals are exactly the gaps the audit found | **Yes, one, and it tightens.** ADR-0031 section 5 says "deactivation does not revoke session rows" and "reactivating the user makes an unexpired session valid again". Under this design the deactivation operation revokes sessions and user-owned API keys, and reactivation restores neither (section 11a quotes the text and gives the replacement). `issue_session` and `rotate_api_key` gain a user-row lock, and rotation of an inactive owner's key is refused. Written into ADR-0031's amendment of 2026-10-12 | **Breaking** signature change for `create_tenant`, `move_tenant`, `transition_tenant_status`, `create_flag`, `set_tenant_override`, `remove_tenant_override` | Approved as D6 and D7; the amendment text is written on acceptance |
| **0043** Last tenant administrator | User deactivation becomes a guarded change, as its "What this does not cover" section requires | A deactivation function now exists | No; it applies the invariant where the ADR said it must be applied | None | No |
| **0002** Multi-tenancy isolation | A reference: the oversight reads are the audited cross-tenant path it commits to. Under D1, a second policy shape, for the three platform tables only | Traceability; D1 gives database-enforced separation of tenant-bound transactions from platform records | The tenant policy, the single GUC, `FORCE`, no `BYPASSRLS` and no `SECURITY DEFINER` are all unchanged. D1 adds to "one equality-comparison policy per tenant-owned table" a different policy on tables that are not tenant-owned; it relaxes nothing | None | Covered by accepting this ADR (D1 approved) |
| **0022** Tenant-session boundary | New allowlist entries for the new untenanted call sites; `bind_tenant_scope`'s documented single purpose gains the oversight and deactivation uses | The test fails otherwise | No | None | No |
| **0029** Commercial parties | None. `PLATFORM_TENANT_ID` continues to grant nothing; the only new behaviour is that the platform tenant cannot be self-suspended | — | No | None | No |
| **0005** Identity | None. No identity-provider claim maps to authority | — | No | None | No |
| **0044** Same-origin check | None. It applies to platform routes through `get_current_actor` | — | No | None | No |
| **0042** Frontend strategy | None. No frontend is added; the dashboard is the product's | — | No | None | No |
| **0015 / 0016** Distribution, migrations | None. Three additive tables in SaaS OS's own migration history | — | No | Consumers run the migration on upgrade | No |

## Decisions D1–D8

Approved by the repository owner on 2026-10-12 and incorporated above. The ADR as a whole was accepted afterwards, on the same date.

| # | Decision as approved | Where it is specified | Condition or limit attached to it |
|---|---|---|---|
| D1 | Tenant-context exclusion policy on the three platform tables, as defence in depth | Section 9a (the database as it is), 9b (matrix, policy, behaviour per state of the variable), 9c (ordering rule) | Not an authorization boundary; does not distinguish platform code from other code under the same role; Core authorization mandatory. Adds a policy shape to ADR-0002 and ADR-0030 |
| D2 | Authority-changing HTTP operations require a SaaS OS session at most 900 seconds old | Section 7 | One limit; may be lowered to 60, never raised. Measures session age, not identity-provider authentication. Route-level only |
| D3 | Maxima: 200 tenants per registry page; 50 tenants per overview call; 10 subscriptions per tenant; 50 sessions per user. Over-limit requests rejected | Section 9d, with the query behind each limit | The subscriptions query sorts one tenant's rows; no covering index exists |
| D4 | Tenant-registry scans for `deactivate_user` only with a concurrency argument | Section 11c: facts, transaction, lock order, case analysis, what is outside it | An argument from reading code. `deactivate_user` is blocked from exposure until the Phase C race tests pass. One deadlock is not eliminated. Work bounded by the scan ceiling (R1), which is not a correctness argument |
| D5 | No provisioning under an arbitrary parent | Section 12a; section 5a matrix | Provisioning: root or `PENDING` parent only. Operator: root, `PENDING` or `ACTIVE`. Nobody: `SUSPENDED` or closed. Tenant administrators have no path (R3) |
| D6 | Deactivation revokes live sessions in the same transaction; reactivation restores none; racing issuance closed; no self-deactivation; both invariants kept; session revocation separately authorized | Section 11a, 11b, 11c, 11d, 11e | Replaces an accepted sentence of ADR-0031 section 5; amendment written into ADR-0031 on 2026-10-12. Requires `issue_session` to lock the user row |
| D7 | User-owned API keys do not remain usable after deactivation and do not return on reactivation | Section 11d | Transactional, permanent revocation; `core.api_keys` is global, so no scan. Requires `rotate_api_key` to lock the owner row and an additive index. No dependency on the API-key authentication track; one constraint recorded for it |
| D8 | Bootstrap grants an explicit, literal, reviewed list; later permissions are not granted automatically | Section 6, "Bootstrap" | Two literals whose union must equal the vocabulary, checked by test; run-time validation before any write; database CHECK as the last line |

## Rulings R1–R3

Approved by the repository owner on 2026-10-12 and incorporated above.

| # | Ruling | Where it is specified |
|---|---|---|
| R1 | A configurable ceiling on the tenant registry scan of `deactivate_user`, default 10 000. Refuse above it; never truncate, skip or proceed on a partial scan. The ceiling bounds work and proves nothing about concurrency | Section 11c, "The scan ceiling"; section 14 |
| R2 | `platform.api_key:revoke`, the eighteenth permission: revoke the user-owned API keys of one named user and nothing else | Section 4; section 5b; section 6 (bootstrap tuple); section 7; section 11f |
| R3 | In the initial release only a platform operator creates a child beneath an `ACTIVE` parent. Tenant administrators and provisioning callers do not. Root and `PENDING` rules unchanged | Section 12a |

No design decision is open.

## Open questions for Phase C

Seven questions. These are not decisions for the repository owner. They are facts that only implementation and tests can establish, and each is a condition on the phase that depends on it. Accepting this ADR answers none of them.

| Question | Why it is open | Consequence if the answer is unfavourable |
|---|---|---|
| Does the locking of section 11c hold under the six numbered race tests of the Phase C plan? (The seventh deactivation test, for a tenant move during the scan, is the last question of this table.) | It is an argument from reading code | `deactivate_user` and `reactivate_user` are withdrawn from Phase C |
| Does every ADR-0043-guarded mutation take its administrator lock first? | Read directly only for membership transitions | The case analysis of 11c has a gap for the mutation that does not |
| Is there a limit on API keys per user? | None was found | `revoke_user_api_keys` and deactivation need a bound or a stated cost |
| Does `core.audit_log` accept a row for a closed tenant? | Not verified | Per-key tenant evidence is omitted for closed tenants and the platform row is the only record |
| Can `lock_open_tenant` serve as the parent-state lock in `create_tenant`? | Its interaction with status transitions was not read | A dedicated row lock is added |
| Does the last-owner locking of section 6 hold under its twelve concurrency tests? | Paper analysis | The owner operations are not exposed |
| What happens when `move_tenant` commits while `deactivate_user` is between reading tenant depths in its first scan and taking the administrator locks of the tenants it found (section 11c, steps 2 and 3)? | Found during the reconciliation with ADR-0043 and not analysed. The deactivation orders its administrator locks by depths it read earlier; a move can change those depths, so the order may disagree with the order a concurrent guarded mutation in the moved subtree uses. Whether that can produce a deadlock, whether PostgreSQL then resolves it without leaving either invariant violated, and whether the membership and administrator facts the deactivation recorded are still the right ones after the move, are all unverified. Nothing is asserted about the outcome | A seventh blocking race test for `deactivate_user`. If the interleaving can violate an invariant, the locking of 11c must change (for example by taking a hierarchy lock, whose order relative to the platform-owners lock is not defined today) before the operation is exposed |

Corrections carried from revision A.1, not decisions: a subscription period end is not stored and is in no projection; a user's tenant list cannot be read across tenants and is in no projection.

## Consequences

- **Breaking change for consumers** at the commit that adds callers to the tenancy and feature-flag functions. A product's seed and sign-up code passes `SystemCaller(SystemAuthority.PROVISIONING)` to `create_tenant` and to activation, as the reference consumer already does for roles and memberships. A product that suspends, moves or deletes tenants from its own code must do so as an enrolled operator. Consumers pin an exact commit (ADR-0015), so the break arrives only when a consumer moves its pin.
- **Reactivation restores no credential.** A reactivated user logs in again and is issued new API keys.
- **Provisioning cannot attach a tenant beneath an active one.** A product either builds a hierarchy before activating it or has an operator extend it (section 12a, ruling R3).
- **A sole owner cannot change their own authority.** They need a second owner or the recovery command. This is deliberate; a single-operator deployment will use the command.
- **Suspension can be self-inflicted and not self-reversed.** A tenant that suspends itself needs the platform to return.
- **Two authorization functions.** Reviewers must check that a platform operation calls `authorize_platform_caller` and a tenant operation calls `authorize_caller`. Architecture tests enumerate both inventories.
- **Three new tables and one new package** in Core, one in the API layer.
- **More audit rows**, and a second place to look for evidence.

## Implementation status

As of 2026-10-13 (first written 2026-10-12; each later subsection is dated). This section records what exists; it changes no decision above.

**Phase B is implemented and merged into `main`** (merge commit `bb9ca423f3875ee03d73ccb2c24b7d911b3a18eb`, pull request #9, four commits). Merging it deploys nothing and activates nothing: a deployment gains the three tables when it runs the migration, and has no platform operator until an operator runs the bootstrap command.

| Part of Phase B | Status |
|---|---|
| Migration `c4a9e1f07b52`: the three platform tables, constraints, partial unique indexes, the tenant-context exclusion policy, explicit privilege revocations | Implemented |
| `PlatformPermission` (18 members), the declared operation table (26 rows), `platform_can()`, `authorize_platform_caller()` | Implemented |
| Operator and grant lifecycle: enroll, suspend, reactivate, revoke; grant, revoke | Implemented |
| Last-active-platform-owner invariant: advisory lock, authorization after the lock, recheck on the flushed state | Implemented |
| Platform audit: in-transaction success rows; separate, best-effort refusal rows | Implemented |
| `SystemAuthority.PLATFORM_BOOTSTRAP`; `python -m saas_os.api.platform_bootstrap` (`bootstrap`, `recover`) | Implemented |
| Isolation registry, retention registry (`SECURITY_RETAIN`), session-boundary allowlist, `bind_tenant_scope()` caller pin, import-linter contracts | Implemented |

**Not implemented, and not part of Phase B.**

- **No platform HTTP surface.** There is no platform-admin router, no `platform_permission` route policy and no `/v1/platform` route. Nothing is activated.
- **No Phase C behaviour.** No caller on the tenant lifecycle or feature-flag functions; no `deactivate_user`, `reactivate_user`, `revoke_user_sessions` or `revoke_user_api_keys`; no oversight read; no operator-login event; no tenant self-service suspension. An architecture test asserts that none of these functions exists.
- **No platform read operations.** `operator.read` and `audit.read` are rows of the operation table only.
- **`erase_user_identity` does not yet refuse an enrolled operator** (section 6).
- Phases C, D, E and F. Phase C remains separately gated.

**Validation performed.** Before the merge, locally, against PostgreSQL 16 and Redis 7 in disposable containers: the default test suite; the full integration suite; the migration gate; the packaging gate; Ruff, Pyright and import-linter; the secrets gate. On pull request #9, the repository's CI (Linux) passed all seven checks on the merged tree's head. Results are in the Phase B implementation report and the pull request, not restated here.

**What the concurrency evidence does and does not establish.**

- The twelve concurrency cases of section 6 were run against PostgreSQL with real locks. Eleven exercise the real operations.
- **Case 6 is a lock-order emulation.** Its row in section 6 is about `deactivate_user`, which does not exist. The test runs a test-only transaction that takes locks in the order section 11c specifies, against a real ADR-0043-guarded mutation, and shows that order composes without a deadlock. It is not a test of `deactivate_user`.
- **Nothing here establishes the correctness of `deactivate_user` or `reactivate_user`.** Their six numbered race tests and the tenant-move case do not exist. The gate stands: neither function is exported or routed until they pass.
- Of the seven "Open questions for Phase C", only the sixth (the last-owner locking) is addressed, and only for the operations Phase B implements. User deactivation as a way of removing an owner is not covered, because no Core function deactivates a user; `is_active` changed by direct SQL takes no lock and is outside the invariant. The other six questions are open.

**Findings from the implementation.**

- *Bootstrap and recovery resolve the identity inside the platform transaction.* Section 6 says bootstrap "resolves or creates the user with the existing `get_or_create_user_for_external_identity`". That function commits a user and its identity link in transactions of its own, so a refusal by Core left both behind for an identity the deployment had never seen. The implementation uses an in-transaction variant instead: the user, its identity link, the operator, the grants and the audit rows commit or roll back together. The decision is unchanged; the mechanism is stricter.
- *One negative control behaves differently from the prediction in section 6.* "Move authorization before the lock: both revoke each other" does not happen in this implementation. Without the lock, each transaction holds its own operator row `FOR SHARE` and needs the other's `FOR UPDATE`; PostgreSQL detects a deadlock and aborts one. The invariant survives, and a caller receives a database error instead of a refusal. The lock is what turns that into orderly serialization.
- *With people as callers, the last-owner recheck is not reachable in sequence.* An actor who holds `platform.authority:manage` is still an owner after removing somebody else, and self-change is refused. The recheck fires on the recovery path, and it is the backstop for the Phase C operations.
- *A refusal cannot always be recorded.* A `denied` row needs an existing user (foreign key) and a person or system actor. A refused service-account caller, and a `UserCaller` naming no real user, are refused and logged, not recorded.
- *Rows written in one transaction share a timestamp.* Their order within one bootstrap is not meaningful.
- *Two negative controls were not run:* dropping the privilege revocations, and dropping the exclusion policy, would need committed DDL on a shared database. Both properties are asserted directly, as the runtime role, in the migration test.

**Amendment (2026-10-13): an oversight read is audited by two rows.** Approved by the repository owner on 2026-10-13. Section 8 required one row, written before the read, that recorded the number of entries returned; section 9d placed its insert before the page read. A row that cannot be changed cannot record what is read after it is written. Both sections, the failure table of 9d, the risk table and the negative controls now describe an attempt row committed in a transaction of its own before anything is read, and a completion row in the read transaction that carries the count and the attempt's id. What this changes: an oversight read is authorized twice, leaves two rows, and its attempt survives a read that fails. What it does not change: no returned value is ever recorded; the runtime role still has only `INSERT` and `SELECT` on the table; no column, constraint or outcome value was added; `correlation_id` keeps its meaning. The same day the owner approved correcting `move_tenant` to the lock order of section 11c, implementing the erasure safeguard of section 6, and leaving the locking of deadlock cases 5 and 7 as it is; see "Implementation status".

**Amendment (2026-10-12): the import rule between tenant RBAC and platform authority is a direct-import rule.** Approved by the repository owner on 2026-10-12. It changes how one boundary is checked; it changes no decision above and implements nothing of Phase C.

- *What was merged with Phase B.* The import-linter contract "Tenant RBAC does not depend on platform authority" was transitive: it failed if any import path led from `saas_os.core.rbac` to `saas_os.core.platform_authority`. That is stricter than section 5, which says that `saas_os.core.rbac` does not import the module.
- *Why it could not stand.* `saas_os.core.rbac` imports `saas_os.core.tenancy` and `saas_os.core.identity`. Section 12a requires `create_tenant` to call `authorize_platform_caller`, and Phase C places the other enforcement in the modules that own the state. Any of those imports creates a path from tenant RBAC to the platform package, so the transitive contract and Phase C could not both hold.
- *The rule now.* The contract carries `allow_indirect_imports = true`, as the reverse contract already did: no module of `saas_os.core.rbac` may import the platform package directly, and an indirect path is permitted. A negative control writes a direct import into `saas_os/core/rbac/__init__.py` and shows that the contract still fails.
- *What replaces the transitive check.* `tests/architecture/test_platform_authority_contract.py` pins the modules outside the package that import it, in any form including a deferred import, each with a reason (`_APPROVED_DIRECT_IMPORTERS`). An importer that is not listed fails the test, and no module of `saas_os.core.rbac` may be listed. Today the list has one entry, the bootstrap command. Each phase that adds an importer adds its entry, reviewed.
- *What is unchanged.* `can()` reads no platform operator or grant. Only the platform package imports the platform models, and no file of `saas_os.core.rbac` mentions the package; both are existing tests. The reverse contract, permission ownership, fail-closed authorization and the audit rules are untouched.
- *What this does not establish.* These are static checks on this repository's source. A dynamic import built from a computed string is not detected, and a consuming product's code is not scanned.

**Phase C is implemented and merged into `main`** (2026-10-13; merge commit `92792d10af982c9bf86693f2b4423a474fa64800`, pull request #13, one commit, `e2ee872af6e39dc00271fdbd7c8ec425513f52a2`). Merging it deploys nothing and activates nothing: no route was added, and a deployment gains the index on `core.api_keys.user_id` when it runs the migration. This subsection records what was merged; it changes no decision above. The earlier paragraphs of this section describe Phase B as it was merged and are left as written.

| Part of Phase C | Status | Where |
|---|---|---|
| Required caller on `create_tenant`, `move_tenant`, `transition_tenant_status`; the edge selected from the status read under lock; same-transaction dual evidence | Implemented | `saas_os/core/tenancy/service.py`, `saas_os/core/tenancy/authority.py` |
| Parent rule (D5, R3) | Implemented | `_apply_parent_rule` |
| `move_tenant` refuses a caller who is a member of the new parent's chain | Implemented. A suspended membership counts; a revoked one does not | `caller_is_member_of_any` |
| Tenant self-service suspension: `tenant:suspend`, the support exclusion, the platform-tenant refusal, no self-reactivation | Implemented in Core. Its opt-in route is Phase D | `holds_through_own_membership` in `saas_os/core/rbac/authorization.py` |
| Feature flags: `create_flag`, `set_tenant_override`, `remove_tenant_override` | Implemented | `saas_os/core/feature_flags/service.py` |
| `revoke_user_sessions`, `revoke_user_api_keys` | Implemented and exported | `saas_os/core/identity/user_authority.py` |
| `deactivate_user`, `reactivate_user` | Implemented and exported; the gate is met (below) | same module |
| Scan ceiling `PLATFORM_DEACTIVATION_MAX_TENANTS` (R1) | Implemented; read at application startup | `saas_os/core/identity/config.py` |
| `issue_session` and `rotate_api_key` lock the owner's user row; rotation of an inactive owner's key is refused | Implemented | `sessions.py`, `saas_os/core/api_keys/service.py` |
| Additive index `core.api_keys (user_id) WHERE user_id IS NOT NULL` | Implemented | migration `d7e4b2a91c36` |
| Tenant registry read and commercial overview | Implemented | `saas_os/core/tenancy/registry.py`, `saas_os/core/billing/oversight.py` |
| Two-event oversight audit (sections 8 and 9d as amended 2026-10-13): the attempt row committed before the read, the completion row in the read transaction | Implemented for the two Phase C reads and, through `run_oversight_read`, the six of Phase D milestone 1 | `record_oversight_attempt` in `saas_os/core/platform_authority/audit.py` |
| `erase_user_identity` refuses a user with a non-revoked operator row (section 6) | Implemented; one `denied` row under `platform.user.erase` | `refuse_erasure_of_enrolled_operator` in `saas_os/core/identity/user_authority.py` |
| `move_tenant` takes the moved subtree's administrator locks before the authorization row locks (section 11c order) | Implemented | `saas_os/core/tenancy/service.py` |
| Statement timeout of the oversight reads, both transactions (section 9d); setting `PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS` | Implemented before Phase D, 2026-10-13 (merged, pull request #15) | `set_local_statement_timeout` in `saas_os/infra/db/session.py`; `oversight_read_timeout` in `saas_os/core/platform_authority/oversight.py`; `saas_os/core/platform_authority/config.py` (moved there from `saas_os.core.tenancy` in Phase D milestone 1) |
| Preliminary gate of `transition_tenant_status` (section 12) | Implemented before Phase D, 2026-10-13 (merged, pull request #15) | `passes_transition_gate` in `saas_os/core/tenancy/authority.py`; `platform_caller_could_hold_any` in `saas_os/core/platform_authority/authorization.py` |
| The four remaining oversight reads (`user.read`, `operator.read`, `audit.read`, `feature_flag.read`) and `run_oversight_read` | Implemented, Phase D milestone 1, 2026-10-13 (not merged) | `saas_os/core/platform_authority/oversight.py`, `saas_os/core/identity/user_authority.py`, `saas_os/core/feature_flags/service.py` |
| Closed set of refusal labels that are not operations (section 5b) | Implemented before Phase D, 2026-10-13 (merged, pull request #15) | `NON_OPERATION_REFUSALS` in `saas_os/core/platform_authority/operations.py`; `tests/architecture/test_platform_refusal_labels.py` |
| Operator-login event `platform.operator.session_issued` | Implemented (see the first finding) | `record_operator_session_issued_in_transaction` |
| Call sites: `tenant_bootstrap.py`, the reference consumer | Updated | |

**Not implemented, and not part of Phase C.** No HTTP surface (Phase D). The oversight reads `user.read`, `operator.read`, `audit.read` and `feature_flag.read` were rows of the operation table only when Phase C merged; the Phase C plan names the registry and the overview. They are implemented since as the first milestone of Phase D (below). `purge_tenant` keeps its `actor_user_id` argument and its own inline transitions. Consumer documentation is Phase E.

**The gate on `deactivate_user` and `reactivate_user`.** The blocking race tests exist and pass against PostgreSQL with real locks (`tests/core/platform_authority/test_user_deactivation_race_integration.py`; case 4 is sequential, in `test_user_authority_integration.py`). Both functions are therefore exported from `saas_os.core.identity`. Neither has a route.

**The seven open questions, as answered by the implementation and its tests.**

| Question | Answer |
|---|---|
| Does the locking of section 11c hold under the six numbered race tests? | Yes for cases 1 to 4 and 6. Case 5 ends in the deadlock section 11c predicts: one transaction is aborted, both invariants hold, a retry succeeds. Case 2 is read as stated in the test module: the user's membership predates the first scan, because a membership created between the scans always aborts the deactivation |
| Does every ADR-0043-guarded mutation take its administrator lock first? | Not re-read function by function in this phase. The race tests exercise membership suspension and revocation only. Still taken from ADR-0043's text for the others |
| Is there a limit on API keys per user? | No. The revocation is one statement over the user's keys by the new index, and one evidence row per key; the cost is bounded by that user's key count, not by a constant. Stated in the function's documentation. No bound was added |
| Does `core.audit_log` accept a row for a closed tenant? | Yes: a key in a `DELETED` tenant is revoked and its per-key tenant row is written (tested). A `PURGED` tenant has no keys |
| Can `lock_open_tenant` serve as the parent-state lock in `create_tenant`? | Its lock mode can, its check cannot. `create_tenant` reads the parent `FOR SHARE` itself, because it needs the status of a closed parent for the refusal code. A transition takes the row `FOR UPDATE`, so it waits |
| Does the last-owner locking hold? | For the Phase B operations as before. For deactivation: refused for the last owner, sequentially (tested). No concurrent last-owner test involving deactivation was added |
| What happens when `move_tenant` commits between the depth read and the administrator locks? | A deadlock is possible and was forced by test (case 7). PostgreSQL aborts one transaction; nothing is left half-done; neither invariant is violated; a retry succeeds. The locking of section 11c was not changed and no hierarchy lock was added. A caller can receive a database error instead of a refusal |

**Findings from the implementation.**

- *The operator-login event is written at session issuance in Core, not in the HTTP callback.* Section 8 says the OIDC callback writes it. `issue_session` writes it in the issuing transaction instead, so every entry point is covered and the API layer imports nothing from the platform package. Same event, same content.
- *The oversight audit conflict between sections 8 and 9d is resolved by amendment (owner decision, 2026-10-13).* Section 9d placed the single row before the page read; section 8 had it record the number of entries returned, which is not known until the page is read. One immutable row cannot do both. Both sections now describe two rows: an attempt, committed in its own transaction before anything is read, and a completion, in the read transaction, carrying the count and the attempt's id. No schema change was needed: the attempt has its own action and the existing `success` outcome, and the link is the attempt row's id in the completion's metadata. A third audit writer was added, fail closed, because the existing own-transaction writer is best effort by contract.
- *Found by the final audit of Phase C; the first and third are corrected since (2026-10-13, before Phase D: sections 12 and 9d).* `transition_tenant_status` validated the edge before it authorized, so a caller with no authority could learn a tenant's existence and status; it now applies a preliminary gate. The oversight transactions carried no statement timeout; both now do. Still open: `move_tenant` accepts a `SUSPENDED` new parent, which is LOW, fails closed where it concerns authority, and is in the deferred ledger of `docs/P-ROADMAP.md`.
- *Found by the final audit of Phase C and corrected.* A registry read of a tenant id that does not exist commits both of its audit rows (the completion with `returned: 0`) before it raises, and an unauthorized caller is refused before the lookup. The edge selection of `transition_tenant_status` names every edge of the lifecycle graph and has no default: it used to judge any unmatched target as the purge operation. `move_tenant` took the administrator locks of the subtree after the authorization's row locks, against the order of section 11c; an operator moving a subtree they belong to while being deactivated could deadlock with the deactivation. The locks are now taken first, and both orderings of that race are forced by test with no transaction aborted.
- *Identity erasure and enrollment are not serialized end to end.* `erase_user_identity` checks for a non-revoked operator row under the platform-owners lock before it erases anything. Erasure spans several transactions, so the lock is not held across it: an enrollment of the same user that commits after the check and before the erasure finishes is not seen. Recorded in the deferred ledger.
- *An enrolled operator is not guaranteed to have an external identity. The implementation does not enforce that invariant (accepted as LOW for this phase by the owner, 2026-10-13).* The safeguard of section 6 guarantees one thing only: an operator row that is committed and not revoked when `erase_user_identity` makes its check causes the erasure to be refused. It does not guarantee that every non-revoked operator has an identity link, and two paths reach an operator without one. *Sequentially, with no race:* erasure deletes the user's external identities and sessions but leaves the `core.users` row in place and active, and `enroll_operator` requires only that the user exists and is active; a user who was erased can therefore be enrolled afterwards, and granted any permission. *Concurrently:* the enrollment commits after the erasure's check released the platform-owners lock and before the erasure finishes, as described in the previous item. In both cases the result is a non-revoked operator nobody can log in as. The owner predicate of section 6 does not look at the identity link either, so such an operator, if granted `platform.authority:manage`, counts as a platform owner, and the last-owner invariant can then be satisfied by an owner who cannot authenticate. Existing mitigation: both acts are deliberate and made by trusted people (erasure is an operator-run command; enrollment needs a platform owner or the bootstrap purpose), and an installation left in that state is recovered with `python -m saas_os.api.platform_bootstrap recover`. Closing it needs a decision this phase did not make: enrollment refusing a user with no external identity, which changes the enrollment contract of sections 3 and 6, together with erasure removing the identity link in the transaction of its check. No locking or contract was changed. Recorded in the deferred ledger.
- *A reason is optional for tenant lifecycle operations by an operator and required for self-service suspension.* Section 6 requires a reason for authority changes; section 12 requires one for self-service suspension. Nothing requires one for provisioning or for a lifecycle change by an operator.
- *The bootstrap command's own two audit rows remain*, next to the two Core now writes for the same creation and activation.
- *`revoke_api_key` locks the key row before the caller's user row*, the opposite of the order deactivation uses. A user revoking their own key while being deactivated can deadlock; PostgreSQL aborts one. Pre-existing order, not changed. `rotate_api_key` was changed to lock the owner's row first.
- *Every lifecycle change now writes platform audit rows that reference the tenant.* A tenant row can no longer be deleted without deleting those first, which only a privileged role can do. No Core function deletes a tenant row; the effect is on test teardown and on operators working by SQL.

**Phase D, milestone 1: the remaining oversight reads are implemented (2026-10-13; not merged).** Phase D was authorized by the repository owner on 2026-10-13 together with Phases E and F. Its routes need a Core function for every row of the route table in section 7, and four oversight operations had none. This milestone adds them, in Core only: there is still no route.

| Read | Permission | Where | Returns |
|---|---|---|---|
| `resolve_user` | `platform.user:read` | `saas_os/core/identity/user_authority.py` | The projection of section 4, by user id or by `(issuer, subject)`: `id`, `is_active`, `created_at`, whether the user has a non-revoked operator row, the live-session count (exact to 50, then "more than 50"), and the 50 most recent sessions (`id`, `created_at`, `expires_at`, `revoked_at`) |
| `list_platform_operators`, `list_platform_grants` | `platform.operator:read` | `saas_os/core/platform_authority/oversight.py` | Operator rows and grant rows, revoked ones included; grants optionally of one operator |
| `list_platform_audit` | `platform.audit:read` | same module | Rows of `core.platform_audit_log`, as stored; filterable by time (`since`, `until`), actor, action and target tenant (section 8) |
| `read_flag_catalog` | `platform.feature_flag:read` | `saas_os/core/feature_flags/service.py` | Flag `key` and `enabled_by_default` |
| `read_tenant_flag_overrides` | `platform.feature_flag:read` | same module | For one named tenant, flag `key` and `enabled`; the one read here that enters a tenant scope |

All six run through one function, `run_oversight_read` in `saas_os/core/platform_authority/oversight.py`, which is the path of section 9d written once: the attempt row committed in a transaction of its own, the second authorization, the bounded query, the completion row, and the statement timeout on both transactions. An architecture test requires each of them to call it and to open no transaction of its own. Pages are by keyset, default 50, maximum 200; a larger request is rejected. The key is the primary key, except for the two flag reads, which page on the flag key: a key is part of their projection, a row id is not. The registry read and the commercial overview, which predate that function, are unchanged and share its timeout wrapper; the timeout's setting and wrapper moved from `saas_os.core.tenancy` into `saas_os.core.platform_authority`, which owns two of the new reads and may not import the tenancy package. `saas_os/api/platform.py` therefore imports one name from the package, to validate that setting at startup; it calls no platform operation.

What these reads do not do, each by decision of section 4 or of this milestone:

- *An unknown user* is reported only after both audit rows are committed, the completion with `returned: 0`; a lookup by external identity that finds nothing raises an error that does not repeat the issuer or the subject, and neither audit row ever holds them. The completion row names the user that was found.
- *An unknown tenant* in `read_tenant_flag_overrides` follows the failure table of section 9d: both rows are committed, the completion with `returned: 0` and no `target_tenant_id`, and then `TenantNotFoundError` is raised. A holder of `platform.feature_flag:read` can therefore learn whether a tenant id exists, with evidence of every such call; a caller without the permission is refused before the lookup. For a tenant that exists the completion row carries `target_tenant_id`.
- *The platform audit page* is ordered by primary key within the filtered set, which is not chronological (section 9d fixes the keyset); a reader sorts by `created_at`. The table has no index besides its primary key, so a filtered read examines rows in key order until the page is full and is bounded by the statement timeout, not by an index (in the deferred ledger). The attempt row of the call that reads a page can appear on that page, and a reader paging through several pages gives `until` so that rows written meanwhile do not move across the cursor.
- *A grant list* is of grants, not of operators with their grants nested: the history of one operator's grants is unbounded, and every read here is one bounded query.

**Residual concurrency risks (deadlock cases 5 and 7). Unresolved; the locking is unchanged (owner decision, 2026-10-13).** PostgreSQL aborting one transaction is the reason these fail closed. It is not a resolution, and neither case is closed.

| | Case 5: inherited authority | Case 7: a move during the scan |
|---|---|---|
| Transactions | `deactivate_user(U)` and a guarded mutation U runs in tenant M by authority inherited from an ancestor (a SUBTREE role), where the mutation affects a user who is an active member of a descendant D of M in which U is also an active member | `deactivate_user(U)`, where U is an active member of tenants A and B, and a guarded mutation at B that reaches A as a descendant, after a `move_tenant` placed A beneath B |
| Lock sequences | Deactivation: platform lock, administrator locks of U's tenants (D among them), then U's user row exclusively. Mutation: administrator lock of M, U's user row `FOR SHARE` (its authorization), then the administrator lock of D | Deactivation: reads the depths of A and B, locks A, then B. Mutation: locks B, then its descendant A |
| First incompatible acquisition | The mutation takes a row lock between two administrator locks. ADR-0043 fixes that order for every guarded mutation: its own tenant, then the caller's authorization, then the descendants | The deactivation orders its administrator locks by depths it read before a move committed, so its order disagrees with the tree as it now is |
| Reachable by ordinary operations | Yes, narrowly. It needs a user who administers by inheritance and is a plain member further down, running a guarded mutation there in the same instant an operator deactivates that user | Yes, more narrowly. It needs three operations in one window: a deactivation between its depth read and its locks, a move of one of the user's tenants beneath another, and a guarded mutation at the new ancestor |
| State after the abort | One transaction is rolled back whole. Either the user is still active with every session and key live and no `success` row, or the membership change did not happen. In both, every tenant keeps an administrator and the installation keeps an owner | The same |
| What the caller sees | A database error (`OperationalError`, deadlock detected), not a refusal. An aborted deactivation records one `failure` row; an aborted membership mutation records nothing | The same |
| Recovery | The caller repeats the call. Forced by test: the repeat succeeds, and exactly one `success` row exists afterwards | The same |

*Is a bounded automatic retry safe without changing the lock order?* For the deactivation, yes as far as correctness goes: the aborted transaction leaves nothing behind, every success row is written inside the transaction that succeeds, and the function already retries the whole transaction for a membership that appears during its scan. A retry would add one `failure` row per aborted attempt unless that recording moved outside the loop. It is not implemented, because nothing in ADR-0031, ADR-0043 or this ADR defines a retry on a database deadlock, and adding one is a behaviour of the operation that needs a decision. For the guarded mutation the same holds, in a function Phase C does not own.

*What would eliminate each cycle.* Case 5: every guarded mutation would take the administrator locks of the descendants it reaches before it authorizes its caller, which changes the order ADR-0043 fixes for some ten functions. Case 7: the deactivation would hold the existing hierarchy-wide lock from before its depth read to its commit, which blocks every tenant creation beneath a parent and every move for the length of two registry scans; or it would re-read the depths under its locks and abort when they changed, which shortens the window and does not close it. Each is a locking decision for the owner.

**Validation.** Before the merge, locally, against PostgreSQL 16 and Redis 7 in disposable containers: the full integration suite; the default test suite and the secrets gate on a clean checkout of the merged commit's tree; the migration, packaging and Docker gates; Ruff, Pyright and import-linter; the dependency audits. On pull request #13, the repository's CI (Linux) passed all seven checks on commit `e2ee872af6e39dc00271fdbd7c8ec425513f52a2`. Results are in the Phase C implementation report and the pull request, not restated here.

## Implementation plan (each phase needs its own authorization)

Phases B to F are the accepted plan. Acceptance of this ADR does not start any of them. Phase B was authorized separately and is implemented and merged; Phase C was authorized separately on 2026-10-12 and is implemented and merged ("Implementation status"). Phases D, E and F were authorized together by the repository owner on 2026-10-13; Phase D is in progress.

### Phase B — Platform authority: grants, provisioning, recovery, last owner
- **Schema.** One additive migration: `core.platform_operators`, `core.platform_grants`, `core.platform_audit_log`. Because default privileges grant the application role full DML on new `core` tables, the migration revokes `DELETE` on the first two and `UPDATE, DELETE` on the third, and enables and forces the exclusion policy (D1) on all three. Backwards compatible; no existing table is touched. Entries in the isolation and retention registries.
- **Code.** `saas_os/core/platform_authority/` (permissions, models, `platform_can`, `authorize_platform_caller`, operator and grant operations, last-owner guard, audit); `SystemAuthority.PLATFORM_BOOTSTRAP`; `saas_os/api/platform_bootstrap.py`.
- **Depends on.** Acceptance of this ADR (given 2026-10-12) and a separate authorization of Phase B (not given).
- **Tests (PostgreSQL).** Bootstrap: first run, identical rerun, refusal when an operator exists, production gate, failure before the grant leaves no authority. Grants: self-grant refused, anti-amplification, inactive subject refused, suspended or revoked operator has no authority. Races with real row locks, both orderings: revoke against a platform mutation, suspend against a mutation, deactivation against a mutation. Last owner: sequential refusal, two owners revoking each other concurrently, suspension of the last owner. Audit atomicity: a forced failure after the change leaves neither change nor row. Migration upgrade and downgrade. The full concurrency table of section 6, including the deadlock and `denied`-row cases. Privileges: as the application role, `DELETE` on each platform table and `UPDATE` on the audit table are rejected by PostgreSQL. Exclusion policy: with a tenant bound, with a non-UUID value set, with the variable cleared and with it never set, each platform table behaves as the table in section 9b states; inside `tenant_session_scope`, a select on each platform table returns nothing and an insert is rejected; a `FOR SHARE` lock taken before a bind block is still held after it. System authority: every purpose against every platform operation, asserting the matrix of section 5a cell by cell; `SystemCaller(PLATFORM_BOOTSTRAP)` against revocation is refused; `SystemCaller(PROVISIONING)` against every operator and grant operation is refused. History: revoke then re-grant leaves two rows; re-enrollment creates a new operator row with no grants.
- **Negative controls.** With `platform_can` forced to `True`, the denial tests fail. With the advisory lock removed, the concurrent last-owner test ends with no owner in some runs. With the guard's verification removed, the last owner is revoked. With authorization moved before the lock, two owners revoke each other. With one extra purpose added to an operation's row in the operation table, the matrix test fails. With the `REVOKE` removed from the migration, the privilege test fails. With the D1 policy dropped, the tenant-bound read test returns rows.
- **Architecture tests.** `saas_os.core.rbac` does not import the platform module; platform permissions never appear in `core.permissions`; the import-based `SystemCaller` site guard; no module under `saas_os/api` other than the two command modules imports `SystemCaller` or `SystemAuthority`; only `saas_os.core.platform_authority` imports the platform models; only its audit function constructs a platform audit row; every platform operation takes a required keyword-only `caller` and appears in the operation table.
- **Acceptance.** All of the above pass; `can()` and every existing test are unchanged; no HTTP route exists.

### Phase C — Core enforcement of existing gaps
- **Code.** Callers and same-transaction evidence on `create_tenant`, `move_tenant`, `transition_tenant_status`; `tenant:suspend` self-service rule and its support exclusion; `deactivate_user`, `reactivate_user`, `revoke_user_sessions`, `revoke_user_api_keys`; the scan-ceiling setting; the parent rule in `create_tenant`; feature-flag authorization; the tenant-registry and commercial-overview reads; operator-login event in the OIDC callback; updates to `tenant_bootstrap.py`, the reference consumer and the scaffold call sites.
- **Schema.** One additive index, `core.api_keys (user_id) WHERE user_id IS NOT NULL`. Nothing else.
- **Depends on.** Phase B. Not on the API-key authentication track (section 11d).
- **Blocking acceptance criterion.** `deactivate_user` and `reactivate_user` are not exported from Core and have no route until the blocking race tests pass against PostgreSQL: the six numbered below and the seventh required by "Open questions for Phase C". If they cannot be made to pass with the primitives described, the two operations are withdrawn from the phase and reported; session and key revocation remain.
- **Tests (PostgreSQL and Redis).** Every lifecycle function: no caller, wrong caller type, user without the permission, tenant administrator, service account, each system purpose against each transition. Dual evidence present and atomic. Self-suspension: member without the permission, delegate, support grantee, ancestor administrator, service account, platform tenant, descendant left without an administrator; cannot self-reactivate. Deactivation: sessions refused on the next request, API key refused, both invariants, self-deactivation refused; reactivation leaves every earlier session refused, including one inserted by a login racing the deactivation; a user-owned API key is refused after deactivation and still refused after reactivation; a key created or rotated concurrently with the deactivation, in both orderings, is refused afterwards; rotation of an inactive owner's key is refused; each revoked key has an `api_key.revoke` row in its own tenant's audit; `revoke_user_sessions` succeeds for a last owner and a last tenant administrator. **Blocking for `deactivate_user`** (section 11c; a seventh test, for a tenant move during the scan, is required by "Open questions for Phase C"), each forced with barriers on two or three connections: (1) U made member and administrator of a new tenant and that tenant's other administrator removed, between the two scans: the deactivation aborts and retries, and the tenant keeps an administrator; (2) the same, with the removal starting after the exclusive lock on U: the removal is refused; (3) a guarded removal holding `FOR SHARE` on U when the deactivation reaches step 5: the deactivation waits and then finds the tenant; (4) U sole administrator of a tenant in S1: refused; (5) the inherited-authority deadlock: one transaction is aborted, both invariants hold, a retry succeeds; (6) a login and a key creation racing the deactivation in both orderings. Scan ceiling: registry at the ceiling (proceeds) and one above (refused, user still active, no credential revoked, one `denied` row); tenants created between the two scans so that the second passes the ceiling (refused, rolled back); the setting unset, at 0, negative and non-numeric; a caller without the permission causes no scan. API-key revocation: a holder of only `platform.api_key:revoke` succeeds and can neither deactivate, revoke sessions nor read a user; holders of `platform.session:revoke` or `platform.user:deactivate` alone are refused; a service account, a tenant administrator and every system purpose are refused; keys in two tenants are both revoked and each tenant's audit has its rows; a service account's keys are untouched; the result and the platform row carry no key id or tenant id; a forced failure after the update leaves every key live; a key created concurrently, in both orderings; a last tenant administrator's keys can be revoked. Parent rule: a tenant administrator of the parent, with every tenant permission, with SUBTREE scope, as a delegate and as a support grantee, is refused beneath an `ACTIVE` parent; a provisioning caller against a root, a `PENDING` parent, an `ACTIVE` parent, a `SUSPENDED` parent and a closed parent; an operator against each; a parent activated between the caller's request and the locked read; a provisioning caller against `move_tenant`. Provisioning: `SystemCaller(PROVISIONING)` against suspend, reactivate, delete, purging, purged, move, deactivation, session revocation and flag override is refused; `PENDING → ACTIVE` presented against a tenant that is actually `SUSPENDED` is refused. Oversight: a request above a page maximum is rejected; a failure in the middle of a page returns nothing and leaves no tenant bound on the connection; neither audit row holds a returned value or an issuer or subject; a suspended tenant is readable; a support grant changes nothing in the projection. Overview: returns only the projection fields; a tenant's rows never appear in another tenant's entry; page cap; an attempt row and a completion row per call. Purge is still unreachable from `saas_os.api`.
- **Negative controls.** Remove the authorization call from one lifecycle function and its denial test fails; remove the per-tenant scope binding from the overview and the isolation test fails; remove the session revocation from `reactivate_user` and the racing-login test fails; remove the second scan from `deactivate_user`, or take the exclusive user lock after it, and race test (1) leaves a tenant with no administrator; remove the key revocation and the reactivation test finds a working key; remove the parent-status check and the provisioning-under-active-parent test succeeds; make the scan stop at the ceiling instead of refusing and the over-ceiling test deactivates a user; drop the exclusive user lock from `revoke_user_api_keys` and the concurrent-creation test leaves a live key; remove the attempt writer from an oversight read and its completion points at no attempt; remove the completion insert and the read returns data with only an attempt row; remove `attempt_id` from the completion and the two rows cannot be paired (amended 2026-10-13).
- **Acceptance.** No Core function that changes tenant lifecycle, flags or user state accepts a call without a caller; the full repository suite passes.

### Phase D — Opt-in platform-admin routing
- **Code.** `platform_permission` policy kind and `require_platform_permission`; `saas_os/api/platform_admin/`; the `PLATFORM_ADMIN_HTTP_ENABLED` startup check; the fresh-session rule; the opt-in tenant self-suspension route.
- **Depends on.** Phases B and C.
- **Tests.** For every route: no credential (401), ordinary user (404), tenant administrator (404), administrator of the platform tenant (404), operator without the permission (403), suspended operator, revoked operator, operator with only that permission (success). Cookie-authenticated mutation from another origin (403). Session older than 900 seconds on an authority-changing route (401, audited), one second inside the limit (success), and the same old session on a non-authority platform route (success); the setting at 901 and at 59 stops startup; a state-changing `platform.authority:manage` route without `fresh_session=True` stops startup. Router mounted without the setting: startup fails. Default application and scaffold: zero platform routes. Route set and one-permission-per-route pinned by a unit test. No route exists for purge, erasure, move, delete, bootstrap, recovery, migrations or backup.
- **Negative control.** Swap one route's permission for another and the pinned contract test and the denial matrix both fail.
- **Acceptance.** As above, plus the existing capability-router and route-policy tests unchanged.

### Phase E — Consumer contract and documentation
- **Docs.** `docs/CONSUMER-GUIDE.md` (enabling the router, building a product-owned dashboard on it, the warning about a single root tenant); `docs/SECURITY.md` and `docs/RUNBOOKS.md` (tier 0, bootstrap, recovery, incident response, database cloning; correcting the stale audit action names and the statements that logins are audited and that all audit is same-transaction); `docs/MULTI-TENANCY.md` section 5; `docs/API-ARCHITECTURE.md`; no ADR amendment remains for this phase (the amendments to ADR-0002, ADR-0022, ADR-0030, ADR-0031, ADR-0040 and ADR-0043 were all written on 2026-10-12).
- **Code.** A reference-consumer scenario that enrolls an operator and exercises one oversight read and one lifecycle operation. The scaffold mounts nothing.
- **No frontend.**
- **Acceptance.** The reference-consumer and scaffold integration tests pass; the guide's examples name real symbols (the existing test pattern).

### Phase F — Verification and closure audit
- **Cross-deployment isolation.** Two disposable databases. An operator enrolled in the first has no authority in the second; a session issued by the first does not authenticate in the second; the same `(issuer, subject)` logging in to the second is an ordinary user.
- **Full validation**, run and reported, not assumed: pytest including the integration suites against PostgreSQL and Redis, Ruff, formatter, Pyright, import-linter, the RLS coverage sweep, migration checks, the secrets gate against the existing baseline.
- **Closure audit.** Re-run the capability audit against the new head and list what remains open.

### Dependencies between tracks

Invitation acceptance (G2), API-key request authentication (G3) and the inbound billing webhook (G4) do not depend on this design and are not part of it. One dependency runs the other way: a machine platform principal would need G3 first.

## Explicitly not part of this decision (deferred)

| Item | Why deferred | Owner |
|---|---|---|
| Reading tenant audit trails across tenants | Close to customer data; needs its own scope and field decision | Separate decision |
| Listing a user's tenants for an operator | No cross-tenant lookup exists; a disclosure decision | Separate decision |
| Subscription period end in the commercial overview | Not stored; needs a provider call or a schema change | Billing |
| A global user-to-tenant membership index | Would make `deactivate_user` cheap and exact, and would be a cross-tenant map of who belongs where | Separate decision; the scan ceiling (R1) is what stands in its place |
| Actual re-authentication for authority changes (`prompt=login`, `max_age`, `auth_time`) | Depends on an identity-provider claim; D2 measures only SaaS OS session age | Separate decision |
| A tenant-scoped permission for creating a child beneath an active tenant | Ruling R3 excludes it from the initial release; no accepted ADR assigns that authority | Separate decision, if product demand reopens it |
| Reporting a user's API-key count, or revoking a single chosen key | Either needs a projection of key data to operators | Separate decision |
| A second database role for platform tables | Would make the separation a database boundary instead of defence in depth; needs a second connection pool and changes ADR-0002's single-role model | Separate decision, only if D1's defence in depth is judged insufficient |
| Tamper-evident platform audit (hash chain or external sink) | Not required by the constraints | Later |
| Narrowing what `PROVISIONING` reaches in existing tenants | Pre-existing ADR-0031 behaviour, outside this ADR | Separate decision |
| Support access over HTTP | The tenant route chain requires direct membership of the path tenant (`saas_os/api/dependencies.py::get_tenant_context`), so a support grantee is answered `404` on every shipped route although `can()` would allow them. Admitting them changes existing route behaviour and needs a ruling, routes for request, approve and revoke, and evidence of each support read | Separate decision; constraint 4 is not fully usable over HTTP until it is made |
| Control Plane approver authorization | `saas_os/control_plane/approvals/service.py::approve` checks only that the approver is not the proposer. This is a tenant-scoped gap, not a platform one, and is not fixed by anything here | Control Plane hardening |
| Packaged operator commands for purge, erasure, move and delete | A layering decision: where a command that may import the erasure module lives | Separate decision |
| Trigger-based immutability for the audit tables | Should be decided for `core.audit_log` and the new table together | Separate decision |
| Multi-factor or recent-authentication claims for operators | Makes authorization depend on an identity-provider claim | Separate decision |
| Expiring or removing the ZITADEL bootstrap `IAM_OWNER` token | Deployment configuration change | Separate decision |
| A deployment identifier checked against grants, to make a cloned database inert | Adds a concept; the runbook covers the case first | Reconsider after Phase F |
| Two-person approval for authority changes | Not required by the constraints; the model leaves room for it | Later |
| Machine platform principals | Depends on G3 | After the G3 decision |
| Metrics, dead-letter administration, runtime configuration | Not ownership questions | Infrastructure |
| Retiring the legacy unauthenticated billing paths and `trusted_system()` | Billing work already deferred by ADR-0031 | Billing |

## What Would Be Difficult to Change Later

- **The permission names.** Deployments will hold grant rows containing them, and products will build dashboards around them. Renaming one is a data migration in every deployment.
- **The definition of a platform owner.** Tightening it (two owners required) would start refusing operations that work; loosening it reopens lockout.
- **Disjoint vocabularies.** Once a platform permission may be placed on a tenant role, or `can()` may consult a platform grant, the separation that constraint 2 asks for cannot be restored without auditing every grant in every deployment.
- **The `/v1/platform` response shapes**, from the moment a product's dashboard calls them.
- **What the oversight projections return.** Adding a field is easy and is how data minimization erodes; each addition should be reviewed as a disclosure decision.
- **Deactivation revoking sessions.** Reverting to ADR-0031's original contract after operators rely on it would silently restore access.
- **The tenant-context exclusion policy (D1).** Removing it later silently removes a database guarantee that tests and reviewers will have come to assume.
- **The parent rule (D5).** Products will shape their provisioning around which parents a provisioning caller may use; loosening it later is easy, tightening it breaks them.
- **Permanent key revocation on deactivation (D7).** Reverting it would restore credentials.
- **The page maxima and the freshness window**, once a product's dashboard and operators' habits are built around them.

## Related

ADR-0002 (isolation model; the audited cross-tenant path); ADR-0005 (identity provides authentication, not authority); ADR-0015 and ADR-0016 (one database per deployment; SaaS OS's own migration history); ADR-0017 (application composition); ADR-0022 (tenant-session boundary allowlist); ADR-0029 (`PLATFORM_TENANT_ID` grants nothing); ADR-0030 (route policy; isolation registry); ADR-0031 (typed callers, same-transaction evidence, decision locks, `User.is_active`); ADR-0040 (opt-in routers; gap G1); ADR-0042 (product-owned frontend); ADR-0043 (last tenant administrator; the advisory-lock pattern); ADR-0044 (same-origin check); `docs/MULTI-TENANCY.md` section 5; `docs/architecture/HTTP-CAPABILITY-MATRIX.md`; `saas_os/core/authority/caller.py`; `saas_os/core/rbac/authorization.py`; `saas_os/core/tenancy/service.py`; `saas_os/core/feature_flags/service.py`; `saas_os/core/identity/sessions.py`; `saas_os/api/route_policy.py`; `saas_os/api/dependencies.py`; `saas_os/api/tenant_bootstrap.py`.
