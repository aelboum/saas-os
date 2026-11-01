# Permission grant migrations: implementation and migration design

**Status: design for separate review, 2026-11-01. Nothing is implemented and no migration exists.** Prepared on `main` `6fd2dfd`. It turns the owner's decisions on the permission-upgrade ADR (proposed as ADR 0060 in pull request #187) into a concrete design for review. The schema changes below need their own approval before any code is written.

## 1. Decisions this design implements (owner, 2026-11-01)

| Question | Decision |
|---|---|
| Option | **C**: append-only permission grant migrations with a per-tenant ledger |
| Who may run them (Q2) | **A named platform operator holding a dedicated platform permission** |
| Suspended tenants (Q3) | **May receive grants** |
| Narrowing `PROVISIONING` (Q4) | **Deferred** until the consumer inventory is complete |

Principles carried over from the owner's direction: no automatic privilege escalation; never overwrite a tenant administrator's decision; never change a deny grant; idempotent; the grant and its audit evidence commit together; tenant isolation preserved; no generic system-permission workaround.

## 2. Model

### 2.1 Declaration (product code)

A product declares an ordered, append-only list:

```python
PermissionGrantMigration(
    id="2026-11-reports",           # stable, unique per product namespace, never reused
    namespace="crm_app",            # the product's own namespace
    role_name="admin",              # a role name the product created at provisioning
    permissions=(("report", "read"), ("report", "export")),
    reason="Reports module, release 4.2",
)
```

Rules checked when the list is loaded, before any database work: ids unique; every permission registered (`core.permissions`); no permission on an authority resource (`is_authority_changing()` in `saas_os/core/rbac/authorization.py`: roles, role permissions, memberships, membership roles, delegations, deny grants, service accounts and their roles, API keys, invitations, support access, billing mutations, tenant self-suspension); a declared migration is never edited (a content digest of each id is recorded, and a changed digest for an applied id is refused).

### 2.2 Application (per tenant)

For each tenant in scope, in its own transaction, under `bind_tenant_scope` and the existing per-tenant advisory lock (`acquire_tenant_advisory_lock`):

1. `lock_open_tenant()`; a tenant that is not open (deleted, purging, purged) is reported `tenant_closed` and skipped. `PENDING`, `ACTIVE` **and `SUSPENDED`** tenants are in scope (decision Q3). A suspended tenant's memberships authorize nothing (`saas_os/core/rbac/authorization.py`, the accessibility check under the share lock), so the grant confers nothing until reactivation, and excluding it would strand the tenant afterwards: no member could grant a permission nobody holds.
2. If the ledger already has `(tenant, namespace, migration id)`: report `already_applied`; **do nothing else**. A permission a tenant administrator revoked after the first application stays revoked.
3. Find the role by name. Absent: `role_missing`, recorded in the ledger, nothing created.
4. For each permission: present on the role already: `already_present`; otherwise insert into `core.role_permissions` (the existing composite foreign key keeps the role in the tenant).
5. Write one tenant audit row per inserted grant (`role_permission.create`, metadata: migration id, namespace) and one ledger row, then commit. Any failure rolls back the whole tenant: no grant without its audit row and ledger row, no ledger row without its grants.

Nothing in the procedure removes a grant, creates or renames a role, assigns a role, adds a membership, or reads or writes a deny grant or delegation. A deny grant keeps winning in `can()`, unchanged.

### 2.3 Authority

- **Platform operation** `permission_grant.apply`, **platform permission** `platform.permission_grant:apply` (a new member of ADR-0045's closed vocabulary; decision Q2).
- The Core function takes a `UserCaller` (the operator) and runs `authorize_platform_caller()` in the same transaction as the work, exactly as `replay_dead_lettered_events()` does (`saas_os/core/outbox/replay.py`): a person only, no system purpose.
- Inside each tenant, the grant itself is made by a new **`SystemAuthority.PERMISSION_UPGRADE`**, accepted by one Core function only (`grant_registered_permission_to_role()`), and never by `grant_permission()`, `create_role()`, `assign_role()` or any other function. It is not `PROVISIONING`, which keeps its current reach until the deferred narrowing (Q4).
- **Command:** `saas-os-operator apply-permission-grants --operator <id> --namespace <ns> --module <python module exposing the list> [--tenant <id> | --all-tenants] [--apply] --reason <text>`, dry run unless `--apply`, with the existing `--confirm-production` guard.

### 2.4 Evidence

| Where | What |
|---|---|
| Tenant audit (`core.audit_log`) | One `role_permission.create` per inserted grant, actor the system purpose with the operator and the migration id in metadata (and, once ADR 0061 is implemented, a `maintenance` system actor naming the migration); one `permission_grant_migration.apply` row per tenant with the outcome counts |
| Platform audit (`core.platform_audit_log`) | One row per run: operator, reason, namespace, migration ids, tenant counts by outcome; never a tenant's role or permission names |
| Ledger | One row per `(tenant, namespace, migration id)` with outcome and time |
| A refusal | One `denied` platform row after the rollback, as for the other platform operations |

## 3. Schema changes (need separate approval)

Two additive migrations, hand-written, following `b3d5f7a9c2e4_add_outbox_replay_permission.py`:

1. **Widen `ck_platform_grants_permission`** on `core.platform_grants` by one permission (`platform.permission_grant:apply`). Accepts every existing row; brief `ACCESS EXCLUSIVE` lock on `core.platform_grants` for the CHECK swap; downgrade restores the previous CHECK and fails by design while a grant of the new permission exists. (If the webhook-secret re-encryption permission of the F7 work is approved first, the counts shift by one; the migrations must be ordered.)
2. **Create `core.permission_grant_applications`** (tenant-owned):

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | primary key |
| `tenant_id` | uuid | not null, foreign key to `core.tenants`, RLS column |
| `namespace` | varchar(100) | not null |
| `migration_id` | varchar(100) | not null |
| `content_digest` | char(64) | SHA-256 of the declaration |
| `outcome` | varchar(32) | `applied`, `role_missing` |
| `grants_added` | integer | not null, at least 0 |
| `applied_at` | timestamptz | not null |
| `applied_by_platform_audit_id` | uuid | the run's platform audit row |

Unique `(tenant_id, namespace, migration_id)`. Forced RLS with the canonical policy; registered `TENANT_OWNED` in the isolation registry; deleted with the tenant (purge). The application role gets `SELECT, INSERT` only: the application never updates or deletes a ledger row.

Data safety: a new empty table and a widened CHECK; no existing row changes; no backfill. Upgrade order: SaaS OS migrations, then the product's (ADR-0016). Downgrade: drop the table (the grants it recorded stay; only their history is lost), then restore the CHECK.

## 4. Existing permission inventory (before an installation's first run)

Permissions are not a fixed list in SaaS OS: Core and products register them at run time into the global `core.permissions` (`register_permission()`; `authorize_caller()` also registers what it checks). What exists therefore differs per installation. Before the first run, the installation's operator runs a read-only inventory, as the migration role, of:

- every row of `core.permissions` (resource, action);
- per role name, how many tenants hold the role, and for each declared migration's permissions, how many of those roles already hold them (the expected `already_present` count);
- tenants by status (`PENDING`, `ACTIVE`, `SUSPENDED`, closed).

The command's dry run produces the same counts per tenant without writing; the inventory exists so the result can be checked independently. The only permission Core itself grants at provisioning is `("tenant", "read_status")` (`FIRST_TENANT_OWNER_PERMISSIONS`, `saas_os/api/tenant_bootstrap.py`); every other grant in an installation was made by its product or by its tenants' administrators.

## 5. Existing consumers

- The first consumer grants new permissions to existing tenants with its own operator command, `crm_app.role_upgrade`, using `SystemCaller(PROVISIONING)` (its decision P2-G7). It keeps working: nothing here narrows `PROVISIONING` (Q4 deferred).
- To move, the consumer declares its past upgrades as grant migrations and runs the dry run: grants its own command already made come back `already_present`, so the first application records them in the ledger without duplicating anything. From then on it uses only the new command. This needs a separately approved pin move in the consumer.
- No other consumer is known. The inventory Q4 waits for: a search of each consumer repository for `SystemAuthority.PROVISIONING` used outside tenant creation, plus a deprecation warning (naming the calling module) added in the release that ships this feature and observed for one release cycle.

## 6. Rollback and recovery

| Situation | Effect | Recovery |
|---|---|---|
| A run fails in one tenant | That tenant's transaction rolls back completely; others are unaffected; the summary names it | Fix the cause, re-run: applied tenants report `already_applied` |
| The process stops mid-run | Committed tenants are complete; the rest untouched | Re-run |
| A migration granted something by mistake | Grants exist with audit rows naming the migration | A tenant administrator revokes it per tenant; a later "revoke" migration kind, limited to grants the ledger attributes to a migration, is a separate design |
| Code rollback to a release without the feature | Grants and ledger stay; nothing reads the ledger | None needed |
| Schema downgrade | Ledger dropped, grants stay | Re-applying later finds the grants `already_present` |

## 7. Tests required by the implementation

- **Isolation:** given tenant A, the function never reads or writes tenant B's roles, grants or ledger rows (two tenants with the same role name, different grants); the RLS coverage sweep includes the new table; an untenanted session sees no ledger rows.
- **Authority:** an operator without `platform.permission_grant:apply` is refused with a `denied` platform row; a plain user, a service account and every other `SystemAuthority` are refused; `PERMISSION_UPGRADE` is refused by `grant_permission()`, `create_role()`, `assign_role()`, `add_tenant_membership()` and every authority-resource function (a test over the public mutating functions); a user still cannot grant a permission they do not hold.
- **Refusals with no partial write:** unregistered permission, authority-resource permission, changed declaration digest, closed tenant.
- **Idempotency:** a second run changes nothing; a revoked grant is not restored; an existing grant is `already_present`.
- **Suspended tenant:** receives the grant; its members still cannot use it until reactivation.
- **Atomicity:** an injected audit failure leaves no grant and no ledger row (negative control: committing before the audit makes the test fail).
- **Concurrency:** two runs on one tenant apply once (advisory lock; a forced race in the style of `tests/core/rbac/test_authorization_transaction_race_integration.py`).
- **Migrations:** upgrade and downgrade tests for both migrations, including the refused downgrade while a grant of the new platform permission exists.

## 8. Not decided here

- The "revoke" migration kind.
- The schedule for narrowing `PROVISIONING` (deferred, Q4).
