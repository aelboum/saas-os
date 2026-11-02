# Permission grant migrations: implementation and migration design

**Status: decided design, implemented by pull request #198 (`feat/permission-grant-migrations`, still open, not merged). Updated 2026-11-02.** First written 2026-11-01 on `main` `6fd2dfd` as a design for separate review, before any code existed. It turns the owner's decisions on the permission-upgrade ADR (proposed as ADR 0060 in pull request #187) into a concrete design. This revision records the owner's later decisions (A: ledger retention, 2026-11-01; B: the grant's audit action; the retention period, 2026-11-02) and aligns the procedure, evidence and schema sections with the implementation in #198. Where the first version said something different, the text below says so and labels the earlier statement historical.

## 1. Decisions this design implements

| Question | Decision |
|---|---|
| Option (owner, 2026-11-01) | **C**: append-only permission grant migrations with a per-tenant ledger |
| Who may run them (Q2, 2026-11-01) | **A named platform operator holding a dedicated platform permission** |
| Suspended tenants (Q3, 2026-11-01) | **May receive grants** |
| Narrowing `PROVISIONING` (Q4, 2026-11-01) | **Deferred** until the consumer inventory is complete |
| Ledger retention (decision A, 2026-11-01) | **`SECURITY_RETAIN`**: the ledger survives a tenant purge next to the `PURGED` tombstone; tenant ids are never reused; the runtime role may only `SELECT` and `INSERT` it |
| Ledger retention period (2026-11-02) | Two years after the tenant reaches `PURGED`, extendable by a documented legal hold; deletion only through a controlled, audited operator process (section 3.3) |
| Audit action of each grant (decision B) | **`role_permission.grant`**, the action `grant_permission()` records, with the same resource and metadata plus the migration's provenance (section 2.4) |

Principles carried over from the owner's direction: no automatic privilege escalation; never overwrite a tenant administrator's decision; never change a deny grant; idempotent; the grant and its audit evidence commit together; tenant isolation preserved; no generic system-permission workaround.

## 2. Model

### 2.1 Declaration (product code)

A product declares an ordered, append-only list:

```python
PermissionGrantMigration(
    id="2026-11-reports",  # stable, unique per product namespace, never reused
    namespace="crm_app",  # the product's own namespace
    role_name="admin",  # a role name the product created at provisioning
    permissions=(("report", "read"), ("report", "export")),
    reason="Reports module, release 4.2",
)
```

Rules checked when the list is loaded, before any database work: ids unique; every permission registered (`core.permissions`); no permission on an authority resource (`is_authority_changing()` in `saas_os/core/rbac/authorization.py`: roles, role permissions, memberships, membership roles, delegations, deny grants, service accounts and their roles, API keys, invitations, support access, billing mutations, tenant self-suspension); a declared migration is never edited (a content digest of each id is recorded, and a changed digest for an applied id is refused).

### 2.2 Application (per tenant)

As implemented in `saas_os/core/permission_grants/apply.py` (#198):

1. **Declaration check**, before any database work (`validate_permission_grant_migrations`).
2. **Pre-flight transaction** (writes nothing): authorize the operator; resolve every declared permission in the global catalog (an unregistered one is refused; nothing is ever registered); list the tenants in scope (the named ones, or every tenant that is not closed); and, tenant by tenant under its RLS scope, refuse a declaration whose applied migration's digest changed.
3. **Each tenant in its own transaction**, in this order:
   1. authorize the operator again (`authorize_platform_caller`, same transaction);
   2. bind the tenant's RLS scope (`bind_tenant_scope`);
   3. `lock_open_tenant()`, which takes the tenant row `FOR SHARE`. A tenant that is not open (deleted, purging, purged) is reported `tenant_closed`, an unknown one `tenant_not_found`, and skipped. `PENDING`, `ACTIVE` **and `SUSPENDED`** tenants are in scope (decision Q3). A suspended tenant's memberships authorize nothing (`saas_os/core/rbac/authorization.py`, the accessibility check under the share lock), so the grant confers nothing until reactivation, and excluding it would strand the tenant afterwards: no member could grant a permission nobody holds;
   4. **with `--apply` only**, the tenant's advisory lock (`acquire_tenant_advisory_lock`), so concurrent runs on one tenant serialize. The order is therefore the tenant row share lock first, then the advisory lock;
   5. read the tenant's ledger for the namespace and refuse a changed digest again;
   6. for each declared migration: if the ledger already has `(tenant, namespace, migration id)`, count it `already_applied` and **do nothing else** (a permission a tenant administrator revoked after the first application stays revoked). Otherwise find the role by name; absent: `role_missing`, recorded in the ledger, nothing created. Present: for each permission the role lacks, insert it through `grant_registered_permission_to_role()` (one `role_permission.grant` tenant audit row each, written by that function in the same transaction); one it already holds is `already_present`. Then add one ledger row for the migration;
   7. if anything was applied or recorded, one `permission_grant_migration.apply` tenant audit row with the counts, then commit.

   Any failure rolls the whole tenant back: no grant without its audit row and ledger row, no ledger row without its grants. The run reports that tenant `failed` (by error type only) and goes on with the next one. A refusal of authority or a changed declaration stops the run instead.
4. **With `--apply`, one platform audit row for the run, written last**, in its own transaction after every tenant's. Its id is generated before the tenants are processed (the run id) and written into every ledger row's `applied_by_platform_audit_id`; the platform row is then inserted with that preset id. There is no foreign key between them (section 3.2).

**Dry run** (no `--apply`): the same counts are computed per tenant (a missing grant is counted as one that would be added), but nothing is written: no grant, no ledger row, no tenant audit row, no platform audit row, and no advisory lock (only the share locks of the authorization and `lock_open_tenant`). Its result has no run id. A refusal still records its `denied` platform row (section 2.4).

Nothing in the procedure removes a grant, creates or renames a role, assigns a role, adds a membership, or reads or writes a deny grant or delegation. A deny grant keeps winning in `can()`, unchanged.

*Historical (first version, 2026-11-01):* this section originally put the advisory lock before `lock_open_tenant()` and wrote the audit rows, the ledger row and the platform row without fixing their relative order. The implementation takes the share lock first and the advisory lock only when applying, and writes the platform row last with a preset id, as described above.

### 2.3 Authority

- **Platform operation** `permission_grant.apply`, **platform permission** `platform.permission_grant:apply` (a new member of ADR-0045's closed vocabulary; decision Q2). Platform audit action `platform.permission_grant.apply`.
- The Core function `apply_permission_grant_migrations()` takes a `UserCaller` (the operator) and runs `authorize_platform_caller()` in every transaction that reads or changes anything, in the same transaction as the work, exactly as `replay_dead_lettered_events()` does (`saas_os/core/outbox/replay.py`): a person only, no system purpose.
- Inside each tenant, the grant itself is made by a new **`SystemAuthority.PERMISSION_UPGRADE`**, accepted by one Core function only (`grant_registered_permission_to_role()` in `saas_os/core/rbac/service.py`), and never by `grant_permission()`, `create_role()`, `assign_role()` or any other function. That function also refuses, before any write, an unregistered permission, an authority-resource permission and a role of another tenant. It is not `PROVISIONING`, which keeps its current reach until the deferred narrowing (Q4).
- **Command:** `saas-os-operator apply-permission-grants --operator <id> --namespace <ns> --module <module[:ATTRIBUTE] holding the list> (--tenant <id> | --all-tenants) [--apply] --reason <text>`, dry run unless `--apply`; with `ENVIRONMENT=production` the CLI's existing `--confirm-production` guard applies.

### 2.4 Evidence

| Where | What |
|---|---|
| Tenant audit (`core.audit_log`), per inserted grant | One **`role_permission.grant`** row (decision B), written by `grant_registered_permission_to_role()` in the grant's transaction: resource `role` / the role id and metadata `permission_id` and `permission` (`resource:action`), exactly as `grant_permission()` records; actor the system purpose (`ActorType.SYSTEM`, so the audit service adds `system_authority` = `permission_upgrade`); plus `migration_id`, `namespace`, `operator_user_id` and `run_id` |
| Tenant audit, per changed tenant | One `permission_grant_migration.apply` row, actor the operator, resource `tenant`: namespace, run id, the applied migration ids, and the counts (migrations applied, roles missing, grants added, grants already present) |
| Platform audit (`core.platform_audit_log`) | One `platform.permission_grant.apply` row per applied run, written last, its id the run id: operator, reason, namespace (target), scope, declaration digest, migration ids (omitted above a size limit), tenant counts by outcome, grant counts; never a tenant's role or permission names. A target tenant only when exactly one tenant was named |
| Ledger | One row per `(tenant, namespace, migration id)` with digest, outcome, grants added, time and run id |
| A refusal | One `denied` platform row after the rollback (an unauthorized caller, or a declaration refused before any tenant changed), as for the other platform operations |

*Historical (first version, 2026-11-01):* the per-grant row was first proposed as `role_permission.create` with only the migration id and namespace in its metadata. Decision B replaced it with `role_permission.grant`, so a grant made by a migration reads exactly like one made by a tenant administrator, distinguished by its system actor and provenance metadata. The first version's note that ADR 0061 might later add a `maintenance` system actor is not part of this implementation.

## 3. Schema changes

Approved with the implementation; both migrations are in #198. Two additive migrations, hand-written, following `b3d5f7a9c2e4_add_outbox_replay_permission.py`.

### 3.1 Migrations

1. **`d7e2a9c4f1b6`: widen `ck_platform_grants_permission`** on `core.platform_grants` from twenty-five to twenty-six permissions with `platform.permission_grant:apply`. It is **stacked on `c5e8a1d3f7b2`** (pull request #192, `platform.webhook_secret:reencrypt`), whose twenty-five-permission list it repeats verbatim as its "before" list; #198 therefore contains #192's commits and must merge after (or with) it. Accepts every existing row; brief `ACCESS EXCLUSIVE` lock on `core.platform_grants` for the CHECK swap; downgrade restores the twenty-five-permission CHECK and fails by design while a grant of the new permission exists (revoke it first).
2. **`e8f3b1d5a2c7`: create `core.permission_grant_applications`** (revises `d7e2a9c4f1b6`).

*Historical (first version):* the ordering against the F7 webhook-secret permission was left open ("the counts shift by one; the migrations must be ordered"). It is now fixed as above.

### 3.2 The ledger table

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | primary key |
| `tenant_id` | uuid | not null, foreign key to `core.tenants` (`NO ACTION`), RLS column |
| `namespace` | varchar(100) | not null |
| `migration_id` | varchar(100) | not null |
| `content_digest` | char(64) | not null, SHA-256 of the declaration (lower-case hex, CHECK) |
| `outcome` | varchar(32) | not null, `applied` or `role_missing` (CHECK) |
| `grants_added` | integer | not null, at least 0 (CHECK) |
| `applied_at` | timestamptz | not null, default `now()` |
| `applied_by_platform_audit_id` | uuid | not null, the run's platform audit row; no foreign key, because `core.platform_audit_log` is hidden from tenant-scoped transactions and the platform row is written after the tenants' |

Unique `(tenant_id, namespace, migration_id)`. Forced RLS with the canonical tenant policy (`ENABLE` + `FORCE`); registered `TENANT_OWNED` in the isolation registry (`saas_os/core/tenancy/isolation.py`). The application role keeps `SELECT` and `INSERT` only: the migration revokes `UPDATE` and `DELETE`, so the application never rewrites or removes a ledger row.

### 3.3 Retention (decision A, 2026-11-01; period, 2026-11-02)

The ledger is classified **`SECURITY_RETAIN`** (`saas_os/core/tenancy/retention.py`). Its rows are minimal security history: which declared migration was applied to which tenant, by which run, with what digest, outcome and count; no personal data, no role, permission or tenant name, no secret. No purge step touches the table, so the rows **survive a tenant purge next to the `PURGED` tombstone**. The `NO ACTION` foreign key on `tenant_id` onto the never-deleted tombstone keeps that tenant id taken: **tenant ids are never reused**, so no later tenant can inherit these rows. The rows lend no authority: only an open tenant's ledger is consulted, and `PURGED` is terminal.

Retention policy (owner, 2026-11-02): a purged tenant's ledger rows are kept for **two years after the tenant reaches `PURGED`**. The period can be extended by a **documented legal hold**. Rows are deleted only through a **controlled, audited operator process**, never by the application (which has no `DELETE`) and never by tenant purge. The implementation of that process is in progress in #198; this design states the policy, not its mechanics.

*Historical (first version, 2026-11-01):* this section originally said the ledger is "deleted with the tenant (purge)". Decision A reversed that.

### 3.4 Data safety and ordering

A new empty table and a widened CHECK; no existing row changes; no backfill. Upgrade order: SaaS OS migrations, then the product's (ADR-0016). Downgrade: drop the table (the grants it recorded stay; only their history is lost), then restore the CHECK.

## 4. Existing permission inventory (before an installation's first run)

Permissions are not a fixed list in SaaS OS: Core and products register them at run time into the global `core.permissions` (`register_permission()`; `authorize_caller()` also registers what it checks). What exists therefore differs per installation. Before the first run, the installation's operator runs a read-only inventory, as the migration role, of:

- every row of `core.permissions` (resource, action);
- per role name, how many tenants hold the role, and for each declared migration's permissions, how many of those roles already hold them (the expected `already_present` count);
- tenants by status (`PENDING`, `ACTIVE`, `SUSPENDED`, closed).

The command's dry run produces the same counts per tenant without writing; the inventory exists so the result can be checked independently. The only permission Core itself grants at provisioning is `("tenant", "read_status")` (`FIRST_TENANT_OWNER_PERMISSIONS`, `saas_os/api/tenant_bootstrap.py`); every other grant in an installation was made by its product or by its tenants' administrators.

## 5. Existing consumers

- The first consumer grants new permissions to existing tenants with its own operator command, `crm_app.role_upgrade`, using `SystemCaller(PROVISIONING)` (its decision P2-G7). It keeps working: nothing here narrows `PROVISIONING` (Q4 deferred).
- To move, the consumer declares its past upgrades as grant migrations and runs the dry run: grants its own command already made come back `already_present`, so the first application records them in the ledger without duplicating anything. From then on it uses only the new command. This needs a separately approved pin move in the consumer.
- No other consumer is known. The inventory Q4 waits for: a search of each consumer repository for `SystemAuthority.PROVISIONING` used outside tenant creation.
- **Deferred:** the first version also promised a deprecation warning (naming the calling module) for `PROVISIONING` used outside tenant creation, "added in the release that ships this feature and observed for one release cycle". #198 does not add it. It is deferred with the rest of Q4 and needs its own change.

## 6. Rollback and recovery

| Situation | Effect | Recovery |
|---|---|---|
| A run fails in one tenant | That tenant's transaction rolls back completely; others are unaffected; the summary names it | Fix the cause, re-run: applied tenants report `already_applied` |
| The process stops mid-run | Committed tenants are complete; the rest untouched; the run's platform row is missing (it is written last), while committed ledger rows name its run id | Re-run; the tenant audit rows of the interrupted run remain the evidence for the tenants it changed |
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
- **Retention:** the ledger is classified `SECURITY_RETAIN` and survives purge; the runtime role cannot update or delete it.

The tests #198 actually contains, and their results, are in that pull request.

## 8. Not decided here

- The "revoke" migration kind.
- The schedule for narrowing `PROVISIONING` (deferred, Q4), including the deprecation warning of section 5.
