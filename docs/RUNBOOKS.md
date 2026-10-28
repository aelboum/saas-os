# Operational Runbooks

Operator procedures for a running deployment. Each section is a single,
self-contained procedure. Nothing here contains a real credential; every
value shown is a placeholder.

## First-tenant bootstrap (post-audit F-02)

Provisions the platform's first tenant and its owner without an HTTP
surface, through the existing Core services, as the restricted
application database role:

```
python -m saas_os.api.tenant_bootstrap \
    --tenant-name "Acme Ltd" \
    --owner-issuer https://<your-zitadel-instance> \
    --owner-subject <owner's OIDC subject> \
    --confirm-production
```

### 1. Prerequisites

- The production stack is up and migrated to the current head
  (`docker compose -f docker-compose.prod.yml up -d`, then the same
  `alembic upgrade head` step `scripts/check-docker-prod.sh` performs).
- `DATABASE_URL` points at the restricted `saas_os_app` role
  (`NOSUPERUSER NOBYPASSRLS`). The command runs
  `saas_os.infra.db.validate_application_role()` first and refuses to proceed
  under any other role -- the bootstrap never uses the migration/admin
  connection.
- The owner has an account at the configured identity provider
  (`OIDC_ISSUER_URL`). No password, token, or code is ever given to
  this command.

### 2. Required identity information

The platform keys a user on the OIDC `(issuer, subject)` pair
(`core.external_identities`). Obtain both from the identity provider:

- `--owner-issuer`: the exact `iss` value the provider writes into its ID
  tokens. For ZITADEL this is the instance URL (for example
  `https://acme-abc123.zitadel.cloud`), the same value as
  `OIDC_ISSUER_URL`. A trailing slash is stripped, matching
  `saas_os.core.identity.provider`.
- `--owner-subject`: the owner's `sub` claim at that issuer (ZITADEL: the
  user's numeric user ID, visible in the ZITADEL console). This is an
  identifier, not a secret, and is never logged or written to audit
  metadata by the bootstrap.

On the owner's first `/auth/login`, `saas_os/api/auth/routes.py` resolves the
same pair to the same `core.users` row the bootstrap created -- there
is exactly one identity model.

### 3. Dry run

```
python -m saas_os.api.tenant_bootstrap --tenant-name "Acme Ltd" \
    --owner-issuer https://<issuer> --owner-subject <sub> --dry-run
```

Read-only in every environment (no `--confirm-production` needed).
Validates the inputs, applies the tenant-name rule (section 8) and
prints which steps a real run would perform.

### 4. Production confirmation

When `ENVIRONMENT=production`, a real run refuses (exit 2, before any
database access) unless `--confirm-production` is passed. Development
and test environments run without it.

### 5. Bootstrap command

Run inside the `backend` container of the production project (it has
the runtime environment and the application role):

```
docker compose -f docker-compose.prod.yml exec backend \
    python -m saas_os.api.tenant_bootstrap \
        --tenant-name "Acme Ltd" \
        --owner-issuer https://<issuer> \
        --owner-subject <sub> \
        --confirm-production
```

Steps, in order -- every step before the last produces only inert
state; authority exists only after the last one:

1. tenant registry row (`pending`)
2. activation (`pending -> active`)
3. owner user row linked to `(issuer, subject)`
4. tenant-local role `owner`
5. permission grants to that role
6. owner membership
7. role assignment to the membership
8. verification through `saas_os.core.rbac.can()` for every granted permission

### 6. Expected result

Exit code 0 and a summary like:

```
first-tenant bootstrap: OK
tenant id:      2f2c...-...
tenant status:  active
owner user id:  8b6e...-...
membership id:  1a9d...-...
owner role:     owner (c41f...-...)
permissions:    tenant:read_status
performed:      tenant, activation, owner_user, owner_role, grant:tenant:read_status, owner_membership, role_assignment
```

Exit 1 means the run was refused or failed (message on stderr, exception
*type* only for unexpected errors -- never a driver message); exit 2 is
a usage or confirmation problem. No database URL or secret is printed.

### 7. Verification

- Owner login: the owner opens `https://<PUBLIC_DOMAIN>/auth/login`,
  authenticates at the provider, then
  `GET https://<PUBLIC_DOMAIN>/v1/tenants/<tenant id>/status` returns
  `200` with `"status": "active"`.
- Audit trail (from the backend container, Python):
  `saas_os.core.audit_log.list(tenant_id)` contains `tenant.bootstrap_created`,
  `tenant.activated`, `rbac.role_created`, `rbac.permission_granted`,
  `tenant.owner_membership_created`, `rbac.role_assigned`, all with
  `actor_type = system` and metadata `{"bootstrap": "first_tenant", ...}`
  carrying identifiers only.

### 8. Repeat / duplicate behaviour

Running the identical command again is a deterministic no-op: exit 0,
`performed: nothing`, the same tenant/user/membership/role ids, no second
tenant, membership, role, grant or assignment (each step is
find-or-create against the existing uniqueness constraints).

Tenant-name rule (`core.tenants.name` is a display name, not unique):

- exactly one tenant with that name, no members yet -> resumed (a crashed
  earlier run);
- exactly one tenant, this owner identity already a member -> resumed
  (no-op or completion of missing steps);
- exactly one tenant with *other* members -> refused (conflict), nothing
  changed;
- two or more tenants with that name -> refused (conflict);
- the tenant is `suspended`/`deleted` -> refused; the command never
  resurrects a tenant.

Do not run two bootstraps concurrently: the name rule is evaluated per
run, so two simultaneous first runs could each create a tenant, after
which the next run refuses on ambiguity (see section 9).

### 9. Failure recovery

A failure at any step leaves no privilege behind -- an unowned pending or
active tenant, a bare user row, or an unassigned role grant nothing
(`saas_os.core.rbac.can()` denies by default). Re-run the identical command: it
resumes and completes the missing steps. If a run reports "more than one
tenant already carries this tenant name", inspect `core.tenants`, decide
which row is canonical, move the other through the normal lifecycle
(`transition_tenant_status` to `deleted`, then `purge_tenant`), and re-run.

### 10. Identifying the resulting tenant

The summary prints the tenant id; it is also the `resource_id` of the
`tenant.bootstrap_created` audit entry and the value the owner uses in
`/v1/tenants/<tenant id>/status`.

### 11. Verifying owner permissions

The owner role holds exactly `FIRST_TENANT_OWNER_PERMISSIONS`
(`saas_os/api/tenant_bootstrap.py`) -- today `tenant:read_status`, the one
permission the external API enforces. From the backend container:

```python
from saas_os.core.rbac import can
can(actor_id=<owner user id>, tenant_id=<tenant id>, action="read_status", resource="tenant")  # True
can(actor_id=<owner user id>, tenant_id=<tenant id>, action="activate",
    resource="saas_os.control_plane.self_learning.adaptation")  # False -- no AI tool authority
```

### 12. Verifying tenant isolation

Bootstrap is ordinary tenant data: `core.tenant_memberships`,
`core.roles`, `core.role_permissions`, `core.membership_roles` remain
`FORCE ROW LEVEL SECURITY` tables, written only through
`tenant_session_scope()` by the `NOSUPERUSER NOBYPASSRLS` role. With a
second tenant bootstrapped for a different owner, the first owner's
session gets `404` from `/v1/tenants/<other tenant id>/status` (not a
member: the identical non-enumerating response), and
`saas_os.core.rbac.can()` returns `False` for every action in the other tenant.
`tests/api/test_tenant_bootstrap_integration.py` proves all of this
against a real PostgreSQL.

## Platform operators (ADR-0045)

Procedures for the people who operate a deployment. Background: `docs/SECURITY.md` section 11 and `docs/ADR/0045-installation-scoped-platform-authority.md`.

### 1. Who holds what

- **Tier-0 credentials** -- the migrations database role, the application role's database credentials and the deployment's secrets, host or orchestrator access, ZITADEL `IAM_OWNER` and the `bootstrap` machine user's token -- are held by as few people as can operate the deployment, and by nobody else. Holding one is equivalent to holding every platform and tenant authority.
- **The audit-digest log store** (ADR-0053; "Audit digests" below) is administered by people who hold none of the tier-0 database credentials. Otherwise the digests prove nothing against those holders.
- **Platform owners** hold `platform.authority:manage`. Keep at least two, held by different people. SaaS OS refuses any change that would leave none, but it does not require two.
- **Operators** hold only the permissions their work needs. A permission implies no other: someone who reads the tenant registry does not thereby read the audit, and someone who suspends tenants does not thereby deactivate users.
- **A second factor** (ADR-0049). In production the platform-admin router refuses an operator whose login used one factor (`401`, `X-Error-Code: multi_factor_required`). Before the first operator uses it:
  1. In ZITADEL, have each operator enroll an authenticator app (TOTP) or a user-verified passkey, and set the organization's login policy to require a second factor (`forceMfa`), so the login asks for it.
  2. Have the operator log in once and check the session: `SELECT multi_factor FROM core.sessions WHERE user_id = '<operator user id>' ORDER BY created_at DESC LIMIT 1` must be `true`.
  3. A security key used on its own does not count (ZITADEL reports it as `user` only).
  Refused attempts are recorded as `denied` platform audit rows with reason `multi_factor_required` on a best-effort basis. If an operator's factors change, revoke their sessions. If every operator is refused although they used a second factor, the ID tokens are not carrying `amr`: set `PLATFORM_OPERATOR_REQUIRE_MFA=false` while it is fixed, and use the recovery command for anything urgent.

### 2. First owner (once per deployment)

After migrations, and only once `OIDC_ISSUER_URL` is final, with the application role's credentials (the command refuses a superuser or `BYPASSRLS` role):

```
python -m saas_os.api.platform_bootstrap bootstrap \
    --owner-issuer https://<your-identity-provider> \
    --owner-subject <the owner's OIDC subject at that issuer> \
    --reason "initial platform owner, <ticket>"
```

- `--owner-issuer` must equal the deployment's `OIDC_ISSUER_URL`. Neither value is a secret.
- `ENVIRONMENT=production` requires `--confirm-production`.
- It refuses if any operator exists, in any status. An identical second run changes nothing and says so.
- It writes platform audit rows with actor type `system`. They cannot name the person at the keyboard, so `--reason` carries the ticket that does.
- Then enroll a second owner. Over HTTP this needs the surface enabled (section 3) and the second person to have logged in once, so that they exist as a user: find their user id with `POST /v1/platform/users/resolve`, enroll with `POST /v1/platform/operators`, and grant with one `POST /v1/platform/operators/{operator_id}/grants` per permission. In process, the same is `enroll_operator` and `grant_platform_permission`.

### 3. Enabling the HTTP surface

The platform routes are served only if the product mounts `build_platform_admin_router()` and the deployment sets `PLATFORM_ADMIN_HTTP_ENABLED=true`. Mounted without the setting, the application does not start. Settings, each validated at startup:

| Setting | Values | Default |
|---|---|---|
| `PLATFORM_ADMIN_HTTP_ENABLED` | exactly `true` or `false` | not enabled |
| `PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS` | 60 to 900 | 900 |
| `PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS` | 100 to 60000 | 5000 |
| `PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS` | 100 to 60000 | 5000 |
| `PLATFORM_DEACTIVATION_MAX_TENANTS` | 1 or more | 10000 |

Restricting `/v1/platform` to an administrative network at the edge is recommended. It is an additional layer, not the control: authorization is decided in Core for every call.

### 4. Routine changes

- **Enroll an operator, grant or revoke a permission, suspend, reactivate or revoke an operator:** an owner, over HTTP, with a session no older than `PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS` (15 minutes unless the deployment lowered it; log out and in again if the request is answered `401` with `X-Error-Code: session_not_fresh`). Every change needs a reason and is recorded.
- **Revoking an operator is terminal** and revokes its grants. Enrolling the same user again creates a new operator with no grants.
- **Only someone who can log in is enrolled.** A user linked to no external identity -- including an erased user -- is refused with `409 subject_not_linked`. Operators enrolled before 2026-10-14 were not checked; once, with read access to the database, list any operator nobody can log in as, and revoke each through an owner (if one is the last owner, enroll and grant a replacement first, or use recovery):

  ```sql
  SELECT o.id, o.user_id, o.status
  FROM core.platform_operators o
  WHERE o.status <> 'revoked'
    AND NOT EXISTS (
      SELECT 1 FROM core.external_identities e WHERE e.user_id = o.user_id
    );
  ```
- **Review** `GET /v1/platform/audit` regularly, and after every recovery. Filter by `actor_user_id`, `action`, `target_tenant_id`, `since` and `until`. `platform.operator.session_issued` rows are operator logins.

### 5. Incident response

Start in SaaS OS, not at the identity provider: disabling a user there does not end a SaaS OS session, which lasts up to twelve hours.

1. **A user's credentials may be compromised.** `POST /v1/platform/users/{user_id}/sessions/revoke` and `.../api-keys/revoke`. Both take effect on the next request and are refused by neither invariant, so they work for a last owner and for a tenant's last administrator. Revoke both: a user with a live session can create a new key a moment after their keys were revoked.
2. **The user must not act at all.** `POST /v1/platform/users/{user_id}/deactivate` sets the user inactive and revokes every session and user-owned API key in one transaction. It is refused (`409`) if it would leave the deployment without an owner (`last_platform_owner`) or a tenant without an administrator (`last_tenant_administrator`), for the caller's own user (`self_target`), and when the deployment has more tenants than `PLATFORM_DEACTIVATION_MAX_TENANTS` (`registry_scan_limit`: every deactivation is refused until the setting is raised). In each case use step 1, which is never refused by an invariant, and resolve the cause. If it is answered `503`, repeat it. Then disable the subject at the identity provider.
3. **An operator's account may be compromised.** An owner suspends the operator (`POST /v1/platform/operators/{operator_id}/suspend`) and revokes the user's sessions.
4. **The only owner is compromised or lost.** Recovery (section 6).
5. **Do not set `core.users.is_active` by SQL.** The database revokes nothing: the sessions and keys stay valid. The contract belongs to the operation.
6. Afterwards: read the platform audit for the actor and the period, and the affected tenants' own audit trails; a platform change to a tenant is recorded in both. For anything that may have been done with `IAM_OWNER`, the evidence is ZITADEL's own event log, which SaaS OS neither reads nor stores (section 9).

Reactivating a user restores no credential: the user logs in again and is issued new keys.

### 6. Recovery (break-glass)

```
python -m saas_os.api.platform_bootstrap recover \
    --enroll-issuer https://<your-identity-provider> \
    --enroll-subject <the replacement's OIDC subject> \
    --grant platform.authority:manage \
    --suspend-operator <operator id> \
    --reason "INC-1234: owner account compromised"
```

- It can enroll an operator, grant named permissions and suspend an operator. It never revokes, deletes or reactivates; an owner does that afterwards over HTTP.
- **Pass one `--grant` for every permission the replacement must hold or be able to hand out.** A person can grant only a permission they hold themselves, and never to themselves: a replacement enrolled with `platform.authority:manage` alone can enroll people and grant that one permission, and nothing else -- not even the session revocation of section 5. Anything left out needs another `recover` run. `recover` reuses an existing active operator for the identity and skips grants it already holds.
- `ENVIRONMENT=production` requires `--confirm-production`, as for the bootstrap.
- It is not a security boundary: whoever can run it already holds tier-0 access. What it adds is the lock, the last-owner check and the evidence.
- Controls, none enforced by SaaS OS: two people perform a recovery; the reason is the incident reference; the platform audit is reviewed afterwards. Every run is logged at warning level.

### 7. Restoring or cloning a database

**A copy of the database is a copy of the authority.** The operators, their grants and their live sessions come with it, and so do every API key, service-account key and webhook signing secret. The same is true of a backup, and of the key that decrypts it. After restoring production data into any other environment, before that environment is reachable:

1. Revoke every session. The application role may do it: `DELETE FROM core.sessions;`
2. Remove the platform authority that came with the copy. The runtime role cannot delete platform rows; with the migrations role, in the copy only: `TRUNCATE core.platform_grants, core.platform_operators;` (grants reference operators, and nothing else references either table, so no `CASCADE` is needed). Keep or truncate `core.platform_audit_log` according to why the copy was made.
3. Point the environment at its own identity provider, and set its `OIDC_ISSUER_URL`. If it shares production's, production subjects can log in to the copy as the ordinary users they are there.
4. Only then run the owner bootstrap for the people who operate that environment. The bootstrap enrolls its owner under the issuer configured at that moment and refuses to run again once an operator exists: done before step 3, it enrolls someone who can never log in, and only `recover` gets out.

A restore *of* production (disaster recovery) is the same installation and keeps its operators. It also **undoes everything done after the backup was taken**: an operator or a grant revoked since is live again, a suspended operator is active, a deactivated user is active, and a session revoked since is valid until it expires. Before the system is reachable, delete all sessions (`DELETE FROM core.sessions;`), then re-apply every revocation, suspension and deactivation made after the backup, from the incident record or from a newer copy of the platform audit; treat any operator enrolled after the backup as not enrolled; and check the owners.

### 8. Operator-run calls with no route

Moving a tenant under another, marking a tenant deleted, purging it, and erasing an identity have no HTTP route. They are Python calls made by an operator with the deployment's credentials: `move_tenant` and `transition_tenant_status(..., TenantStatus.DELETED)` need a caller holding `platform.tenant:move` or `platform.tenant:delete` and are recorded; `purge_tenant` is described under "Tenant purge" in the consumer guide and takes `caller=SystemCaller(SystemAuthority.TENANT_PURGE)` -- no person or operator is accepted -- with the person running it in `actor_user_id`; both of its transitions are recorded in the platform audit. `erase_user_identity` is described in `docs/MULTI-TENANCY.md` section 6. Erasure refuses a user who is an enrolled operator: revoke the operator first.

### 9. The identity provider's event log

SaaS OS records platform authority in `core.platform_audit_log`; what is done *at the identity provider* -- a password or passkey reset, a new key, an `IAM_OWNER` grant, a user disabled -- is recorded only by the identity provider. For a takeover through `IAM_OWNER` (`docs/SECURITY.md` section 11) that record is the independent evidence. In the reference topology (`docker-compose.prod.yml`, ZITADEL `v4.19.0`):

- **Where it is.** ZITADEL is event-sourced: every change it makes is an event in its own database, the `zitadel-db` service (database `${ZITADEL_DB_NAME}`), table `eventstore.events2`. That database is reachable only on the `identity-db` network; the SaaS OS backend cannot reach it, by design.
- **How to read it.** Through ZITADEL itself, as an instance administrator: the Admin API's `ListEvents` (`admin.v1.AdminService/ListEvents`), which filters by aggregate (for example one user), event type and time. Reading the table directly with the database owner's credentials also works, and is a tier-0 act.
- **How it is kept.** The events are ZITADEL's system of record, not a log it rotates: they stay in that database for as long as the database does. They are therefore inside the identity backup ("Self-hosted identity operations", sections 5 and 6), and a restore of an older identity backup loses the events written since. Keep identity backups for at least as long as you keep the platform audit, and keep `ZITADEL_MASTERKEY` with them: a `zitadel-db` backup without its master key does not restore.
- **What it is not.** It is not tamper-evident either: whoever holds the `zitadel-db` owner credentials can alter it. For evidence that must survive a compromise of tier 0, export the relevant events (or the whole backup) to storage that the same people cannot write.
- **After an incident.** Retrieve the events for the affected subjects and for every `IAM_OWNER` holder over the incident window, and keep that export with the incident record, next to the platform audit rows of the same window.

## Audit digests (ADR-0053)

The worker digests every settled window of `core.audit_log` and `core.platform_audit_log` and writes one `audit_digest` line per window to its log. Those lines are the only evidence against someone who can change the database: they are worth nothing unless they leave the database administrators' reach. Background: `docs/ADR/0053-audit-digests-in-external-logs.md`.

### 1. Before production

1. Ship the worker's stdout to an append-only or retention-locked store: for example object storage with a compliance-mode retention lock, or a log service in which entries cannot be edited or deleted.
2. Make sure nobody who holds the migrations role, superuser access or host access to the database can delete entries, edit them, or shorten the store's retention. Where the same people hold both, the control is absent. Record who holds the store's administrative rights.
3. Keep the lines at least as long as the audit rows they cover.
4. Alert when no line with `"message": "audit_digest"` has arrived for longer than one window plus the settle time plus a margin: about 80 minutes with the defaults (`AUDIT_DIGEST_WINDOW_SECONDS=3600`, `AUDIT_DIGEST_SETTLE_SECONDS=900`). A stopped worker or a broken pipeline otherwise leaves rows uncovered without anyone noticing.
5. After the first deployment, wait for the first lines and run the verification below once, so the procedure is known to work.

The settle time must exceed the longest transaction that writes audit rows. A row committed after its window was digested shows up as a change.

### 2. Verifying

Export the `audit_digest` lines for the period from the **external store**, never from the database or from a copy the database administrators can edit. Then run this inside the backend or worker container, which carries the application role's `DATABASE_URL`:

    python -m saas_os.ops.audit_digest verify exported.jsonl

The command prints one JSON object, and its exit status says how the check went:

- **0**: every window matches and the chain is whole.
- **1**: something differs, and each finding names its window, plus the tenant for `audit_log_changed`.
- **2**: the input or the configuration is unusable.

The command only reads. `covered_until` says where coverage ends; rows newer than that are not covered yet.

| Finding | Meaning | First step |
| --- | --- | --- |
| `audit_log_changed` / `platform_audit_log_changed` | Rows in that window (and tenant) differ from when they were digested | Treat as an incident: restore the window from a backup into an isolated target and compare |
| `gap` | No record for a period | Check the worker and the log pipeline for that period; those rows were never digested |
| `chain_broken`, `chain_restarted` | `core.audit_digests` was changed or emptied, or the database was restored | Compare with the incident record of any restore; otherwise an incident |
| `record_altered`, `conflicting_records` | The export itself differs from what was logged | Check the export and the store's integrity |
| `rows_before_coverage` | Rows dated before the first record | Rows inserted into the past, or a chain restarted: an incident unless explained by a restore |
| `rows_after_coverage` | Settled rows after the last record | The export ends early, or records never reached the store: re-export to the present; if still there, check the pipeline (`--partial` only for a deliberately shorter export) |

### 3. After a restore from backup

A restore removes the audit rows written after the backup. Every window after it is then reported as changed, and the chain breaks at the restore point. Record the restore time and the verifier's output in the incident record. Findings in windows before the backup are not explained by the restore.

## Operator commands (ADR-0050)

`saas-os-operator` runs the four destructive platform operations that are never routes, and the stored-error redaction below. Run it inside the backend container (`docker compose -f docker-compose.prod.yml exec backend saas-os-operator ...`), which has the deployment's environment and the application role's `DATABASE_URL` -- never the migrations URL; add `--confirm-production` in production. On success it prints one JSON object on standard output and exits 0; `failed: <ErrorType>` on standard error with exit 1 when Core refuses or fails; usage and input errors on standard error with exit 2.

```
# Mark a tenant deleted (an operator holding platform.tenant:delete)
saas-os-operator delete-tenant --tenant <id> --operator <operator user id>     --reason "TICKET-1" --confirm <id>

# Purge it into its tombstone; --setup registers the product's purge participants
saas-os-operator purge-tenant --tenant <id> --actor <your user id>     --setup my_product.purge:register_purge_participants --confirm <id>

# Move a tenant and its subtree (platform.tenant:move)
saas-os-operator move-tenant --tenant <id> --new-parent <id>     --operator <operator user id> --reason "TICKET-2"

# Erase a user's identity data and their memberships in the listed tenants
saas-os-operator erase-user --user <id> --tenant <id> [--tenant <id> ...]     --actor <your user id> --confirm <user id>

# Count, then redact, stored webhook errors that still carry a destination URL
saas-os-operator redact-webhook-errors
saas-os-operator redact-webhook-errors --apply
```

- A purge without `--setup` must say `--no-product-participants`: otherwise product rows would stay behind the purged tenant. The command is its own process: participants the product registered in its API or worker process are not registered here, which is why `--setup` is required. A `--setup` that registers nothing is refused before the tenant is touched. A purge run with `--no-product-participants` records `product_participants_skipped: true` in its `tenant.purge_completed` metadata, so the override can be found in the audit trail. Participants already registered in the process still run, so `participants_run` can be above 0.
- A purge that fails exits 1 and leaves the tenant `PURGING` with a `tenant.purge_failed` record; a failing product participant shows as `failed_step` `participant:<name>`. Fix the cause and run the same command again: it resumes and re-runs every step. Only a run that reaches `PURGED` records `tenant.purge_completed`.
- An enrolled platform operator is not erased: revoke the operator first.
- `erase-user` removes the user only from the tenants you list, and Core cannot find the others for you. List them first, with the migrations role: `SELECT tenant_id FROM core.tenant_memberships WHERE user_id = '<user id>'`. The result does not prove completeness. If an erasure fails part way, run the same command again to finish it.
- Nothing here is a protection against the person running it; `--reason` should carry the ticket reference, which the audit records.
- `redact-webhook-errors` (ledger row 900) finds the webhook destination errors stored before pull request #110, whose text holds the destination URL with any credential or token in it: outbox `last_error` values in every tenant, closed ones included, and Redis dead-letter entries. Without `--apply` it only counts (`outbox_events`, `dead_letter_entries`). With `--apply` it replaces each matching text with `<error type>: Invalid webhook URL (redacted: the stored message contained the destination URL).` and changes nothing else: no status, attempt, schedule or other entry. The old text cannot be recovered, so keep a backup if you need it. A second run finds 0. It needs `REDIS_URL` as well as `DATABASE_URL`, and writes no audit record. Backups and log stores taken before the run still hold the old text.

## AI configuration role (ADR-0056)

The `saas-os-operator ai-*` commands that change AI configuration (every one except `ai-show`) run their transaction as the platform-configuration role, the only role that can write the global AI configuration tables. The application role can only read them.

- **Provision.**
  - The migration `f6a2c8e4b1d9` creates `saas_os_platform_config` (or `PLATFORM_CONFIG_DB_USER`) `NOLOGIN` if it does not exist and grants its privileges. If the migrations role lacks `CREATEROLE`, create the role first: `CREATE ROLE saas_os_platform_config NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;`
  - Enable it with the migrations role: `ALTER ROLE saas_os_platform_config LOGIN PASSWORD '<generated>';`
  - Local Compose: give `PLATFORM_CONFIG_DB_PASSWORD` in the shell for the first `docker compose up -d db` of a new volume (`02-create-platform-config-role.sh`), never in `.env`.
- **Use.** Put the URL in the one command's environment, never in the backend's or the worker's:

  ```
  docker compose -f docker-compose.prod.yml exec -e PLATFORM_CONFIG_DATABASE_URL backend \
      saas-os-operator ai-provider-create ... --confirm-production
  ```

  `exec -e NAME`, with no `=value`, copies the variable from your shell into the environment of that one exec'd process; the backend's own process does not get it. Missing or wrong, the command fails with `DatabaseConfigurationError` or `UnsafeDatabaseRoleError` and changes nothing. The backend and the worker refuse to start if `PLATFORM_CONFIG_DATABASE_URL`, `PLATFORM_CONFIG_DB_PASSWORD` or either `_FILE` form is in their environment.
- **Keep the URL out of shell history.** Never type it on a command line. In bash, read it without echo, use it, then remove it from the shell:

  ```
  read -rs PLATFORM_CONFIG_DATABASE_URL && export PLATFORM_CONFIG_DATABASE_URL
  docker compose -f docker-compose.prod.yml exec -e PLATFORM_CONFIG_DATABASE_URL backend \
      saas-os-operator ai-provider-create ... --confirm-production
  unset PLATFORM_CONFIG_DATABASE_URL
  ```

  **File form.** `PLATFORM_CONFIG_DATABASE_URL_FILE=<path>` names a file whose content is the URL. Only the production and test secrets provider reads `_FILE` (`EnvironmentSecretsProvider`, used when `ENVIRONMENT` is `production` or `test`); the development `.env` provider does not. The path is read by the command, inside its container. A file that exists in the long-running backend container is readable by the API process there too, even though that process refuses the variable. So do not mount the file into the running backend; this repository does not ship or test a one-off container for the purpose.
- **What this does not protect against.** The steps above keep the URL out of `.env`, out of shell history, off command lines, and out of the backend's and the worker's environments. They do not hide it from anyone with privileged access while the command runs:
  - the value is in the environment of your shell (until `unset`), of the `docker` client, and of the operator process inside the container. Root on the host, and root or the same user inside the container, can read them (for example `/proc/<pid>/environ`);
  - anyone who can use the Docker daemon can run commands in the container and read that process's environment;
  - SaaS OS error messages and logs name the variable or the role, never the URL. A third-party tool you add (a shell profile that logs commands, terminal recording, a debugger) is not covered.

  Treat the operator host and the operator command as a trusted administrative boundary (ADR-0056, "Still trusted"). Avoiding shell history is hygiene; it is not a control against a privileged local user.
- **Rotate.** `ALTER ROLE saas_os_platform_config PASSWORD '<new>';` then replace the stored secret. Nothing long-running holds a connection.
- **Revoke.** `ALTER ROLE saas_os_platform_config NOLOGIN;` disables AI configuration changes and nothing else. Inference keeps working.
- **Check.** If the application or the worker stops with "can write control_plane.ai_...", the application role has a write grant on a protected table: apply the pending migrations, or revoke the grant.
- **Downgrade.** Below `f6a2c8e4b1d9` the application role regains `INSERT, UPDATE` on the six tables and the platform-configuration role loses its privileges in this database. The role itself stays; drop it with `DROP OWNED BY saas_os_platform_config; DROP ROLE saas_os_platform_config;` in each database it has privileges in.

## Self-hosted identity operations (ADR-0023 Phase 3)

Procedures for the production self-hosted ZITADEL topology
(`docker-compose.prod.yml`, docs/DEPLOYMENT-ARCHITECTURE.md §11a).

### 1. Initial production bootstrap

```
docker compose -f docker-compose.prod.yml up -d proxy
```

Caddy's own `depends_on` pulls in the entire identity stack (ZITADEL, its
dedicated database, the TLS-material init step) before Caddy itself
starts. Then:

```
docker compose -f docker-compose.prod.yml up -d zitadel-bootstrap
docker compose -f docker-compose.prod.yml logs zitadel-bootstrap
```

The last command prints `OIDC_CLIENT_ID=<value>` -- copy it into the
production `.env.app`'s `OIDC_CLIENT_ID`, then
`docker compose -f docker-compose.prod.yml up -d --force-recreate backend`
so `backend` picks it up. `OIDC_ISSUER_URL` should already be set to
`https://<IDENTITY_PUBLIC_DOMAIN>`; `OIDC_CLIENT_SECRET` stays empty (a
public, PKCE-only client, matching Phase 1's local default).

### 2. Re-running bootstrap safely

Safe to re-run at any time (list-before-create by name, unchanged from
Phase 1) -- it finds the existing `saas-os` project and `saas-os-backend`
application and reuses the same `OIDC_CLIENT_ID`, printing it again
rather than creating a duplicate. Only re-copy the value into `.env.app` if
it changed (it will not, on an existing instance).

### 3. ZITADEL restart

```
docker compose -f docker-compose.prod.yml restart zitadel
```

Existing SaaS-OS sessions remain valid throughout (`saas_os/core/identity/sessions.py`
never calls the provider); `/auth/me`, RBAC, and API-key/service-account
authorization are all unaffected. New logins fail closed (502/503,
through Caddy's own upstream health check against ZITADEL's
`/debug/ready`) until ZITADEL reports healthy again, then work normally
-- verified empirically (Phase 3 implementation report) by stopping and
restarting ZITADEL against a real running stack.

### 4. ZITADEL upgrade

Pin the new exact version in `docker-compose.prod.yml` (never `latest`),
same convention as every other pinned image in this repository. Bring
`zitadel` down, deploy the new image, let its own `init`/`setup` steps
run its internal migrations against `zitadel-db` (ZITADEL's own
mechanism, entirely independent of SaaS-OS's Alembic history), verify
`/debug/ready`, then resume traffic. Verify a rollback path (the prior
image tag) before considering the upgrade complete --
docs/DEPLOYMENT-ARCHITECTURE.md §6's own binding rollback requirement,
applied here to ZITADEL specifically for the first time; a ZITADEL-side
schema migration that already ran against `zitadel-db` may not be
reversible by the image alone.

`zitadel` and `zitadel-login` are pinned to the same release and move
together (`tests/architecture/test_production_identity_topology.py`).
Upgrading a deployment from v4.19.0 to v4.19.5: set
`ZITADEL_SESSION_COOKIE_SECRET` first (section 11), take a backup (section
5), deploy `zitadel`, wait for `/debug/ready`, then deploy `zitadel-login`.
v4.19.1 to v4.19.5 list no manual migration; ZITADEL's own setup steps run on
start. Read the release notes of every version in between before any later
upgrade.

### 5. Backup

```
python -m saas_os.infra.db.backup.orchestrator run \
    --container saas-os-zitadel-db-1 \
    --admin-database-url-var ZITADEL_BACKUP_DATABASE_URL
```

or let `deploy/saas-os-zitadel-backup.timer` run it daily (see
docs/BACKUP-RESTORE.md's own ZITADEL section for the full pipeline
description). **Also back up `ZITADEL_MASTERKEY` itself, separately,
through your own secret-management process** -- it is never part of this
pipeline's own artifact, and a `zitadel-db` backup without its matching
masterkey is not a valid disaster-recovery backup.

### 6. Restore

```
python -m saas_os.infra.db.backup.orchestrator restore \
    --container saas-os-zitadel-db-1 \
    --admin-database-url-var ZITADEL_BACKUP_DATABASE_URL \
    --metadata /path/to/backup.pgdump.json \
    --target-database zitadel_restored \
    --confirm-production-restore
```

Restores into a **fresh** target only (this pipeline's own
never-overwrite guarantee, unchanged) -- point `zitadel-db`'s own
`ZITADEL_DB_NAME` at the restored database name (or rename it to the
expected one) before bringing `zitadel` up against it. See
docs/BACKUP-RESTORE.md's own "ZITADEL database backup" section for the
complete restore sequence, including the master-key step below.

### 7. Master-key recovery

Restoring `zitadel-db` alone is not sufficient: set
`ZITADEL_MASTERKEY` in the restore target's own `.env` to the *exact*
value that was active when the backup was taken (from your own separate
secret backup, step 5) before starting `zitadel` against the restored
data. A mismatched or missing masterkey does not fail loudly with a
clear message at this pinned version -- treat "wrong masterkey" as the
first thing to double-check if `zitadel` fails to become ready against a
freshly restored database.

### 8. OIDC configuration verification

```
curl -s https://<IDENTITY_PUBLIC_DOMAIN>/.well-known/openid-configuration | python -m json.tool
```

Confirm `"issuer"` equals `OIDC_ISSUER_URL` exactly (a mismatch here is
the single most common misconfiguration -- `saas_os/core/identity/oidc.py`'s
issuer check rejects every token otherwise). From the `backend`
container, confirm the same discovery document is reachable directly
(proving the `identity-edge` alias + TLS trust, not just Caddy's own
public leg):

```
docker compose -f docker-compose.prod.yml exec backend python -c \
    "from saas_os.core.identity import provider; print(provider._discover_jwks_uri('https://<IDENTITY_PUBLIC_DOMAIN>'))"
```

(substitute the real value for `<IDENTITY_PUBLIC_DOMAIN>` -- it is not
itself part of `backend`'s own persistent environment, deliberately:
`saas_os/core/identity` never reads it, only the already-configured
`OIDC_ISSUER_URL`, which equals `https://<IDENTITY_PUBLIC_DOMAIN>` by
operator convention.) Printing the `jwks_uri` proves the exact mechanism
this ADR's Phase 3 depends on: `backend` reaching ZITADEL directly over
`identity-edge`, through SaaS-OS's own discovery client, trusting ZITADEL's
self-signed internal certificate via `OIDC_CA_BUNDLE` (set in `backend`'s
own environment), without hairpinning through Caddy. Since the owner
decision on ledger row 965 (2026-10-28, ADR-0023 amendment) identity calls
ignore `SSL_CERT_FILE` and the proxy variables and refuse redirects; a
plain `httpx.get` probe would still read `SSL_CERT_FILE` and so proves
less.

### 9. Master-key compromise (incident response, ADR-0023 Phase 4)

Distinct from ordinary loss/disaster-recovery (steps 5-7 above): this is
for a `ZITADEL_MASTERKEY` that is suspected **exposed** -- known or
plausibly known to someone other than its authorized operators -- even
if there is no evidence it has been misused yet.

**Detection.** Treat any of the following as a compromise, not merely an
operational slip: the key value appearing in a log, error message,
process listing, shell history, ticket, chat message, or any other
unintended output; an unauthorized person gaining access to the
production host, the operator's secret-management system, or a backup of
either; suspected compromise of any operator account able to read the
value. This repository's own backup/observability code never logs or
exposes it (docs/BACKUP-RESTORE.md's Security section, ADR-0023 §12) --
an appearance of the value anywhere is itself evidence of a channel this
architecture does not expect and should not be dismissed as benign.

**Immediate containment.** Treat the key as compromised as soon as
suspected, not only once confirmed. Treat the running production
`zitadel` instance -- and everything it currently trusts -- as
untrustworthy from that point forward. Restrict access to the affected
host and to wherever the key is stored (rotate access credentials to
that storage itself, if it is a shared system). Preserve logs and other
evidence relevant to how the exposure happened before taking any
destructive action. Notify this deployment's operator/security owner
immediately -- do not attempt silent, solo remediation of a credential
compromise.

**Critical distinction -- this is not a rotation.** `docs/BACKUP-
RESTORE.md`'s own statement stands: there is no repository-supported
in-place master-key rotation mechanism at the pinned
`ghcr.io/zitadel/zitadel` image (established at v4.19.0; the v4.19.1 to
v4.19.5 release notes announce none). **Do not simply set a new value
for `ZITADEL_MASTERKEY` in `.env` and restart `zitadel` against the
existing, already-provisioned `zitadel-db`.** ZITADEL's own signing keys
and other sensitive state already at rest in that database are encrypted
under the *old* key; restarting against a new one is not an approved
recovery or rotation procedure for that existing data and this
repository makes no claim it produces a working instance, a readable
database, or a safe security boundary. Nothing in this repository
performs, or has verified, an in-place re-encryption of `zitadel-db`
under a new masterkey.

**Recovery direction.** Treat the compromise as scoped to the entire
existing identity instance, not merely to the key value:

* Do not continue operating the existing `zitadel` instance against its
  existing `zitadel-db` as though nothing happened.
* Decide, with the operator/security owner, whether the deployment must
  be recreated from scratch (a new `zitadel`/`zitadel-db` provisioned
  with a newly generated `ZITADEL_MASTERKEY`, following the same
  "Initial production bootstrap" procedure at the top of this section)
  rather than restored from an existing backup -- see Backup implications
  below for why an existing backup is not automatically a safe starting
  point.
* Where the architecture permits a newly generated secret (a fresh
  `ZITADEL_MASTERKEY`, fresh `ZITADEL_DB_PASSWORD`, a freshly
  bootstrapped instance), use one -- do not reuse the compromised value
  or any value derived from it.
* Re-establish the OIDC application configuration the normal way (steps
  1-2 above: `zitadel-bootstrap`, `OIDC_CLIENT_ID` into `.env.app`,
  `--force-recreate backend`).
* Re-establish any other bootstrap/provisioning state the same
  documented way, rather than by copying state out of the compromised
  instance.
* Validate the new issuer (`OIDC_ISSUER_URL`/`ZITADEL_EXTERNALDOMAIN`
  match, step 8 above) and a real end-to-end login before considering
  the incident's identity-infrastructure leg closed.
* Where the architecture exposes a way to invalidate standing trust tied
  to the old instance (e.g. the OIDC application/client registered with
  it), treat that as part of closing the incident, not an optional
  follow-up.

This repository does not implement, and this runbook does not invent, an
automated migration or re-encryption procedure between the old and new
instance -- that gap is exactly why prevention (containment above) and a
security-owner decision matter more than a scripted fix here.

**Existing SaaS sessions.** SaaS-OS sessions are owned by SaaS-OS, not by
ZITADEL (`saas_os/core/identity/sessions.py` never calls the provider, restated
from step 3 above) -- recreating or abandoning the ZITADEL instance does
**not**, by itself, invalidate any existing SaaS-OS session, revoke any
issued API key, or change RBAC/tenancy state. Treat the incident response
as covering several independent surfaces, not one: existing SaaS
sessions, any *fresh* OIDC authentication against the (now
untrustworthy) old issuer, the identity-provider trust relationship
itself, and any operator/application credential that could plausibly
have been reached through the same exposure. Assess and close each
separately; do not assume recreating ZITADEL is a substitute for
reviewing the others.

**Backup implications.** A `zitadel-db` backup taken while the
compromised masterkey was active is encrypted under that same
compromised trust boundary -- it is not automatically a "clean" recovery
source merely because it predates the moment compromise was noticed (the
exposure window is frequently uncertain). Restoring such a backup
resurrects the same signing material the compromise put at risk.
Whether any existing backup is safe to use as a data source for a
*newly* provisioned instance (as opposed to restoring it directly into a
trusted deployment) requires the operator/security owner's own
assessment of what was actually exposed -- this runbook does not
prescribe a universal answer. Independent of that assessment, the
existing rule stands: a `zitadel-db` backup without its matching
masterkey was never a valid recovery artifact in the first place
(docs/BACKUP-RESTORE.md).

### 10. Bootstrap token

ZITADEL creates an `IAM_OWNER` personal access token for the `bootstrap`
machine user when it creates the instance, and writes it to the
`zitadel-bootstrap-prod` volume for `zitadel-bootstrap` (ADR-0045,
section 10, item 6). It is the strongest credential in the deployment, so
it must not outlive its use.

- **Expiry.** `ZITADEL_BOOTSTRAP_PAT_EXPIRATION` (RFC 3339) is required:
  every `docker compose -f docker-compose.prod.yml` command refuses to run
  without it. Set it about 30 days after the first deploy. ZITADEL reads it
  once, when it creates the instance; changing it later changes nothing.
- **Upgrading an existing deployment** to a version with this setting:
  before pulling it, add `ZITADEL_BOOTSTRAP_PAT_EXPIRATION` to `.env` (any
  valid time; the existing instance ignores it), then revoke the existing
  token as below -- it was created with an expiry in 2100.
- **After the first bootstrap** (section 1: `OIDC_CLIENT_ID` copied, login
  working), revoke the token rather than wait for it to expire: in the
  console (`https://<IDENTITY_PUBLIC_DOMAIN>/ui/console`), Users → Service
  Users → `bootstrap` → Personal Access Tokens → delete. Then empty the
  token file (the `zitadel-bootstrap` service mounts the volume read-only,
  so write through a separate container):

  ```
  docker volume ls | grep zitadel-bootstrap-prod     # the exact volume name
  docker run --rm -v <volume>:/bootstrap busybox:1.36.1 \
    sh -c ': > /bootstrap/bootstrap.pat'
  ```

  From then on `zitadel-bootstrap` finds the empty file, prints that the
  token is revoked and exits successfully, so a routine `up -d` still works.
- **Running the bootstrap again** (section 2) needs a token: create a new
  personal access token for `bootstrap` in the console with an expiry of a
  day, write it to the volume, run the bootstrap, then delete the token and
  empty the file again:

  ```
  printf '%s' '<token>' | docker run --rm -i -v <volume>:/bootstrap busybox:1.36.1 \
    sh -c 'cat > /bootstrap/bootstrap.pat'
  docker compose -f docker-compose.prod.yml up zitadel-bootstrap
  ```
- ZITADEL's own event log records every use of the token; keep it
  (Independent evidence, ADR-0045).
- The local development topology (`docker-compose.yml`) keeps its
  long-lived token: it is a development instance, outside this rule.

### 11. Login V2 session-cookie secret

`zitadel-login` signs its `sessions` cookie, and the short-lived proofs that a
user has just verified an email or invite code (5 minutes) or is linking an
identity provider (15 minutes), with `ZITADEL_SESSION_COOKIE_SECRET`. Before
ZITADEL v4.19.2 that cookie was unsigned, which allowed account takeover
through Login V2 (GHSA-jh92-5mrj-p2w2, High). `docker-compose.prod.yml` pins
v4.19.5 and refuses to start while the variable is unset or empty; ZITADEL
itself does not read it, and local development, which runs no Login V2, does
not need it.

Requirements (ZITADEL v4.19.5, `apps/login/src/lib/session-cookie-signature.ts`
and `self-hosting/manage/login-client.mdx`):

- Generate it from a cryptographically secure random source:
  ```
  openssl rand -base64 32
  ```
  Store the output in the deployment's secret store at once; never paste it
  into a committed file, a ticket or a log.
- Every value must be at least 32 characters. A shorter value is not ignored:
  Login V2 logs an error, reports not ready on `/ready` and signs nothing.
- Every Login V2 replica serving the same deployment needs the same value, or
  a cookie written by one replica is rejected by another.
- Supply it to Compose from the secret store through the deploying shell's
  environment, or write it into the production `.env`, which Compose reads
  only to fill in `${...}` values and loads into no service (see "Production
  configuration files" below). Never put it in `.env.app`.

Without a dedicated secret Login V2 would derive its key from its own API
credential (here the login-client private key). ZITADEL deprecates that
fallback, and in it rotating the private key (`deploy/generate-login-client-key.sh`)
signs every user out of Login V2; this repository does not use it.

**Rotation.** The variable takes a comma-separated list: the first value
signs, every value verifies.

1. Generate a new value and deploy `<new>,<old>` to every replica:
   `docker compose -f docker-compose.prod.yml up -d zitadel-login`.
2. After the longest Login V2 session lifetime has passed, deploy `<new>`
   alone.

Proofs signed with the old value stay valid while it is still listed.
Removing a value at once, instead of through step 1, signs every Login V2
user out; application sessions (`saas_os/core/identity/sessions.py`) and
issued tokens are not affected. Treat a disclosed value as compromised:
replace it directly (not through step 1, which would keep accepting it) and
accept the sign-out.

**First deployment of v4.19.2 or later.** Cookies written by an older Login V2
carry no signature and are ignored, so every Login V2 user signs in again
once (more than once during a rolling update). A user partway through email
or invite verification, passkey registration or IdP linking starts that step
again.

## Production configuration files (ADR-0012 amendment of 2026-10-21)

`docker-compose.prod.yml` reads two files next to it. Both are gitignored
(`.env.*` and `.env`).

| File | Holds | Read by |
|---|---|---|
| `.env.app` (template `.env.app.example`) | the application's settings: `DATABASE_URL`, `MIGRATIONS_DATABASE_URL`, `REDIS_URL`, `OIDC_*`, Stripe, SMTP, `PLATFORM_TENANT_ID`, `BACKUP_*` | `backend` and `worker` (`env_file:`); the host timers in `deploy/` |
| `.env` | the values Compose fills into the file: `PUBLIC_DOMAIN`, `IDENTITY_PUBLIC_DOMAIN`, `IDENTITY_PROFILE`, every `ZITADEL_*` value, and `POSTGRES_*`/`APP_DB_*` for the bundled reference database | Compose's own `${...}` substitution only; no service loads it; `deploy/saas-os-zitadel-backup.service` reads `ZITADEL_BACKUP_DATABASE_URL` from it |

`frontend` and `proxy` load neither file; `proxy` receives
`PUBLIC_DOMAIN`, `IDENTITY_PUBLIC_DOMAIN` and `IDENTITY_PROFILE` explicitly.
So the identity provider's secrets (`ZITADEL_MASTERKEY`, ZITADEL's database
password, the first-instance admin password, `ZITADEL_SESSION_COOKIE_SECRET`)
reach only the identity services that use them.

Never copy an identity value into `.env.app`. `scripts/check-docker-prod-tls.sh`
fails if `backend`, `worker`, `frontend` or `proxy` receives any `ZITADEL_`
variable.

**Moving an existing deployment** (from v0.2.0 or earlier, where `.env` was
loaded whole into all four services):

1. Copy `.env.app.example` to `.env.app` and move into it every application
   setting from `.env` (the table above). Keep `.env` mode `0600`, and give
   `.env.app` the same.
2. Remove the moved settings from `.env`, or leave them: no service reads
   `.env` any more, so they reach no container either way.
3. Point the host timers at the new file: reinstall the `deploy/*.service`
   units (they now name `.env.app`) and run `systemctl daemon-reload`.
4. `docker compose -f docker-compose.prod.yml up -d --force-recreate backend worker frontend proxy`.
5. Check: `docker compose -f docker-compose.prod.yml exec backend env | cut -d= -f1 | grep '^ZITADEL_'`
   prints nothing.

Compose refuses every command on this file while `.env.app` is missing
(`env file .../.env.app not found`), so a skipped step 1 stops the deployment
rather than starting the application without its settings.

## Production external PostgreSQL and Redis (ADR-0028)

The architectural decision is
`docs/ADR/0028-production-stateful-service-ownership-and-tls-trust.md`; this
section is the operational side of it and does not restate the reasoning.
Everything below describes behaviour already implemented and merged --
nothing here is a new decision.

### 1. Topology

Production runs against stateful services the operator owns:

```
Application
    |
    +--> external/operator-managed PostgreSQL   (DATABASE_URL, MIGRATIONS_DATABASE_URL)
    |
    +--> external/operator-managed Redis        (REDIS_URL)
```

`docker-compose.prod.yml` still defines `db` and `redis`, but both carry
`profiles: ["bundled-stateful"]`, so a plain
`docker compose -f docker-compose.prod.yml up` starts neither, and no service
declares `depends_on` on them. They are the **reference/local topology**
only -- the subject of `scripts/check-docker-prod.sh`'s perimeter test -- and
are not the production deployment. Local development uses
`docker-compose.yml`'s own `db`/`redis`, which are unrelated to this.

Start the bundled services only deliberately:

```
docker compose -f docker-compose.prod.yml --profile bundled-stateful up -d db redis
```

### 2. PostgreSQL configuration

Two variables, both pointing at the same operator-managed endpoint:

| Variable | Consumed by | Role |
|---|---|---|
| `DATABASE_URL` | application runtime (`saas_os/infra/db/config.py`) | the restricted application role |
| `MIGRATIONS_DATABASE_URL` | migration tooling (`saas-os-migrate`, Alembic via `saas_os/infra/db/migrations/env.py`) | the privileged migration/admin role |

Both resolve through the same enforcement path, so migrations are never a
weaker transport than the application. Keep the driver-qualified scheme the
repository already uses (`.env.app.example`), in the production `.env.app`:

```
DATABASE_URL=postgresql+psycopg://<app-role>:<password>@<host>:<port>/<database>?sslmode=verify-full&sslrootcert=<ca-path>
MIGRATIONS_DATABASE_URL=postgresql+psycopg://<admin-role>:<password>@<host>:<port>/<database>?sslmode=verify-full&sslrootcert=<ca-path>
```

Every angle-bracketed value is a placeholder. Supply them through the
existing mechanism -- the container environment, which in production is read
by `EnvironmentSecretsProvider`. Do not place a credential in a command-line
argument, where it would appear in a process listing.

TLS behaviour already enforced by `saas_os/infra/db/config.py`, which is the sole
owner of this policy:

- `sslmode=verify-full` is the production target. It is preserved exactly as
  written, together with `sslrootcert` and any other libpq parameter.
- Supplying no `sslmode` causes `sslmode=require` to be injected. That is the
  shipped default and it is *not* verify-full: it encrypts without validating
  the server's certificate or hostname.
- `sslmode=disable`, `allow`, `prefer` and any unrecognised value are rejected
  at configuration time, before a connection is attempted. There is no
  plaintext fallback.

Under `verify-full` the PostgreSQL hostname in the URL must match the server
certificate's SAN, and the CA that signed it must be readable by the process
at the `sslrootcert` path.

### 3. Redis configuration

```
REDIS_URL=rediss://:<password>@<host>:<port>/<db-index>
```

Production requires the `rediss://` scheme. `redis://` is rejected by both
owning modules (`saas_os/infra/jobs/config.py`, `saas_os/infra/ratelimit/config.py`), which
validate the scheme rather than rewriting it -- Redis has no in-URL
equivalent of `sslmode`.

Trust behaviour, stated precisely:

- The Redis client verifies the **certificate chain** against its trust store
  (`cert_reqs` resolves to `CERT_REQUIRED`).
- It does **not** perform hostname verification (`check_hostname` is
  `False`), and there is no application-level setting to enable it. Redis
  therefore does not provide `verify-full` equivalence.
- There is no application-level `ssl_ca_certs` configuration surface. Trust
  comes from the process trust store only.
- A **publicly trusted Redis certificate is the preferred deployment**: it
  needs no CA distribution and the client default already validates it.

Memory: the same Redis holds the job queue and every rate-limit counter,
including one short-lived key per distinct refused credential (the
failed-credential limit, `saas_os/api/dependencies.py`). Size it with
headroom and alert on memory use. Keep the default `noeviction` policy: an
eviction policy such as `volatile-ttl` or `allkeys-lru` can evict queued
job keys, which carry a TTL. When Redis is full, rate-limited routes answer
`503` and the failed-credential check fails open; no job is lost.

### 4. CA material, `OIDC_CA_BUNDLE` and `SSL_CERT_FILE`

Two trust settings exist, each for its own connections; do not add another.

- `backend` mounts the `identity-ca` volume read-only at `/identity-ca`.
- Calls to the identity provider (discovery, JWKS, token exchange) and the
  `zitadel-bootstrap` job trust only `OIDC_CA_BUNDLE`, which
  `docker-compose.prod.yml` sets to `${OIDC_CA_BUNDLE-/identity-ca/tls.crt}`.
  It replaces certifi for those calls; an empty value means certifi. They
  never read `SSL_CERT_FILE` (ADR-0023 amendment of 2026-10-28).
- `backend` also sets `SSL_CERT_FILE: ${SSL_CERT_FILE:-/identity-ca/tls.crt}`.
  The default is ZITADEL's own internal CA, unchanged, but identity calls no
  longer depend on it.
- Because the Redis client builds its context from
  `ssl.create_default_context()`, `SSL_CERT_FILE` is also what makes a
  privately signed Redis certificate trusted. An operator in that situation
  supplies **one combined bundle** containing both the identity CA and the
  Redis CA and points `SSL_CERT_FILE` at it. This is process-wide trust: the
  CA becomes trusted for every TLS connection that container makes, which is
  why a publicly trusted Redis certificate is preferred.
- `worker` also connects to Redis but has **no** `identity-ca` mount and no
  `SSL_CERT_FILE` of its own. A private-CA Redis deployment must therefore
  make the CA file reachable by the worker process as well; the repository
  does not currently mount one there.
- PostgreSQL CA material is separate and per-connection: it is referenced by
  `sslrootcert` in the URL, not by `SSL_CERT_FILE`.

### 5. Certificate requirements (operator-side)

PostgreSQL:

- the certificate chain must validate against the CA given as `sslrootcert`;
- under `verify-full`, the certificate SAN must match the hostname in the URL;
- the CA file must be readable by the application and migration processes.

Redis:

- the certificate chain must validate against the process trust store;
- public trust is preferred;
- hostname verification does not apply (section 3).

### 6. Ownership

SaaS-OS consumes the configured endpoints and trust material. It does not
provision, issue, renew or own the external database/cache lifecycle. The
operator/infrastructure owner is responsible for:

- PostgreSQL and Redis credentials;
- PostgreSQL and Redis server certificates;
- any private CA material;
- rotating all of the above.

This repository prescribes no rotation interval, secret-management product,
credential store, automated renewal mechanism or provider, and this runbook
does not invent one.

### 7. Backup and restore against an external endpoint

`saas_os/infra/db/backup` supports both transports:

- **Container transport** -- pass `container=`; `pg_dump`/`pg_restore`/`psql`
  run through `docker exec` against that container. Unchanged, and still the
  path for a bundled/local database.
- **Endpoint transport** -- omit `container=`; the tools run directly against
  the endpoint named by the supplied configuration, carrying that
  configuration's TLS settings (forwarded through libpq's `PGSSL*` variables,
  so `verify-full` is never downgraded). This is the only path available for
  an external managed PostgreSQL, which has no container to exec into.

**Operational requirement:** endpoint-based backup and restore require the
PostgreSQL client binaries -- `pg_dump`, `pg_restore` and `psql` -- to be
present wherever the operation executes. They are deliberately **not** a
repository dependency, because the container transport needs none. A missing
binary produces an explicit error naming the tool.

### 8. Deployment checklist

1. External PostgreSQL provisioned.
2. External Redis provisioned.
3. PostgreSQL certificate SAN matches the hostname used in the URLs.
4. PostgreSQL CA trust available at the configured `sslrootcert` path.
5. `DATABASE_URL` configured, `sslmode=verify-full`.
6. `MIGRATIONS_DATABASE_URL` configured with equivalent TLS.
7. `REDIS_URL` uses `rediss://`.
8. Redis CA trust available via `SSL_CERT_FILE` when private trust is used --
   for the worker as well as the backend (section 4).
9. PostgreSQL client binaries available wherever backups/restores run.
10. Operator-owned rotation process exists for the external credentials and
    certificates.
11. Production Compose started **without** `--profile bundled-stateful`,
    unless the reference topology is deliberately wanted.
12. TLS connectivity validated against the real endpoints before the
    deployment is treated as complete (section 9).

### 9. Live validation is the operator's step, not a completed one

The repository's disposable Tier 2 harness
(`scripts/check-docker-prod-tls.sh`, ADR-0027) and the CI checks validate the
configuration layer and the harness itself. They do **not** constitute
validation of any real deployment: the harness uses disposable containers at
`sslmode=require`, and no live operator-managed PostgreSQL or Redis endpoint
has been validated. In particular, `verify-full` has never completed a
handshake against a real certificate, and the disposable harness proved
nothing about Redis hostname verification.

Before declaring a deployment complete, validate against the actual
endpoints:

- PostgreSQL: connect with `sslmode=verify-full` against the real hostname and
  certificate, and confirm the connection reports TLS active.
- Redis: connect over `rediss://`, confirm certificate-chain validation
  succeeds, and confirm application connectivity.
