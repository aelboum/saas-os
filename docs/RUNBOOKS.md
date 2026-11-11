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
- **How it is kept.** The events are ZITADEL's system of record, not a log it rotates: they stay in that database for as long as the database does. They are therefore inside the identity backup ("Self-hosted identity operations", sections 5 and 6), and a restore of an older identity backup loses the events written since. Keep identity backups for at least as long as you keep the platform audit, and keep the ZITADEL master key (the file `ZITADEL_MASTERKEY_FILE` names) with them: a `zitadel-db` backup without its master key does not restore.
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

### 4. User ids in audit rows: retention policy (not implemented)

Owner policy of 2026-11-02, approved: a completed audit row identifying a user as its initiator (`initiated_by` user id, and other user ids in audit metadata) keeps that identification for two years from the row's creation; a legal hold suspends expiry; after expiry a controlled privacy process removes or anonymises the direct identification where legally permissible, keeping the non-identifying history. **The mechanism is not implemented**: there is no expiry job, no legal-hold command and no redaction command. Do not edit or delete audit rows by hand with the migrations role to apply the policy: the digest verifier reports every such change as `audit_log_changed`, and the evidence chain cannot tell it from tampering. Requests to remove identifiers from audit rows are recorded and wait for the approved mechanism (proposal: `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md`). Identity erasure (`erase-user`) does not change audit rows.

**Platform audit rows that target a user: the first part is implemented** (audit identity phase P1, migration `e2b7c4d9a1f6`). A new platform audit row about a user (a user operation, a refusal, the attempt and completion rows of a user lookup, the refused erasure of an enrolled operator) stores a random reference (`target_type` `user_subject`) instead of the user id, and the `user_id` of operator events became `user_subject_ref`. Rows written before the migration keep their raw ids (they do not expire). Tenant audit rows, `actor_user_id` and the other raw ids are unchanged. The expiry command, the legal-hold routes and the lookup routes are not implemented: until they are, the references and their link rows (`core.platform_audit_subject_links`) are kept beyond two years. Section 5 covers the tables.

### 5. Audit subject references: the link tables and a deliberate downgrade

`core.platform_audit_subject_links` maps a reference stored in a platform audit row to a user, one live link per user and UTC day. It is the only way to resolve such a reference; its rows are `SECURITY_RETAIN`, the application role cannot delete them, and the only change it can make to a link is to unlink it (identity erasure). `core.platform_audit_subject_erasures` holds one marker per erased user, and `core.platform_audit_identity_holds` the legal holds (nothing places one yet).

- **Do not edit or delete these rows by hand with the migrations role.** A link deleted while an audit row still carries its reference makes that row unresolvable for good; the links that identity erasure unlinks are meant to be.
- **Migration order.** `saas-os-migrate upgrade head` (the migrations role) before the new application version starts. The migration creates two tables that reference `core.users`, which takes a `SHARE ROW EXCLUSIVE` lock on `core.users` for the milliseconds the migration transaction lasts: writes to `core.users` wait, reads do not. Prefer a quiet moment.
- **Downgrade.** `saas-os-migrate downgrade` past `e2b7c4d9a1f6` refuses while any of the three tables holds a row (`refusing to drop it`) and changes nothing. On an installation that has recorded any platform action against a user it therefore always refuses: dropping the link table would make every reference already written unresolvable. If the owner approves it in writing, empty the tables with the migrations role (`TRUNCATE core.platform_audit_subject_links, core.platform_audit_subject_erasures, core.platform_audit_identity_holds`), record the case, then downgrade. The audit rows keep their references; older code writes raw ids again.
- **After a restore.** A restore to a point before an erasure brings the user's live links back and lacks the marker: run `erase-user` again before serving traffic.

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
saas-os-operator erase-user --user <id> --tenant <id> [--tenant <id> ...]     [--invited-email <address> ...] --actor <your user id> --confirm <user id>

# Count, then redact, stored webhook errors that still carry a destination URL
saas-os-operator redact-webhook-errors
saas-os-operator redact-webhook-errors --apply

# Count, then replay, a tenant's dead-lettered outbox events (platform.outbox:replay)
saas-os-operator replay-outbox-events --tenant <id> --operator <operator user id> \
    --dead-lettered-since 2026-10-31T00:00:00+00:00 --reason "TICKET-3: quota raised"
saas-os-operator replay-outbox-events --tenant <id> --operator <operator user id> \
    --event-id <id> [--event-id <id> ...] --reason "TICKET-3: quota raised" --apply

# Count, then re-encrypt, a tenant's legacy plaintext webhook signing secrets
# (platform.webhook_secret:reencrypt; finding F7)
saas-os-operator reencrypt-webhook-secrets --tenant <id> --operator <operator user id> \
    --reason "TICKET-5: F7 re-encryption"
saas-os-operator reencrypt-webhook-secrets --tenant <id> --operator <operator user id> \
    --reason "TICKET-5: F7 re-encryption" --apply
# Count, then apply, a product's permission grant migrations (platform.permission_grant:apply)
saas-os-operator apply-permission-grants --operator <operator user id> --namespace my_product \
    --module my_product.grants --all-tenants --reason "TICKET-4: release 4.2"
saas-os-operator apply-permission-grants --operator <operator user id> --namespace my_product \
    --module my_product.grants --all-tenants --reason "TICKET-4: release 4.2" --apply
# Permission grant ledger retention: report (platform.security_retention:report),
# an emergency legal hold (platform.security_retention_hold:manage); a hold is
# released only through the authenticated platform-admin route (see below)
saas-os-operator permission-grant-ledger-retention --operator <operator user id> --all-purged \
    --reason "TICKET-6: yearly retention review"
saas-os-operator hold-permission-grant-ledger --operator <operator user id> --tenant <id> \
    --reference LEGAL-2026-014 --reason "TICKET-7: litigation hold"
```

- A purge without `--setup` must say `--no-product-participants`: otherwise product rows would stay behind the purged tenant. The command is its own process: participants the product registered in its API or worker process are not registered here, which is why `--setup` is required. A `--setup` that registers nothing is refused before the tenant is touched. A purge run with `--no-product-participants` records `product_participants_skipped: true` in its `tenant.purge_completed` metadata, so the override can be found in the audit trail. Participants already registered in the process still run, so `participants_run` can be above 0.
- A purge that fails exits 1 and leaves the tenant `PURGING` with a `tenant.purge_failed` record; a failing product participant shows as `failed_step` `participant:<name>`. Fix the cause and run the same command again: it resumes and re-runs every step. Only a run that reaches `PURGED` records `tenant.purge_completed`.
- An enrolled platform operator is not erased: revoke the operator first.
- In each listed tenant, `erase-user` also replaces the user as the stored initiator of outbox events (`saas_os.initiated_by`, ADR 0061) with `"unavailable"`, whatever the event's status, and reports how many as `outbox_initiators_erased` (also in each tenant's `identity.erasure_membership_removed` audit row, or in an `identity.erasure_outbox_initiators_erased` row where the user had no membership left). The events themselves still run, retry or replay as before. An event being processed at that moment may still reach its consumer with the user id, once; audit rows already written are not changed. A second run reports 0. The search reads the stored text of every event of each listed tenant (there is no index for it), so a tenant with a large outbox makes the command slower; it locks only the events whose stored initiator names the user. It locks those events in id order, as `replay-outbox-events --apply` does, so the two wait for each other rather than deadlock; dispatcher claims skip locked events. `redact-webhook-errors --apply` locks the events it rewrites in no set order, one stored-error prefix after another in one transaction per tenant, so if it runs at the same moment as `erase-user` on the same tenant PostgreSQL may abort one of the two with a deadlock error: the aborted transaction is rolled back, and running the same command again finishes the work.
- In each listed tenant, `erase-user` also deletes the invitations addressed to the person, in every state (pending, accepted, revoked, expired), and reports the total as `invitations_deleted`; each tenant's count is recorded in an `identity.erasure_invitations_erased` audit row (a count, never an address). Core stores no e-mail on the user, so it finds an invitation by: each `--invited-email` you declare (repeatable; compared after trimming and case folding), the e-mail the identity provider verified for the user's sessions, and, in each tenant, the address of an invitation the user accepted there. Declare any other address the person was invited at; an address that is none of these is not found. A pending invitation is deleted with its token, so the link stops working and the tenant can invite the address again. Invitations the person issued or revoked for someone else are kept (they name the person as inviter or revoker); the address is never printed or logged. A second run reports 0. **Limits:** (a) the address of an invitation the user accepted in a tenant is read before the matching rows are locked, so an acceptance committed in between is matched by `accepted_by_user_id` only; (b) an acceptance by the person that commits after a tenant's invitation step survives until the erasure is run again, so run it again if the person could still accept invitations (a still-valid session) while it ran. Matching is exact on `strip().casefold()` of the address: no Unicode normalisation (NFC) and no plus-address handling (`person+tag@x` is not matched by a declared `person@x`); case folding can make distinct non-ASCII addresses equal (for example `ß` and `ss`, the Kelvin sign and `k`), which is why only addresses the operator declares, and ASCII session e-mails, are matched. A session's `verified_email` is a weak source: `revoke_session` clears it and retention deletes old sessions, so a person who logged out contributes nothing; declare any other known address. `--invited-email` puts the address in the process arguments and the shell history; for a sensitive case use the library call or a restricted shell.
- `erase-user` removes the user only from the tenants you list, and Core cannot find the others for you. List them first, with the migrations role: `SELECT tenant_id FROM core.tenant_memberships WHERE user_id = '<user id>'`. The result does not prove completeness. If an erasure fails part way, run the same command again to finish it.
- Nothing here is a protection against the person running it; `--reason` should carry the ticket reference, which the audit records.
- `replay-outbox-events` (outbox decision brief Q2, 2A) returns a tenant's dead-lettered outbox events to `pending`: attempts reset to 0, due now, `last_error` kept. Fix the cause first (raise the quota, repair the destination), then count without `--apply`, then replay. One tenant per run and at most 1000 events; a larger selection is refused, so narrow `--dead-lettered-since` or name the events. `--dead-lettered-since` needs a UTC offset. **It selects by time, not by cause:** every dead-lettered event of the tenant, of any type and for any reason, whose row last changed at or after that time. That includes events dead-lettered on purpose (a receiver's `410`, a malformed event) and events whose stored error `redact-webhook-errors --apply` rewrote later, since that rewrite changes the row. Without `--apply` it returns only a count, not which events. Prefer `--event-id`, with ids listed read-only first (for the deliveries refused by `WEBHOOK_ALLOW_HTTP`, the query in `docs/architecture/WEBHOOK-HTTP-DESTINATIONS-ASSESSMENT.md`, section 7), and put the ticket and the expected count in `--reason`: the audit rows record the count, not the ids. There is no undo: an applied replay is due at once; if the wrong events were replayed, stop the workers before they deliver them. A webhook is delivered to the subscription's destination as it is now, under the same egress checks as any delivery. The operator needs `platform.outbox:replay`, which the first owner holds and grants to whoever should replay. An installation bootstrapped before the permission existed (migration `b3d5f7a9c2e4`) has an owner without it, who cannot grant what they do not hold: give it to that owner with the break-glass command, which reuses the existing active operator and grants only what is missing: `python -m saas_os.api.platform_bootstrap recover --enroll-issuer <issuer> --enroll-subject <subject> --grant platform.outbox:replay --reason "TICKET-4: outbox replay"`; each applied run writes a `platform.outbox.replay` platform row and an `outbox.replay` row in the tenant's audit trail (a count, no event id). A closed tenant is refused. Delivery is at-least-once: a consumer that already acted on an event it had not been able to complete may see it again, and dedupes on the event id. An event dead-lettered `CrashAfterStart:` or `OutcomeUnknown:` (crash recovery D4, `docs/architecture/OUTBOX-STARTED-MARKER.md`) may already have reached its destination: check the destination before replaying it. The dead letter keeps its started marker (`external_started_at`, `external_started_claim`) as evidence; the replay clears it, so record it in the ticket first if needed.
- `reencrypt-webhook-secrets` (finding F7) encrypts, in place, the signing secrets of a tenant's webhook subscriptions that predate field encryption (stored without the `efv1:` prefix). The secret's value does not change, so receivers need nothing. **Procedure:** (1) find the tenants: count read-only, as the migrations role, `SELECT tenant_id, count(*) FROM core.webhook_subscriptions WHERE signing_secret NOT LIKE 'efv1:%' GROUP BY tenant_id` (a release that logs `webhook_signing_secret_legacy_plaintext` on delivery also names them); (2) take a database backup; (3) run without `--apply` and check the count; (4) run with `--apply`. The output is counts only; no secret is ever printed or logged. Every run first checks the operator's permission (a refusal is recorded as a `denied` platform row). With `--apply` the command then checks the field-encryption key (an encrypt-and-decrypt round trip); a missing or unusable key stops it before any tenant or subscription row is read (`WebhookSecretReencryptionKeyError`). A run without `--apply` locks no row. Each new ciphertext is decrypted again and compared with the stored secret before the row changes; any mismatch rolls the whole tenant back (`WebhookSecretReencryptionError`) and nothing changes. One tenant per run, at most 1000 subscriptions; run again for the rest. A second run finds nothing to do. Each applied run writes one `platform.webhook_secret.reencrypt` platform row (the count) and one `webhook_subscription.secret_reencrypted` row per subscription in the tenant's audit trail. A closed tenant is refused. The operator needs `platform.webhook_secret:reencrypt`; an owner bootstrapped before it existed (migration `c5e8a1d3f7b2`) gets it with `python -m saas_os.api.platform_bootstrap recover ... --grant platform.webhook_secret:reencrypt`. **Recovery:** if deliveries fail to sign after a run, the key the worker uses differs from the one the command used: give the worker the key version recorded in the envelopes, or restore the backup of step 2. Plaintext stays accepted at run time until a later release refuses it.
- `apply-permission-grants` (ADR 0060, option C) adds the permissions a product release declares (`docs/CONSUMER-GUIDE.md` section 8) to the named role of each existing tenant. Run it after the product's own migrations, which register the permissions. `--module` names the module whose `PERMISSION_GRANT_MIGRATIONS` holds the list (`module:ATTRIBUTE` for another name); `--tenant <id>` or `--all-tenants` (every tenant that is not deleted, purging or purged; suspended ones included). Without `--apply` it changes nothing and prints, per tenant, how many migrations it would apply, how many grants it would add and how many are already present. With `--apply` the run first writes a started platform row whose id is the `run_id`, then runs each tenant in its own transaction under the tenant's advisory lock, then writes a completed platform row (`partial: true` if a tenant failed); the output gives the `run_id` and the outcome per tenant (`changed`, `unchanged`, `tenant_closed`, `tenant_not_found`, `failed`). It never prints a role or permission name. The operator needs `platform.permission_grant:apply`, which the first owner holds and grants. A declaration that grants an authority permission, names an unregistered permission, or edits a migration already applied somewhere is refused before any tenant changes, with a `denied` platform row.
  - **Before the first run**, inventory the installation read-only, with the migrations role: `SELECT resource, action FROM core.permissions ORDER BY 1, 2;` the roles that would receive grants, `SELECT r.name, count(*) FROM core.roles r JOIN core.tenants t ON t.id = r.tenant_id WHERE t.status NOT IN ('deleted', 'purging', 'purged') GROUP BY r.name;` how many of them already hold a declared permission (the expected `already_present`), `SELECT count(*) FROM core.role_permissions rp JOIN core.roles r ON r.id = rp.role_id JOIN core.permissions p ON p.id = rp.permission_id WHERE r.name = 'admin' AND p.resource = 'my_product.reports' AND p.action = 'read';` and tenants by status, `SELECT status, count(*) FROM core.tenants GROUP BY status;`. The dry run must agree with these counts.
  - **Recovery.** A tenant that failed is reported in `failed_tenant_ids` and was rolled back completely (no grant without its audit and ledger rows). Fix the cause and run the same command again: tenants already applied report `unchanged`, the failed ones are applied. If the process stopped part way, run it again the same way: the stopped run has a started platform row and no completed row, and every ledger row it wrote names that started row. A grant made by mistake is revoked per tenant by its administrator (`role_permission:revoke`); the ledger keeps the migration as applied, so no later run re-adds it. What was applied where: `SELECT tenant_id, migration_id, outcome, grants_added, applied_at FROM core.permission_grant_applications WHERE namespace = 'my_product';` (migrations role). The ledger is security history (`SECURITY_RETAIN`): a tenant purge keeps its rows next to the tombstone, and the application can neither change nor delete them; do not delete them by hand. They hold ids, a digest, an outcome and counts, never a name or personal data.
  - **Retention (owner policy of 2026-11-02; ADR-0045 amendment of 2026-11-02).** A tenant's ledger rows become eligible for expiry two calendar years after the tenant reached `PURGED`, unless a legal hold is active. The purge time is the `platform.tenant.purge_transition` platform audit row with `to_status = purged`, written in the same transaction as the status change. `permission-grant-ledger-retention` reports, per tenant (`--tenant <id>`, or `--all-purged` in id order, 1000 at a time; continue with `--after <last tenant id>` while `more` is true), its status (`eligible`, `retention_running`, `legal_hold`, `purge_time_unknown`, `purge_time_ambiguous`, `not_purged`, `tenant_not_found`), its ledger row count, active holds, purge time and expiry, and the eligible rows' total (`eligible_ledger_rows`) and digest (`eligible_digest`). It is read only and writes one platform audit row with the counts and the digest. The operator needs `platform.security_retention:report`; `platform.permission_grant:apply` does not allow it. `purge_time_unknown` (a tenant purged before the platform row existed) and `purge_time_ambiguous` (more than one purge row) are never eligible: investigate before any decision.
  - **Legal hold.** When the person responsible for a legal matter asks for the ledger of a tenant to be preserved, place a hold: `hold-permission-grant-ledger --tenant <id> --reference <matter reference> --reason "<ticket>"`. The reference is an opaque matter id (letters, digits and `._:-`, at most 100 characters), never a person's name. The output gives the `hold_id`; record it in the ticket. A hold can also be placed through the platform-admin route `POST /v1/platform/permission-grant-ledger/holds`. When the matter closes, the hold manager releases it through the authenticated route only, with a fresh session: `POST /v1/platform/permission-grant-ledger/holds/<hold id>/release` with `{"reason": "<ticket>"}` (owner decision of 2026-11-03: no command releases a hold; `release-permission-grant-ledger-hold` is removed). The release records the session that made it, which is what lets a later approval tell who released holds in its scope; a release made by the removed command has no such evidence and blocks its tenant's deletion. Retrying the same release with the same reason returns it again (`"replay": true`). `GET /v1/platform/permission-grant-ledger/holds` lists holds (`release_authenticated` per released hold). A released hold stays as history; a release is never repeated. Placing and releasing each write a platform audit row. Active holds, read only, with the migrations role: `SELECT id, target_tenant_id, reference, placed_at FROM core.permission_grant_ledger_holds WHERE released_at IS NULL ORDER BY placed_at;`. A release is one-way: the database refuses any change to a released hold. Placing and releasing need `platform.security_retention_hold:manage` (neither the report permission nor `platform.permission_grant:apply` allows it). The first owner receives `platform.security_retention:report` at bootstrap, and **not** `platform.security_retention_hold:manage` (separation of duties, owner decision of 2026-11-02); see "Granting legal-hold management" below. An owner bootstrapped before migration `a9c3e5f7b1d4` gets the report permission with `python -m saas_os.api.platform_bootstrap recover ... --grant platform.security_retention:report`.
  - **Granting legal-hold management (separation of duties, owner decision of 2026-11-02).** `platform.security_retention_hold:manage` is withheld from the first owner (`NOT_GRANTED_AT_BOOTSTRAP`). Anti-amplification (a person may grant only a permission they hold) then means nobody can grant it from inside the product, the owner included, and the person who receives it cannot pass it on unless they also hold `platform.authority:manage`. It is granted only out of band, by whoever holds the deployment's database credentials, with the break-glass command:
    1. **Authorisation, outside SaaS OS.** A written request from the person responsible for legal or security matters names the security operator (by OIDC issuer and subject, never by e-mail), states that they are independent of the platform owner who runs routine operations, and is approved by someone other than that owner. Record it in a ticket.
    2. **Grant**, in the backend container: `docker compose -f docker-compose.prod.yml exec backend python -m saas_os.api.platform_bootstrap recover --enroll-issuer <issuer> --enroll-subject <subject> --grant platform.security_retention_hold:manage --reason "TICKET-10: legal-hold manager" --confirm-production`. An existing active operator is reused; otherwise one is enrolled. Grant nothing else in the same call: the security operator should not hold the report permission or `platform.authority:manage`.
    3. **Check**: `SELECT o.id, o.user_id, g.granted_at FROM core.platform_grants g JOIN core.platform_operators o ON o.id = g.operator_id WHERE g.permission = 'platform.security_retention_hold:manage' AND g.revoked_at IS NULL;` and the `platform.grant.create` platform audit row (actor type `system`, the ticket as reason).
    4. **Removal**: a platform owner revokes the grant with the ordinary revoke operation, or suspends the operator.
    *Limits.* This is a procedural control, not a technical boundary against the database credential holder, who could write grant rows directly (`saas_os/core/platform_authority/bootstrap.py`, "Neither is a security boundary"). The operator commands take a declared `--operator` id, not an authenticated identity, so separation between the hold manager and other operators is only as strong as the custody of the application and migrations credentials and the review of the platform audit log. In particular, hold management is "the one identity the platform owner cannot create" only while the owner holds neither container access (the break-glass `recover --grant` above) nor a database credential (a grant row written directly): an owner with either can give it to an account of their own, which also defeats the two-party designation of the approver register.
  - **Deletion of expired ledger rows is disabled (separation of duties, owner decisions of 2026-11-02 and 2026-11-03).** `--apply` of the procedure below is refused with `LedgerDeletionDisabledError` (`deletion_disabled`, exit 1, one `denied` platform row) and deletes nothing. The authenticated approval mechanism of `docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md` is implemented; enabling deletion is a separate owner-approved change after an independent review of the implementation and of the approver register, with the procedure rehearsed once on a disposable database. Expired rows remain in the ledger meanwhile (retention beyond two years, not loss of evidence).
  - **The approver eligibility register (owner decisions of 2026-11-03).** Separate accounts never prove separate people, so only an approver enrolled in the append-only register may approve a deletion or authorise its execution. Every write is an authenticated platform-admin request with a fresh session; the deployment must require multi-factor login (`PLATFORM_OPERATOR_REQUIRE_MFA=true`), or the writes are refused `multi_factor_not_enforced`. Paths below are under `/v1/platform/permission-grant-ledger/approver-register`; every body is `{"ticket_ref": "...", "reason": "..."}` plus the fields named, and refuses any other field. References are opaque record ids, never names or personal data.
    1. **Designation (two parties).** After the organisation's governing body designates a representative in writing: a platform owner (`platform.authority:manage`) proposes, `POST representatives/<user id>/proposals` with `designation_ref` (the resolution) and `valid_until` (at most 12 months); within 72 hours an independent security operator (`platform.security_retention_hold:manage`, without `platform.authority:manage`), neither the proposer nor the subject, confirms: `POST representatives/<user id>/proposals/<proposal id>/confirm`. The representative needs `platform.security_retention:report` to act. While a proposal for a subject is pending, any other proposal for that subject is refused `proposal_already_pending` (up to 72 hours); to correct a mistaken proposal, wait for it to expire, or confirm it and then revoke the designation.
    2. **Enrolment.** After an independent verification that the subject is a distinct natural person, the representative enrols them: `POST approvers/<user id>/enrolments` with `natural_person_ref`, `verification_ref`, `authorisation_ref`, `valid_until` (at most 12 months, more than 120 days away) and optionally `renews_entry_id`. The enrolment is usable 120 days after it is recorded. Nobody enrols themselves; holders of `platform.authority:manage` or of hold management, and representatives, are never enrolled. One renewal of the current enrolment may overlap it, while both remain valid: record it at least 120 days before the current one ends, or eligibility lapses in between. **When a designation expires** (owner decision of 2026-11-03, final closure), every enrolment it authorised is suspended at that instant (state `suspended` in `GET approver-register/eligibility`), and approvals or execution authorisations those approvers gave earlier are refused at their next use (`approver_not_eligible`, `authorizer_not_eligible`). A new designation revives none of them and a suspended enrolment cannot be renewed (`invalid_renewal`): verify each approver again and enrol them under the new designation with a new `verification_ref` (reusing the old one is refused `verification_not_fresh`); each new enrolment is usable 120 days later. `verification_not_fresh` compares reference strings only: the reviewer must reconcile each re-enrolment's `verification_ref` with a new external verification record. To avoid a gap, have the governing body renew the designation and re-enrol the approvers under it at least 120 days before the current designation ends.
    3. **Revocation**, immediate: an enrolment by an active representative (`.../enrolments/<entry id>/revoke`) or by an independent security operator (`.../security-revoke`); a designation by a platform owner (`representatives/<user id>/designations/<entry id>/revoke`) or by an independent security operator (`.../security-revoke`). The same transaction invalidates every outstanding approval and execution authorisation of the affected approvers (a designation's revocation suspends every enrolment it authorised); the response gives the counts.
    4. **Review, every quarter.** A reviewer who is neither a platform owner, a representative nor an approver exports the register (`GET approver-register`, JSON, `platform.audit:read`) and the per-enrolment state (`GET approver-register/eligibility`), reconciles every entry with its external records, checks that each entry's audit row is in the ADR-0053 digest chain, and checks every approval and authorisation row against the register as it stood then. Findings go to the governing body. The review before any change that enables deletion is stricter (final closure): see "Conditions before deletion may be enabled" below.
    *Limits.* Anyone holding the application database credential can insert register entries, approvals and audit rows directly, and anyone holding the migrations credential can also disable the triggers; a platform owner who holds either credential can therefore defeat the two-party designation alone. The migrations credential must be under dual control (owner decision of 2026-11-03, final closure): two separately authorised people, no shared personal accounts, independently authorised credential access, audited access and use, never a declared operator id instead; if the deployment cannot enforce that, deletion stays disabled. Dual control of the application credential is recommended. SaaS OS cannot enforce or check either; detection is the platform audit log, the ADR-0053 digests and the quarterly review.
  - **Requesting, approving and authorising a deletion (authenticated; owner decisions of 2026-11-03).** Paths are under `/v1/platform/permission-grant-ledger`. (1) Report (`POST retention-report`, or the command) and record `eligible_ledger_rows`, `eligible_digest` and the eligible tenant ids. (2) A reporter who does not hold `platform.authority:manage` requests: `POST deletion-requests` with `tenant_ids` (every one eligible with rows), `eligible_ledger_rows`, `eligible_digest`, `reason`; it expires after 72 hours unless approved. (3) A registered approver who is not the requester and released no hold in scope approves with a fresh, multi-factor session, restating the count and digest: `POST deletion-requests/<id>/approve`; the approval is single use and valid for 72 hours. (4) Another registered approver, of a different verified person (the requester may do it), authorises the execution: `POST deletion-requests/<id>/execution-authorizations`; the authorisation is valid for 60 minutes and never past the approval. Its `id` goes to the command. Retrying any step with identical content returns the same record (`"replay": true`); anything else is a `409` with a fixed code. A tenant with a release made by the removed command is refused (`unauthenticated_release_in_scope`).
  - **Schema downgrades keep the evidence.** The downgrade of `a9c3e5f7b1d4` refuses while any hold exists (active or released), and the downgrade of `e8f3b1d5a2c7` refuses while the ledger holds any row: both fail with an error naming the table, in one transaction, and change nothing. The downgrade of `a9c3e5f7b1d4` also refuses while any `core.platform_grants` row names `platform.security_retention:report` or `platform.security_retention_hold:manage`, and the downgrade of `d7e2a9c4f1b6` while any names `platform.permission_grant:apply`, revoked or not; on an installation bootstrapped after them, treat them as irreversible. **Deliberate downgrade (manual, separately approved; not a routine rollback):** (1) obtain the owner's written approval naming the rows to be removed and why, and check the retention report and active holds (a row under an active hold or not yet eligible must not be removed without legal sign-off); (2) take a database backup and export the rows (`COPY (SELECT * FROM core.permission_grant_ledger_holds) TO STDOUT WITH CSV HEADER`, the same for `core.permission_grant_applications`) to the ticket's evidence store; (3) as the migrations role, in one transaction, insert a platform audit row recording the removal (counts and the ticket; no personal data) and remove the rows; (4) run the downgrade. No command performs this; it is not a deletion path for expired rows.
  - **Deleting expired permission grant ledger rows (owner decision B of 2026-11-02; manual, migrations role; `--apply` currently disabled, see above).** Since the owner decisions of 2026-11-03 the deletion takes an execution authorisation: `docker compose -f docker-compose.prod.yml exec -e MIGRATIONS_DATABASE_URL backend python -m saas_os.ops.permission_grant_ledger_expiry --execution-authorization <id> --reason "TICKET-9: retention expiry" --confirm-production` re-checks the whole chain under the tenant locks (the people, both enrolments, releases, scope, count and digest, expiry, consumption and invalidation) and writes one `verify` platform row; it deletes nothing. With `--apply` it is refused `deletion_disabled`. Once deletion is enabled, `--apply` deletes exactly the bound rows and consumes the approval and the authorisation in the same transaction; the person running it is not authenticated (`runner: migrations_role_unauthenticated`). The declared-operator form below only reports: its `--apply` can never delete. Earlier steps, kept for the report: There is no `saas-os-operator` command and no platform permission for it, and the runtime role must never get `DELETE` on the ledger. The procedure is `python -m saas_os.ops.permission_grant_ledger_expiry`, which connects **only** with `MIGRATIONS_DATABASE_URL` and refuses a role that does not own the ledger or that is `DATABASE_URL`'s user. It is never part of a tenant purge. Steps:
    1. **Ticket.** Open a ticket for the expiry run; it names the operator and is the `--reason` of every step. The operator must be an enrolled platform operator holding `platform.security_retention:report`; the command records that id. The id is a declaration, not an authenticated identity: whoever holds the migrations credential can name any such operator, as with every operator command, so it does not prove who ran the command. The controls are possession of the migrations credential and the audit record; run it only as the person named in the ticket.
    2. **Report** (runtime role, audited): `saas-os-operator permission-grant-ledger-retention --operator <operator user id> --all-purged --reason "TICKET-9: retention expiry"` (or `--tenant <id>`; page with `--after` while `more` is true). Record `eligible_ledger_rows`, `eligible_digest` and the eligible tenant ids in the ticket. Investigate any `purge_time_unknown` or `purge_time_ambiguous` tenant; they are never deleted.
    3. **Backup and export** the eligible tenants' rows to the ticket's evidence store, as the migrations role: `COPY (SELECT * FROM core.permission_grant_applications WHERE tenant_id IN (<eligible ids>)) TO STDOUT WITH CSV HEADER`.
    4. **Dry run** with the migrations role, in the backend container, the URL passed for this one process only (as for the AI configuration role below): `docker compose -f docker-compose.prod.yml exec -e MIGRATIONS_DATABASE_URL backend python -m saas_os.ops.permission_grant_ledger_expiry --operator <operator user id> --tenant <id> [--tenant <id> ...] --reason "TICKET-9: retention expiry" --confirm-production`. Name the same tenants as the report (or `--all-purged` with the same `--after`). It must print the same `eligible_ledger_rows` and `eligible_digest`; it writes nothing.
    5. **Apply**: the same command with `--apply --confirm-rows <eligible_ledger_rows> --confirm-digest <eligible_digest>`. In one transaction it locks the tenants, re-checks eligibility and legal holds with the database clock, refuses (`confirmation_mismatch`, exit 1, nothing deleted) unless the count and digest are exactly the confirmed ones, deletes those rows, and writes one `platform.permission_grant_ledger.expired_delete` platform row for the run (its id is the printed `run_id`) and one per tenant. A hold placed since the report, or a later purge row, changes the digest: run the report again.
    6. **Close the ticket** with the `run_id`. Check: `SELECT target_tenant_id, metadata FROM core.platform_audit_log WHERE action = 'platform.permission_grant_ledger.expired_delete' AND outcome = 'success' ORDER BY created_at;`.
    Exit codes: 0 done, 1 refused or failed (only the error type is printed; nothing was deleted), 2 invalid input. A refusal writes a `denied` platform row (`not_authorized`, `invalid_request`, `deletion_disabled`, `confirmation_mismatch`); a refused connection writes nothing. The procedure has not been exercised on production data.
  - **Conditions before deletion may be enabled (owner decisions of 2026-11-03, final closure).** The two-party designation of the approver register is accepted. A designation's expiry suspends its approvers at once; a new designation revives nothing, and only a new enrolment under it, with fresh verification (a new `verification_ref`) and its own 120 days, restores them; approvals and authorisations they gave earlier fail at their next use. Before any change that enables deletion: (1) an independent reviewer, a natural person other than the implementer, the platform owner, the representative proposer, the representative, every approver and the migrations credential custodian, inspects the exact final head of that change and its security evidence (a review of an earlier commit is insufficient); (2) the migrations credential is under dual control: two separately authorised people, no shared personal accounts, independently authorised and audited credential access and use, never a declared operator id instead. If the deployment cannot enforce dual control, deletion stays disabled. SaaS OS can enforce neither condition; they are procedure and infrastructure, recorded with the change.
- **Unknown outcomes** (`last_error` starting `OutcomeUnknown:` or `ConsumerTimedOut:`, since 2026-11-01): the external request may already have taken effect. Check the destination before replaying: the relay's or Resend's logs and dashboard by `Message-ID` (`<notification.{event id}@...>`) for an e-mail, the receiver's logs by `event_id` for a webhook. `OutcomeUnknown: <type> (unclassified)` is a bare timeout that a consumer let escape (owner decision D of 2026-11-01): check that consumer's destination the same way, and ask its owners to classify the timeout (`ConfirmedNotSentError` or `AmbiguousOutcomeError`). Replay only what did not arrive. A replay runs the event once even when its idempotency window has closed; a Resend send replayed more than 24 hours after the first attempt is a new email. `outbox_event_outcome_unknown` and `outbox_event_retry_window_closed` in the worker's logs name the event id only. `outbox_event_outcome_unrecorded` (error level, since 2026-11-02) means the worker could not record a failed attempt, the database being unavailable: the event stays claimed and runs again automatically when its lease expires (`last_error` then starts `LeaseExpired:`), even if that attempt's outcome was unknown. Check the destination for that event id before the lease runs out (default 15 minutes) if a repeat would matter. `OutcomeUnknown: record_after_send_<type> (record)` is a notification e-mail that was sent but whose notification row was not recorded: replaying it sends the e-mail again. `OutcomeUnknown: the idempotency window closed ...` can also come from a `last_error` whose deadline could not be read (it then counts as passed); check the destination as for any unknown outcome.
- `redact-webhook-errors` (ledger row 900) finds the webhook destination errors stored before pull request #110, whose text holds the destination URL with any credential or token in it: outbox `last_error` values in every tenant, closed ones included, and Redis dead-letter entries. Without `--apply` it only counts (`outbox_events`, `dead_letter_entries`). With `--apply` it replaces each matching text with `<error type>: Invalid webhook URL (redacted: the stored message contained the destination URL).` and changes nothing else: no status, attempt, schedule or other entry. The old text cannot be recovered, so keep a backup if you need it. A second run finds 0. It needs `REDIS_URL` as well as `DATABASE_URL`, and writes no audit record. Backups and log stores taken before the run still hold the old text.

## Holding a tenant's AI (ADR-0054 amendment of 2026-11-09)

Stop one tenant's new AI requests for a security, contractual, spending or operator reason, whatever the tenant's policy says. This is not a provider switch (`ai-provider-status`, which affects every tenant) and not a tenant setting (the tenant cannot lift it).

- **Who.** An enrolled operator holding `platform.ai_tenant_hold:manage` (reading needs `platform.ai_config:read`). The first owner of a new installation has it; on an existing installation grant it with the break-glass `platform_bootstrap recover --grant platform.ai_tenant_hold:manage` (no operator is granted a new permission automatically).
- **Credential.** Setting and lifting are AI configuration writes: put `PLATFORM_CONFIG_DATABASE_URL` in that one command's environment, exactly as in "AI configuration role" below. Without it the command fails with `DatabaseConfigurationError` and changes nothing, so keep the procedure within reach before an incident, not during it. Reading needs only the application role.
- **Hold.** `saas-os-operator ai-hold-set --tenant <tenant id> --hold-reason <security|contractual|spending|operator> --operator <user id>`. Effect: from the commit, every new request, retry and fallback of that tenant is refused with `tenant_ai_held`; a call already under way completes and settles (usage is recorded). Holding a held tenant, or an unknown tenant, is refused and changes nothing.
- **Check.** `saas-os-operator ai-hold-show --tenant <tenant id> --operator <user id>`. The platform audit log shows `platform.ai_tenant_hold.set`; the tenant's own audit log shows `ai.policy.hold` and each refusal the hold causes. If the tenant row is missing but the platform row exists, the second write failed after the commit (look for the log line `ai_tenant_hold_tenant_audit_failed`): the hold is in force and the platform row is the evidence.
- **Lift.** `saas-os-operator ai-hold-lift --tenant <tenant id> --operator <user id>`. The tenant's own policy applies again from the commit. To change the reason, lift and set again.
- **Rollback of the migration.** `c8e5a2f7d1b3` refuses to downgrade while any hold row or any grant of the permission exists; lifting a hold is not deleting it. Removing rows to allow a downgrade is a separately approved manual procedure.

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

## AI model prices

Gap 21a (ADR-0054 amendment of 2026-11-09). Merged, not yet released; this section applies from the release that contains migration `a4c8e1f3b7d5`. A price is the platform's own estimate of what a model costs. `estimated_cost` on an attempt is estimated platform spend, never an amount a provider invoices.

- **Who.** A platform operator holding `platform.ai_provider:manage`. Reading the prices needs `platform.ai_config:read`. No tenant permission does either.
- **No operator command yet.** `saas-os-operator` has no price command. Both changes are calls to `set_model_price` and `confirm_model_price` in `saas_os/control_plane/inference/config/service.py`, made from Python in the place and with the credential the `ai-*` commands use: the platform-configuration URL in that one process's environment, exactly as in "AI configuration role (ADR-0056)" above. `saas-os-operator ai-show` prints every price with its rates and its `reviewed_at`.

  ```python
  import uuid
  from saas_os.control_plane.inference.config import service as ai_config
  from saas_os.core.authority import UserCaller

  ai_config.confirm_model_price(
      provider_key="<provider key>",
      model_id="<model id>",
      pricing_version="<version>",
      caller=UserCaller(uuid.UUID("<your user id>")),
      reason="<ticket and what you checked>",
  )
  ```

  The repository ships and tests no script around this call. The calls themselves are tested in `tests/control_plane/inference/test_ai_pricing_integration.py`.
- **Change a price.** Call `set_model_price` with a new `pricing_version` and the `effective_from` from which it applies. A version is never rewritten: a call that names an existing version is refused (`pricing_version_exists`). The optional rates are `cached_input_per_million`, `cache_write_per_million`, `per_request` and `unit_rates`; leave out a rate the provider does not charge. The new version is recorded as confirmed at the moment it is written.
- **Confirm a price.** After checking a version against the provider's current price list, call `confirm_model_price`. It sets `reviewed_at` to now and changes nothing else. If the provider's price differs, do not confirm: write a new version.
- **How often.** A price counts as current for 24 hours after its last confirmation. `AI_PRICE_MAX_AGE_SECONDS` (`1` to `86400`) can shorten that, never lengthen it. Past the limit the price is `stale`; a price that was never confirmed is `unverifiable`.
- **After the upgrade.** Every price written before migration `a4c8e1f3b7d5` has no confirmation time and is `unverifiable`. Confirm each price that is still correct, once, after the upgrade.
- **What happens when a price is not current.** Before Gap 21b, nothing: no request is refused on a price, and attempts are priced as before. From the release that contains migration `f1b9d3e7a5c2` (Gap 21b, on a branch), every request of a tenant with a budget is refused (`budget_pricing_unavailable`) while its model's price is stale, unverifiable or missing. Confirm every price in use before giving any tenant a budget, and then at least once a day ("AI budgets" below).
- **Cost unknown.** An attempt has no `estimated_cost` (NULL, never zero) when its model has no price in effect, when its token counts are unknown, or when it used a unit the price has no rate for, for example cache-write tokens under a price without `cache_write_per_million`. The tenant usage report counts these attempts separately.
- **Check.** Each change writes one `platform.ai_provider.configure` row to the platform audit log, with `change` set to `set_model_price` or `confirm_model_price`, the provider, the model and the pricing version. A call by a user without the permission writes a `denied` row and changes nothing. A call refused for its input (an unknown provider, model or version, an existing version, an invalid rate) changes nothing and writes no row.
- **Downgrade.** Below `a4c8e1f3b7d5` the new rates and every confirmation time are lost. Every price row, with its input, output and cached-input rates, stays.

## AI budgets

Gap 21b (ADR-0054 amendment of 2026-11-10). Implemented on the branch `feat/ai-budget-reserve-settle`; not merged, not released. This section applies from the release that contains migration `f1b9d3e7a5c2`. A budget limits **estimated platform spend** (tokens times the listed rates of "AI model prices" above), never what a provider invoices; reconcile with the provider's invoices outside SaaS OS, and keep the provider's own account-wide spend limit set as well (Gap 21 option D).

- **Who.** Plan budgets, overrides and the release of an unknown outcome need the platform permission `platform.ai_budget:manage`. A first owner bootstrapped by a release that contains it holds it; an existing deployment grants it deliberately (a platform owner's grant, or `python -m saas_os.api.platform_bootstrap recover --grant platform.ai_budget:manage` as in "Platform operators"). A tenant user with `ai.budget:manage` can only lower the tenant's own budget; `ai.usage:read` reads it.
- **No operator command yet.** As for prices, these are Python calls in `saas_os/control_plane/inference/budget_admin.py`: `set_plan_budget`, `set_tenant_budget_override` and `clear_tenant_budget_override` on the platform-configuration credential ("AI configuration role (ADR-0056)"); `release_budget_reservation` on the application database credential (it changes the tenant's own rows). Tested in `tests/control_plane/inference/test_ai_budget_integration.py`; no script ships.
- **Before the first budget.** Confirm the price of every model the tenant can use (`confirm_model_price`), and arrange to confirm each one at least every 24 hours. A budgeted request on a model whose price is older is refused (`budget_pricing_unavailable`). Nothing confirms prices automatically.
- **Set a plan budget.** `set_plan_budget(plan_id, budget_version=..., currency=..., monthly_amount=Decimal(...), caller=..., reason=..., effective_from=None)`. A version is never rewritten (`version_exists`); a change is a new version. `currency=None, monthly_amount=None` records that the plan has no budget from then on. A tenant already in the month keeps the lower of its current limit and the new one: a lower plan budget applies at once, a higher one from the next UTC month.
- **Raise one tenant.** `set_tenant_budget_override(tenant_id, currency=..., amount=Decimal(...), reason="contractual" | "support" | "incident" | "operator", expires_at=<aware datetime, at most 366 days ahead>, caller=...)`. It replaces the plan budget at once and lapses by itself at `expires_at`; `clear_tenant_budget_override` ends it earlier. The tenant's own cap still applies. The platform audit row commits with the change; the tenant's row (`ai.budget.override_set`, `.override_clear`) follows in a second transaction, and if that write fails `ai_budget_override_tenant_audit_failed` is logged and the override stands.
- **Unknown outcomes.** When a provider call may have been accepted but its result is unknown (`InferenceOutcomeUnknownError`, a timeout after sending, an interrupted call, or an attempt abandoned by a process that died), its worst case stays charged in the month's `retained` amount and the reservation is `expired_unknown`. Find them with the migrations or a read-only role: `SELECT id, request_id, attempt_id, amount, currency, created_at FROM control_plane.ai_budget_reservations WHERE tenant_id = '<tenant>' AND state = 'expired_unknown'`. Check the provider's own usage records for that request (the attempt row's `provider_request_id`, when one was received). Only if the provider did not charge it, call `release_budget_reservation(tenant_id, reservation_id, caller=..., reason="<ticket and what you checked>")`. It writes the tenant's `ai.budget.reservation_release` row and the platform `platform.ai_budget_reservation.release` row in the same transaction. Nothing releases these by time: if no one checks, the tenant's month stays charged with the worst case, which is the safe side.
- **What the tenant sees.** Refusals `monthly_budget_exhausted`, `budget_pricing_unavailable`, `budget_currency_conflict`, `budget_unavailable`, `budget_not_configured`, logged as `ai_inference_budget_refused` with the reason only. `read_tenant_budget` and the usage report's `budget` block show the limit, its source and the settled, reserved and retained amounts.
- **Currencies.** One currency per tenant: a plan budget, an override and a cap in different currencies refuse every request of that tenant (`budget_currency_conflict`) until they agree. A month that started in one currency keeps it.
- **`AI_INFERENCE_BUDGET_REQUIRED`.** Owner's rule: `true` in production whenever AI is enabled for any tenant. With it on, a tenant whose plan has no budget and that has no override or cap is refused. Turn it on only after every AI-enabled plan has a budget.
- **Retention.** Periods and reservations are financial records (`FINANCIAL_RETAIN`); the owner's target is 13 months, but no expiry runs yet and the application role cannot delete them. Plan budgets and overrides are kept like other platform decisions.
- **Downgrade.** Below `f1b9d3e7a5c2` is refused while any budget row or any grant of `platform.ai_budget:manage` exists. Removing them deletes financial records: export them first and treat it as a data decision, not a routine step.

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

`/debug/ready` does not prove that the instance can use its data (section 7).
After the upgrade, make one call that needs ZITADEL's keys before resuming
traffic: a sign-in, or a token request with a machine user's credentials.

Rehearsed 2026-10-29 on a disposable copy of this service configuration
(ledger row "Rehearsal of the self-hosted identity runbook"): an instance
created at v4.19.0 kept its users, project, machine credentials and signing
keys through the upgrade to v4.19.5, which ran ten setup steps on start. Both
rollback paths worked there: the v4.19.0 image started against the upgraded
database, and the pre-upgrade backup restored into a new database ran under
v4.19.0. That holds for these two releases only. A rollback to a release
before v4.19.2 also brings back the unsigned Login V2 cookie
(GHSA-jh92-5mrj-p2w2): Login V2 v4.19.0 accepted an unsigned `sessions`
entry in the same rehearsal. Prefer fixing forward.

### 5. Backup

```
python -m saas_os.infra.db.backup.orchestrator run \
    --container saas-os-zitadel-db-1 \
    --admin-database-url-var ZITADEL_BACKUP_DATABASE_URL
```

or let `deploy/saas-os-zitadel-backup.timer` run it daily (see
docs/BACKUP-RESTORE.md's own ZITADEL section for the full pipeline
description). **Also back up the master key itself (the content of the
file `ZITADEL_MASTERKEY_FILE` names, section 5a), separately, through your
own secret-management process** -- it is never part of this pipeline's own
artifact, and a `zitadel-db` backup without its matching masterkey is not a
valid disaster-recovery backup.

### 5a. Master-key file

`zitadel` reads its master key from a file, never from an argument or an
environment variable: `docker-compose.prod.yml` mounts the file named by
`ZITADEL_MASTERKEY_FILE` (in `.env`) as the Compose secret
`zitadel_masterkey`, at `/run/secrets/zitadel_masterkey` in `zitadel` only,
and starts ZITADEL with `--masterkeyFile`. A key passed as `--masterkey` was
readable in the host's process list and in `docker inspect` (ledger,
2026-10-29). Compose refuses to start while `ZITADEL_MASTERKEY_FILE` is unset
or empty.

The file must hold exactly 32 bytes with no trailing newline: ZITADEL does
not trim it and refuses `masterkey must be 32 bytes, but is 33`. It must be
readable by uid 1000, the ZITADEL image's user, and by no other account: a
file only root can read stops ZITADEL with `no master key provided: open
/run/secrets/zitadel_masterkey: permission denied`. Keep it outside the
repository. For a new deployment:

```
sudo install -d -m 0700 /etc/saas-os/secrets
openssl rand -hex 16 | tr -d '\n' | sudo tee /etc/saas-os/secrets/zitadel_masterkey >/dev/null
sudo chown 1000:1000 /etc/saas-os/secrets/zitadel_masterkey
sudo chmod 0400 /etc/saas-os/secrets/zitadel_masterkey
sudo wc -c /etc/saas-os/secrets/zitadel_masterkey     # must print 32
```

and set `ZITADEL_MASTERKEY_FILE=/etc/saas-os/secrets/zitadel_masterkey` in
`.env`. The directory stays root-only; the container reads the file through
its own mount. On a host where uid 1000 is a person's login account, that
account can read the key: keep such accounts to operators.

**Moving an existing deployment.** The key must stay the same value: a new
one cannot read the existing database (section 7). Copy it from `.env`
into the file without putting it on a command line:

```
sudo install -d -m 0700 /etc/saas-os/secrets
grep '^ZITADEL_MASTERKEY=' .env | cut -d= -f2- | tr -d '\n' \
    | sudo tee /etc/saas-os/secrets/zitadel_masterkey >/dev/null
sudo chown 1000:1000 /etc/saas-os/secrets/zitadel_masterkey
sudo chmod 0400 /etc/saas-os/secrets/zitadel_masterkey
sudo wc -c /etc/saas-os/secrets/zitadel_masterkey     # must print 32
```

If the value in `.env` is quoted, remove the quotes from the file and check
`wc -c` again. Set `ZITADEL_MASTERKEY_FILE`, remove the `ZITADEL_MASTERKEY`
line from `.env`, then `docker compose -f docker-compose.prod.yml up -d zitadel`. Before resuming
traffic, make the key-dependent check of section 7 (a sign-in or a token
request). Rolling back to a Compose file that still reads `ZITADEL_MASTERKEY`
needs that line back in `.env`, with the same value.

Rehearsed 2026-10-29 with the real `docker-compose.prod.yml` of the
previous release and of this one, on one disposable Compose project (ledger
row "Rehearsal of the master-key move and the bootstrap token"). Before the
move the key was in the host's process list. Running the new file without
`ZITADEL_MASTERKEY_FILE` was refused (`required variable
ZITADEL_MASTERKEY_FILE is missing a value`) and left the running `zitadel`
untouched. After the copy above (`wc -c` printed 32) and `up -d zitadel`,
the key was in neither the process list nor `docker inspect`, and the
bootstrap token, a project, a machine user's `client_credentials` token and
a password session all worked. Rolling back to the previous file and
forward again worked too. Not shown there: `chown`, `chmod` and the
root-only directory, because the host was Windows; ownership was checked
separately (a root-only file is refused, uid 1000 with mode 0400 works).

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

Restoring `zitadel-db` alone is not sufficient: put the *exact* key that
was active when the backup was taken (from your own separate secret
backup, step 5) into the restore target's master-key file (section 5a)
before starting `zitadel` against the restored data.

A wrong masterkey does not stop `zitadel` from becoming ready. In the
2026-10-29 rehearsal (v4.19.5, restored database, a different 32-character
key) the container started and reported healthy, the discovery document
and the JWKS answered `200`, and nothing was logged at start. Every request
that needs a key failed:

- API calls with a personal access token: `401` `Errors.Token.Invalid
  (AUTH-7fs1e)`;
- the token endpoint: `500` `server_error`;
- logged per request: `CRYPT-OhN2u` "failed to decrypt value" and
  `error decrypting value`.

So `/debug/ready` and the healthcheck prove nothing about the key. After a
restore, make one call that needs ZITADEL's keys before resuming traffic: a
sign-in, or a token request with a machine user's credentials. If it fails
with the log lines above, the masterkey is wrong. In the rehearsal, stopping
the instance and starting it with the right key brought everything back.
That run lasted minutes; nothing shows how long a wrong-key instance can run
before it writes state under that key, so stop it at once.

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
in the master-key file (section 5a) and restart `zitadel` against the
existing, already-provisioned `zitadel-db`.** ZITADEL's own signing keys
and other sensitive state already at rest in that database are encrypted
under the *old* key; restarting against a new one is not an approved
recovery or rotation procedure for that existing data and this
repository makes no claim it produces a working instance, a readable
database, or a safe security boundary. Nothing in this repository
performs, or has verified, an in-place re-encryption of `zitadel-db`
under a new masterkey. In the 2026-10-29 rehearsal a different key against
an existing database looked healthy and could not decrypt any stored secret
(section 7): the restart does not fail visibly, which is why it must not be tried.

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
  read -rs BOOTSTRAP_PAT      # paste the token; it is not echoed or kept in history
  printf '%s' "$BOOTSTRAP_PAT" | docker run --rm -i -v <volume>:/bootstrap busybox:1.36.1 \
    sh -c 'cat > /bootstrap/bootstrap.pat'
  unset BOOTSTRAP_PAT
  docker compose -f docker-compose.prod.yml up zitadel-bootstrap
  ```

  `printf` is a shell builtin, so the token never appears in a process list;
  typing it into the command line instead would keep it in shell history.
- ZITADEL's own event log records every use of the token; keep it
  (Independent evidence, ADR-0045).
- Rehearsed 2026-10-29 on `docker-compose.prod.yml`'s identity services
  (ledger row "Rehearsal of the master-key move and the bootstrap token"),
  with ZITADEL's Management API and a drill-only `IAM_OWNER` machine user
  standing in for the console: the first token's expiry equalled
  `ZITADEL_BOOTSTRAP_PAT_EXPIRATION`; after deleting it, a call with it
  answered `401`; with the file emptied as above, `zitadel-bootstrap` printed
  "bootstrap token revoked (empty token file): nothing to provision" and
  exited `0`; a new one-day token written as above let it run again and
  print the same `OIDC_CLIENT_ID`; deleted, that token answered `401` too.
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
signs every user out of Login V2; this repository does not sign with it.
Login V2 v4.19.5 still *verifies* with it: its list of verification keys is
every value of `ZITADEL_SESSION_COOKIE_SECRET` plus the configured API
credential (`getSessionCookieSecrets()`), and in the 2026-10-29 rehearsal a
cookie entry signed with the login-client private key was accepted while the
variable was set. Signing uses the first listed value only. So rotating the
private key signs no one out, and a holder of the private key can sign a
cookie entry. That entry still needs a real session ID and session token to
show an account, and the private key already authenticates as the login
client, so treat a disclosed private key as the larger incident.

**Rotation.** The variable takes a comma-separated list: the first value
signs, every value verifies.

1. Generate a new value and deploy `<new>,<old>` to every replica:
   `docker compose -f docker-compose.prod.yml up -d zitadel-login`.
2. After the longest Login V2 session lifetime has passed, deploy `<new>`
   alone.

Rehearsed 2026-10-29 against Login V2 v4.19.5 with real ZITADEL sessions:
before rotation only the old value's entries were accepted; after step 1
entries signed with either value; after step 2 only the new value's. An
unsigned entry was refused throughout.

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
So the identity provider's secrets (ZITADEL's database password, the
first-instance admin password, `ZITADEL_SESSION_COOKIE_SECRET`) reach only the
identity services that use them. The ZITADEL master key is not in `.env`: `.env`
holds only the path of its file (`ZITADEL_MASTERKEY_FILE`, section 5a of
"Self-hosted identity operations"), mounted into `zitadel` alone.

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
