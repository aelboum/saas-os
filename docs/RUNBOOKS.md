# Operational Runbooks

Operator procedures for a running deployment. Each section is a single,
self-contained procedure. Nothing here contains a real credential; every
value shown is a placeholder.

## First-tenant bootstrap (post-audit F-02)

Provisions the platform's first tenant and its owner without an HTTP
surface, through the existing Core services, as the restricted
application database role:

```
python -m api.tenant_bootstrap \
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
  `infra.db.validate_application_role()` first and refuses to proceed
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
  `core.identity.provider`.
- `--owner-subject`: the owner's `sub` claim at that issuer (ZITADEL: the
  user's numeric user ID, visible in the ZITADEL console). This is an
  identifier, not a secret, and is never logged or written to audit
  metadata by the bootstrap.

On the owner's first `/auth/login`, `api/auth/routes.py` resolves the
same pair to the same `core.users` row the bootstrap created -- there
is exactly one identity model.

### 3. Dry run

```
python -m api.tenant_bootstrap --tenant-name "Acme Ltd" \
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
    python -m api.tenant_bootstrap \
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
8. verification through `core.rbac.can()` for every granted permission

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
  `core.audit_log.list(tenant_id)` contains `tenant.bootstrap_created`,
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
(`core.rbac.can()` denies by default). Re-run the identical command: it
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
(`api/tenant_bootstrap.py`) -- today `tenant:read_status`, the one
permission the external API enforces. From the backend container:

```python
from core.rbac import can
can(actor_id=<owner user id>, tenant_id=<tenant id>, action="read_status", resource="tenant")  # True
can(actor_id=<owner user id>, tenant_id=<tenant id>, action="activate",
    resource="control_plane.self_learning.adaptation")  # False -- no AI tool authority
```

### 12. Verifying tenant isolation

Bootstrap is ordinary tenant data: `core.tenant_memberships`,
`core.roles`, `core.role_permissions`, `core.membership_roles` remain
`FORCE ROW LEVEL SECURITY` tables, written only through
`tenant_session_scope()` by the `NOSUPERUSER NOBYPASSRLS` role. With a
second tenant bootstrapped for a different owner, the first owner's
session gets `404` from `/v1/tenants/<other tenant id>/status` (not a
member: the identical non-enumerating response), and
`core.rbac.can()` returns `False` for every action in the other tenant.
`tests/api/test_tenant_bootstrap_integration.py` proves all of this
against a real PostgreSQL.

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
production `.env`'s `OIDC_CLIENT_ID`, then
`docker compose -f docker-compose.prod.yml up -d --force-recreate backend`
so `backend` picks it up. `OIDC_ISSUER_URL` should already be set to
`https://<IDENTITY_PUBLIC_DOMAIN>`; `OIDC_CLIENT_SECRET` stays empty (a
public, PKCE-only client, matching Phase 1's local default).

### 2. Re-running bootstrap safely

Safe to re-run at any time (list-before-create by name, unchanged from
Phase 1) -- it finds the existing `saas-os` project and `saas-os-backend`
application and reuses the same `OIDC_CLIENT_ID`, printing it again
rather than creating a duplicate. Only re-copy the value into `.env` if
it changed (it will not, on an existing instance).

### 3. ZITADEL restart

```
docker compose -f docker-compose.prod.yml restart zitadel
```

Existing SaaS-OS sessions remain valid throughout (`core/identity/sessions.py`
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

### 5. Backup

```
python -m infra.db.backup.orchestrator run \
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
python -m infra.db.backup.orchestrator restore \
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
the single most common misconfiguration -- `core/identity/oidc.py`'s
issuer check rejects every token otherwise). From the `backend`
container, confirm the same discovery document is reachable directly
(proving the `identity-edge` alias + TLS trust, not just Caddy's own
public leg):

```
docker compose -f docker-compose.prod.yml exec backend python -c \
    "import httpx; r = httpx.get('https://<IDENTITY_PUBLIC_DOMAIN>/.well-known/openid-configuration', timeout=5); print(r.status_code)"
```

(substitute the real value for `<IDENTITY_PUBLIC_DOMAIN>` -- it is not
itself part of `backend`'s own persistent environment, deliberately:
`core/identity` never reads it, only the already-configured
`OIDC_ISSUER_URL`, which equals `https://<IDENTITY_PUBLIC_DOMAIN>` by
operator convention.) A 200 here proves the exact mechanism this ADR's
Phase 3 depends on: `backend` reaching ZITADEL directly over
`identity-edge`, trusting ZITADEL's self-signed internal certificate via
`SSL_CERT_FILE` (already set in `backend`'s own environment), without
hairpinning through Caddy.
