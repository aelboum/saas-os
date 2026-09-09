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
  (`ZITADEL_ISSUER_URL`). No password, token, or code is ever given to
  this command.

### 2. Required identity information

The platform keys a user on the OIDC `(issuer, subject)` pair
(`core.external_identities`). Obtain both from the identity provider:

- `--owner-issuer`: the exact `iss` value the provider writes into its ID
  tokens. For ZITADEL this is the instance URL (for example
  `https://acme-abc123.zitadel.cloud`), the same value as
  `ZITADEL_ISSUER_URL`. A trailing slash is stripped, matching
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
