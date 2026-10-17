# ADR-0056: A dedicated database identity for installation-wide AI configuration writes

Status: Accepted (2026-10-17). The repository owner delegated this decision for the AI inference release on 2026-10-17, conditional on the final implementation still supporting it. The implementation was reviewed against D1–D6 and its PostgreSQL integration evidence (see "Implementation evidence"), and it does. Implemented on branch `feat/ai-inference` and merged into `main` by pull request #53 (`0598a9a`).
Date: 2026-10-17
Supersedes / Superseded by: — (narrowly amends ADR-0045 section 9a; takes up the "second database role" ADR-0045 lists as a separate decision, for the AI configuration tables only)
Related: ADR-0002 (tenant isolation), ADR-0012 (secrets), ADR-0021 (transport encryption), ADR-0030 (no `SECURITY DEFINER`, RLS sweep), ADR-0045 (platform authority, sections 9a and 9b), ADR-0050 (operator commands), ADR-0054 (AI inference, sections 5 and 6), ADR-0055 (destination authorization).

## Context

- The installation-wide AI configuration lives in six global tables in `control_plane`: `ai_providers` (endpoint `base_url`, credential name `credential_ref`, credential binding `credential_origin`), `ai_models`, `ai_aliases`, `ai_endpoint_trust`, `ai_destination_policy` and `ai_model_prices`. They decide where tenant content is sent and which deployment secret is attached to it.
- Before this ADR the application role (`APP_DB_USER`) held `SELECT, INSERT, UPDATE` on all six (migrations `e4b8c2d6f1a3`, `c5d7e9f1a2b4`). Every sanctioned write went through `run_platform_change` (platform authorization and platform audit in one transaction), but nothing in the database stopped any other code running as the application role, in any request or job, from writing the rows directly. `app.tenant_id` is a session setting any session can change; it is not an identity.
- ADR-0045 section 9a: one database principal for all application code. ADR-0045 lists a second database role as a separate decision. ADR-0030 forbids `SECURITY DEFINER` functions in SaaS-OS schemas.
- Every write to these tables is made by an operator command (`saas-os-operator ai-*`, ADR-0050). There is no HTTP route and no job that writes them. The API process and the worker only read them.
- A platform change authorizes the operator inside its own transaction and holds the user, operator and grant rows `FOR SHARE` until commit (ADR-0045 section 5, ADR-0031 section 3a). PostgreSQL requires `UPDATE` privilege on at least one column of a table for any row-locking clause, `FOR SHARE` included. This was checked against PostgreSQL 16.

## Options considered

1. **A dedicated identity and connection for these writes, the application role reduced to `SELECT`.** A real database boundary. Costs a second role, credential and connection, and a migration that changes grants.
2. **A write-only tenant-context exclusion policy.** It rests on `app.tenant_id`, which any session can clear. Defence in depth only; rejected as the boundary.
3. **Accept the application-layer boundary.** Leaves the gap open.

## Decision

Option 1, for the six AI configuration tables only.

### D1. Two identities

| Identity | Configuration | Used by | On the six AI tables |
|---|---|---|---|
| Application role (`APP_DB_USER`) | `DATABASE_URL` | API, worker, bootstrap commands, every operator command, all reads | `SELECT` only. `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE` revoked |
| Platform-configuration role (`PLATFORM_CONFIG_DB_USER`, default `saas_os_platform_config`) | `PLATFORM_CONFIG_DATABASE_URL` | only the transaction of a declared AI configuration operation, inside `saas-os-operator ai-*` | `SELECT, INSERT, UPDATE`. No `DELETE`, no `TRUNCATE` |

The migrations role stays the table owner. The platform-configuration role owns nothing, is `NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION`, and is neither a member of the application role nor the reverse.

### D2. The platform-configuration role's complete privileges

- `CONNECT` on the database; `USAGE` on schemas `core` and `control_plane`.
- The six AI tables: `SELECT, INSERT, UPDATE`.
- `core.platform_audit_log`: `INSERT`, and `SELECT` on `id` and `created_at` (the ORM reads server defaults back with `RETURNING`). Nothing else on it.
- The authorization reads, columns only: `core.users (id, is_active)`, `core.platform_operators (id, user_id, status)`, `core.platform_grants (id, operator_id, permission, revoked_at)`. It cannot read any other column of those tables, any identity data (`core.external_identities`), any tenant table, or the contents of the audit log.
- **Row locks without writes.** Because `FOR SHARE` needs `UPDATE` on one column, the role holds `UPDATE` on one timestamp column of each of those three tables (`users.updated_at`, `platform_operators.updated_at`, `platform_grants.granted_at`). A `BEFORE UPDATE ... FOR EACH STATEMENT` trigger on each table, running `core.refuse_platform_config_role_update()` (a plain `SECURITY INVOKER` PL/pgSQL function), raises whenever the current role is the platform-configuration role. The lock is allowed, every update by that role is refused. No `SECURITY DEFINER` function is introduced.

Nothing else: no tenant table, no other platform table, no sequence, no function `EXECUTE` beyond PUBLIC defaults.

### D3. Which code may use the privileged connection

- `saas_os.infra.db.platform_config` builds the engine from `PLATFORM_CONFIG_DATABASE_URL` through `SecretsProvider`. A missing or invalid value raises `DatabaseConfigurationError`; there is no fallback to `DATABASE_URL`, and `DATABASE_URL` never falls back to it.
- Before the engine is first returned, `validate_platform_config_role()` checks, on the connection itself, that the connected role is not a superuser, not `BYPASSRLS`, not `CREATEROLE`, owns none of the six tables and is not a member of their owner, holds `INSERT` and `UPDATE` on `control_plane.ai_providers`, and holds table-level `INSERT`, `UPDATE`, `DELETE` or `TRUNCATE` on nothing but the six tables and `INSERT` on `core.platform_audit_log`. Otherwise `UnsafeDatabaseRoleError`. Messages name a role or a table, never a URL.
- The only importer of `platform_config_session_scope()` is `saas_os.core.platform_authority.transactions` (an architecture test pins it). It is not exported by `saas_os.infra.db`, `saas_os.core.platform_authority` or any public facade.
- `run_platform_change` uses the privileged session only for operations in `PLATFORM_CONFIGURATION_OPERATIONS` (`ai_provider.configure`, `ai_endpoint_trust.configure`, `ai_policy.configure`), a frozen set declared in code beside the operation table. The caller names an operation; it cannot choose the connection. The authorization (platform permission, in the transaction, under the row locks), the change and the success audit row all run on that one connection and commit together. Naming the operation is not enough: the process also needs the privileged credential, and the operator needs the permission.
- A refusal's `denied` row is still written by `record_platform_refusal()` on the application connection, as for every other platform operation.
- Reads (`ai-show`, the inference path) use the application role.

### D4. Process separation

- The API (`build_platform_app` lifespan) and the worker refuse to start if `PLATFORM_CONFIG_DATABASE_URL`, the role's password `PLATFORM_CONFIG_DB_PASSWORD`, or the `_FILE` form of either is in their environment, or if `SecretsProvider` resolves either. A long-running, tenant-serving process never holds the credential.
- `validate_application_role()`, which every startup path already runs, additionally refuses to start if the application role, or any role it is a member of, holds `INSERT`, `UPDATE`, `DELETE` or `TRUNCATE` on any of the six tables. A deployment whose grants drifted fails closed instead of running with the old boundary.
- The credential is given only to the operator-command invocation, for example `docker compose exec -e PLATFORM_CONFIG_DATABASE_URL backend saas-os-operator ai-provider-create ...`, which sets it for that one process. It must not be in the `.env` file a backend or worker container loads.

### D5. Provisioning

- The migration (`f6a2c8e4b1d9`) creates the role `NOLOGIN` if it does not exist (it needs `CREATEROLE` on the migrations role; otherwise the operator creates the role first). It refuses to continue if an existing role is a superuser, `BYPASSRLS`, the application role, or in a membership with it. It never sets a password.
- A role created `NOLOGIN` leaves AI configuration writes impossible until an operator enables it: `ALTER ROLE saas_os_platform_config LOGIN PASSWORD '<placeholder>'`. Fail closed.
- `saas_os/infra/db/init/02-create-platform-config-role.sh` creates it with `LOGIN` on the first boot of a fresh local volume when `PLATFORM_CONFIG_DB_PASSWORD` is set, and does nothing otherwise.
- Rotation: `ALTER ROLE ... PASSWORD`, then update the secret. Revocation: `ALTER ROLE ... NOLOGIN`, which disables configuration writes and nothing else.
- Downgrade restores the previous grants (application role `SELECT, INSERT, UPDATE`), revokes everything from the platform-configuration role and drops the triggers and function. It does not drop the role, a cluster-level object that may hold grants in another database; the runbook gives the command.

### D6. Unchanged

The tenant RLS policies, the platform tables' tenant-context exclusion policies, the credential allowlist (`AI_PROVIDER_CREDENTIALS`), credential-binding confirmation, egress rules and the audit table's immutability are unchanged. The application role keeps every other privilege it had, including on `core.platform_operators` and `core.platform_grants`.

## Threat model

Prevented, by the database:
- Any code running as the application role, in a request, a job or an operator command, inserting, updating or deleting rows of the six tables, whatever `app.tenant_id` holds. Repointing a provider's `base_url` and `credential_origin` together, changing `credential_ref`, adding a private-endpoint trust entry or opening a destination policy now requires the platform-configuration credential.
- The platform-configuration role writing anything else: tenant data, platform grants, operators, users, or updating or deleting audit rows.

Prevented, by configuration checks that fail closed:
- An API or worker process holding the privileged credential.
- A deployment running new code with the old grants.
- A privileged URL that points at a superuser, a `BYPASSRLS` role, the table owner, or a role with extra write privileges.

Still trusted:
- **Platform authority itself.** The application role still holds `INSERT` and `UPDATE` on `core.platform_operators` and `core.platform_grants` (ADR-0045 section 9a, unchanged). Code running as the application role can still enroll an operator and grant `platform.ai_provider:manage`. It still cannot write the AI tables: that needs the platform-configuration credential, which the API and worker processes never hold. Moving the platform tables behind a separate identity is a separate, platform-wide decision.
- The process that runs `saas-os-operator ai-*` and the person running it. That process holds both credentials. Inside it, any code could use the privileged connection.
- The migrations role, superusers and anyone who holds the platform-configuration password.
- The secret store and the deployment's environment handling.

### Residual-risk decisions for the AI inference release (2026-10-17, delegated by the owner)

- **Platform operator and grant tables: accepted residual risk.** They stay under the ADR-0045 §9a application-role model for this release. A database identity for platform authority itself is a separate, platform-wide follow-up, not part of this decision.
- **The operator command is a trusted administrative boundary: accepted.** The privileged connection is not protected from code running inside that process, or from privileged users on the operator host. `docs/RUNBOOKS.md` ("AI configuration role") describes how to keep the credential out of `.env`, shell history and the long-running processes, and what remains exposed.
- **Future protected tables: non-blocking follow-up.** The startup check covers exactly the six tables in `PROTECTED_TABLES`. It is not a general protection for platform tables. How future installation-wide tables are protected (explicit grants, an entry in the list, possibly narrower default privileges in `control_plane`) is to be decided separately.

## Implementation evidence (2026-10-17, branch `feat/ai-inference`)

Real PostgreSQL 16:
- `tests/infra/db/test_platform_config_boundary_integration.py`: the application role is refused `INSERT`, `UPDATE`, `DELETE` and `TRUNCATE` on each of the six tables with `app.tenant_id` unset, empty, a random tenant and the all-zero id, and can still read them. The platform-configuration role inserts and updates, cannot delete or truncate, cannot write tenant, platform-authority or audit rows beyond appending, cannot read other columns, and can lock the authorization rows `FOR SHARE`. Both role checks refuse drifted grants, memberships and roles of the wrong kind.
- `tests/infra/db/test_platform_config_identity_migration.py`: the grants at head, the downgrade and upgrade again, a missing role created `NOLOGIN`, and an unsafe or related existing role refused.
- `tests/control_plane/inference/test_ai_configuration_integration.py` (ADR-0056 section): a configuration change runs as the platform-configuration role with its audit row; a failed change leaves no row and no audit row; without the credential, or with the application URL in its place, nothing changes; a tenant transaction cannot repoint a provider.
- `tests/architecture/test_platform_config_boundary.py`, `tests/architecture/test_tenant_session_boundary.py` (the new opener is scanned), and unit tests for the API and worker startup refusal.

Negative controls, each restored byte for byte afterwards:
- Removing the application-role `REVOKE` from the migration fails all 24 application-role write tests.
- Removing the triggers fails the three lock-column update tests.
- Removing the protected-table check from `validate_application_role()` fails the drift and membership tests.
- Routing the configuration operations to the application connection fails the configuration tests with `permission denied`.
- Removing the lifespan credential check fails its unit tests.

## What would be difficult to change later

- Every deployment now provisions a second login role and credential to change AI configuration.
- New installation-wide configuration tables must be added to the protected list (`PROTECTED_TABLES`, defined in `saas_os/infra/db/role_guard.py` and imported by `saas_os/infra/db/platform_config.py`) and get explicit grants. The `control_plane` default privileges still grant the application role writes on new tables.
