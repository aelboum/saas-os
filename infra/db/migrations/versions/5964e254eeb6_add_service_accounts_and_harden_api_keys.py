"""add service accounts, service account roles, and harden api keys

Revision ID: 5964e254eeb6
Revises: ccdbecd208f7
Create Date: 2026-09-11 00:00:00.000000

Architecture research: universal multi-tenant tenancy, Phase E
("Principal + Service Accounts + API Key Hardening"). See
`core/identity/models.py::ServiceAccount`, `core/rbac/models.py
::ServiceAccountRole`, and `core/api_keys/models.py::ApiKey` for the full
models this migration's schema enforces, and `core/rbac/authorization.py
::can()`/`core/api_keys/service.py::validate_api_key()` for how they are
evaluated.

Additive to the existing schema (Phases 3.1-3.4, A-D), nothing removed or
retyped -- two new tables, plus a widened CHECK/new nullable column on
each of three existing tables:

`core.service_accounts` -- tenant-owned, RLS-protected (identical
single-GUC `app.tenant_id` policy shape `infra.db.rls.tenant_rls_statements()`
applies to every other tenant-owned table, nothing hierarchy-aware, no
`app.authorized_tenant_ids`). `(tenant_id, name)` and `(tenant_id, id)`
are both unique -- the latter is the composite-FK target
`core.service_account_roles` and the hardened `core.api_keys` reference
below, mirroring `core.tenant_memberships`'s own `UniqueConstraint("tenant_id", "id")`
(`770fe52b8468`). `status` is `CHECK`-constrained to exactly
`'active'`/`'disabled'`, mirroring `core.tenants.status`'s and
`core.membership_roles.scope`'s own CHECK-constrained-string convention
(`e99c76057719`, `a17e5f3c9d84`).

`core.service_account_roles` -- tenant-owned, RLS-protected, the
machine-principal analogue of `core.membership_roles`
(`81ac56902107`) -- same `scope` CHECK, same composite-FK discipline:
`(tenant_id, service_account_id) -> service_accounts(tenant_id, id)` and
`(tenant_id, role_id) -> roles(tenant_id, id)`, so a row can never
reference a service account or role belonging to a different tenant, and
(unlike `core.membership_roles`, which can exist for a user's membership
in more than one tenant) a service account's own single, fixed
`tenant_id` means this composite FK can only ever be satisfied at that
one tenant -- see `ServiceAccountRole`'s own docstring.

`core.deny_grants`/`core.delegation_grants` (`ccdbecd208f7`, `c92f4b81e6a7`)
-- `principal_type`/`delegate_principal_type` widen from `('user',
'system')` to `('user', 'system', 'service_account')`; each gains a new
nullable `principal_service_account_id`/`delegate_service_account_id`
column (a plain FK to `core.service_accounts.id`) rather than widening
`principal_id`/`delegate_principal_id`'s own FK target, since a single
column cannot validly reference two different tables depending on a
row's own type -- see `DenyGrant`/`DelegationGrant`'s own docstrings.
Every existing row's `principal_type`/`delegate_principal_type` is
already `'user'` or `'system'`, a subset of the new, wider CHECK, so no
existing row is affected; the new column defaults `NULL` for every
existing row, satisfying the new three-way pairing CHECK exactly as the
old two-way pairing CHECK already required. The active-lookup and
active-unique indexes on both tables are dropped and recreated to
additionally cover the new column (a service-account-principal row's
`principal_id`/`delegate_principal_id` is `NULL`, and SQL `NULL` never
equals `NULL` in a uniqueness check, so omitting the new column would
silently make the uniqueness guard inert for every such row).

`core.api_keys` (`3a2522ccb9ea`) -- `user_id` becomes nullable (was
`NOT NULL`); gains a new nullable `service_account_id` column with its
own composite FK `(tenant_id, service_account_id) ->
core.service_accounts(tenant_id, id)` (mirroring the table's existing
`(tenant_id, user_id) -> core.tenant_memberships(tenant_id, user_id)` FK
exactly) and a `ck_api_keys_single_owner` CHECK requiring exactly one of
`user_id`/`service_account_id`; gains a new nullable `expires_at` column
(`NULL` = no expiry, Phase 4.1's original, unchanged behavior). Every
existing row already has `user_id` set and `service_account_id` NULL,
satisfying the new CHECK; `expires_at` defaults `NULL` for every existing
row, so no existing key gains an expiry it did not already have.

No RLS change to any other table, no `app.authorized_tenant_ids`, no
`SECURITY DEFINER`, no `BYPASSRLS`, no change to
`validate_application_role()`.

Runs via the privileged bootstrap/migration role
(`infra.db.config.get_migrations_database_config()`, `MIGRATIONS_DATABASE_URL`)
-- never the restricted application runtime role. No explicit GRANT
statement is needed for the two new tables: `e99c76057719`'s `ALTER
DEFAULT PRIVILEGES IN SCHEMA core` rule already grants the runtime role
(`APP_DB_USER`, default `saas_os_app`) SELECT/INSERT/UPDATE/DELETE on any
new table the same bootstrap role creates in `core`; altering an existing
table's columns/constraints needs no new GRANT at all (grants are
table-level, not column-level).

Downgrade reverses every change in the opposite dependency order (drop
the `api_keys`/`deny_grants`/`delegation_grants` additions first, then
`service_account_roles`, then `service_accounts` last, since the first
three reference the last two). Reverting `api_keys.user_id` to `NOT NULL`
and the two CHECK constraints back to their original, narrower shape
will fail if a service-account-owned row already exists at downgrade
time -- the same, already-established reversibility scope every other
migration in this repository has (a schema-shape downgrade, not a
data-migration): run this downgrade only against a database with no
Phase-E-shaped data yet, exactly like every prior migration's own
downgrade in this repository assumes for its own additions.

Hand-written, not autogenerated -- `infra/db/migrations/env.py`'s
`target_metadata` remains `None` deliberately (see that file's docstring).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from infra.db.rls import tenant_rls_statements

# revision identifiers, used by Alembic.
revision: str = "5964e254eeb6"
down_revision: str | Sequence[str] | None = "ccdbecd208f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- core.service_accounts ------------------------------------------
    op.create_table(
        "service_accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "tenant_id", sa.Uuid(), sa.ForeignKey("core.tenants.id"), nullable=False, index=True
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("tenant_id", "name", name="uq_service_accounts_tenant_name"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_service_accounts_tenant_id_id"),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')", name="ck_service_accounts_valid_status"
        ),
        schema="core",
    )
    for statement in tenant_rls_statements("service_accounts", schema="core"):
        op.execute(statement)

    # --- core.service_account_roles -------------------------------------
    op.create_table(
        "service_account_roles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("core.tenants.id"), nullable=False),
        sa.Column("service_account_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.String(length=20), nullable=False, server_default="self"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint(
            "service_account_id", "role_id", name="uq_service_account_roles_service_account_role"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_account_id"],
            ["core.service_accounts.tenant_id", "core.service_accounts.id"],
            name="fk_service_account_roles_tenant_service_account",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["core.roles.tenant_id", "core.roles.id"],
            name="fk_service_account_roles_tenant_role",
        ),
        sa.CheckConstraint(
            "scope IN ('self', 'subtree')", name="ck_service_account_roles_valid_scope"
        ),
        schema="core",
    )
    for statement in tenant_rls_statements("service_account_roles", schema="core"):
        op.execute(statement)

    # --- core.deny_grants: widen principal_type to include 'service_account'
    op.add_column(
        "deny_grants",
        sa.Column(
            "principal_service_account_id",
            sa.Uuid(),
            sa.ForeignKey("core.service_accounts.id"),
            nullable=True,
        ),
        schema="core",
    )
    op.drop_constraint("ck_deny_grants_principal_type", "deny_grants", schema="core", type_="check")
    op.create_check_constraint(
        "ck_deny_grants_principal_type",
        "deny_grants",
        "principal_type IN ('user', 'system', 'service_account')",
        schema="core",
    )
    op.drop_constraint(
        "ck_deny_grants_principal_pairing", "deny_grants", schema="core", type_="check"
    )
    op.create_check_constraint(
        "ck_deny_grants_principal_pairing",
        "deny_grants",
        "(principal_type = 'user' "
        " AND principal_id IS NOT NULL AND principal_service_account_id IS NULL) "
        "OR (principal_type = 'system' "
        " AND principal_id IS NULL AND principal_service_account_id IS NULL) "
        "OR (principal_type = 'service_account' "
        " AND principal_id IS NULL AND principal_service_account_id IS NOT NULL)",
        schema="core",
    )
    op.drop_index("ix_deny_grants_tenant_principal", table_name="deny_grants", schema="core")
    op.create_index(
        "ix_deny_grants_tenant_principal",
        "deny_grants",
        ["tenant_id", "principal_type", "principal_id", "principal_service_account_id"],
        schema="core",
    )
    op.drop_index("uq_deny_grants_active_unique", table_name="deny_grants", schema="core")
    op.create_index(
        "uq_deny_grants_active_unique",
        "deny_grants",
        [
            "tenant_id",
            "principal_type",
            "principal_id",
            "principal_service_account_id",
            "scope_mode",
            "permission_id",
        ],
        unique=True,
        schema="core",
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    # --- core.delegation_grants: widen delegate_principal_type to include
    # 'service_account' (delegator side unchanged -- see module docstring)
    op.add_column(
        "delegation_grants",
        sa.Column(
            "delegate_service_account_id",
            sa.Uuid(),
            sa.ForeignKey("core.service_accounts.id"),
            nullable=True,
        ),
        schema="core",
    )
    op.drop_constraint(
        "ck_delegation_grants_delegate_principal_type",
        "delegation_grants",
        schema="core",
        type_="check",
    )
    op.create_check_constraint(
        "ck_delegation_grants_delegate_principal_type",
        "delegation_grants",
        "delegate_principal_type IN ('user', 'system', 'service_account')",
        schema="core",
    )
    op.drop_constraint(
        "ck_delegation_grants_delegate_pairing", "delegation_grants", schema="core", type_="check"
    )
    op.create_check_constraint(
        "ck_delegation_grants_delegate_pairing",
        "delegation_grants",
        "(delegate_principal_type = 'user' "
        " AND delegate_principal_id IS NOT NULL AND delegate_service_account_id IS NULL) "
        "OR (delegate_principal_type = 'system' "
        " AND delegate_principal_id IS NULL AND delegate_service_account_id IS NULL) "
        "OR (delegate_principal_type = 'service_account' "
        " AND delegate_principal_id IS NULL AND delegate_service_account_id IS NOT NULL)",
        schema="core",
    )
    op.drop_index(
        "ix_delegation_grants_tenant_delegate", table_name="delegation_grants", schema="core"
    )
    op.create_index(
        "ix_delegation_grants_tenant_delegate",
        "delegation_grants",
        [
            "tenant_id",
            "delegate_principal_type",
            "delegate_principal_id",
            "delegate_service_account_id",
        ],
        schema="core",
    )
    op.drop_index(
        "uq_delegation_grants_active_unique", table_name="delegation_grants", schema="core"
    )
    op.create_index(
        "uq_delegation_grants_active_unique",
        "delegation_grants",
        [
            "tenant_id",
            "delegate_principal_type",
            "delegate_principal_id",
            "delegate_service_account_id",
            "scope_mode",
            "permission_id",
        ],
        unique=True,
        schema="core",
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    # --- core.api_keys: nullable user_id + service_account_id owner +
    # expires_at (architecture research Phase E -- "API Key Hardening")
    op.alter_column("api_keys", "user_id", existing_type=sa.Uuid(), nullable=True, schema="core")
    op.add_column(
        "api_keys", sa.Column("service_account_id", sa.Uuid(), nullable=True), schema="core"
    )
    op.create_foreign_key(
        "fk_api_keys_tenant_service_account",
        "api_keys",
        "service_accounts",
        ["tenant_id", "service_account_id"],
        ["tenant_id", "id"],
        source_schema="core",
        referent_schema="core",
    )
    op.add_column(
        "api_keys",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        schema="core",
    )
    op.create_check_constraint(
        "ck_api_keys_single_owner",
        "api_keys",
        "(user_id IS NOT NULL AND service_account_id IS NULL) "
        "OR (user_id IS NULL AND service_account_id IS NOT NULL)",
        schema="core",
    )


def downgrade() -> None:
    # --- core.api_keys ----------------------------------------------------
    op.drop_constraint("ck_api_keys_single_owner", "api_keys", schema="core", type_="check")
    op.drop_column("api_keys", "expires_at", schema="core")
    op.drop_constraint(
        "fk_api_keys_tenant_service_account", "api_keys", schema="core", type_="foreignkey"
    )
    op.drop_column("api_keys", "service_account_id", schema="core")
    op.alter_column("api_keys", "user_id", existing_type=sa.Uuid(), nullable=False, schema="core")

    # --- core.delegation_grants --------------------------------------------
    op.drop_index(
        "uq_delegation_grants_active_unique", table_name="delegation_grants", schema="core"
    )
    op.create_index(
        "uq_delegation_grants_active_unique",
        "delegation_grants",
        [
            "tenant_id",
            "delegate_principal_type",
            "delegate_principal_id",
            "scope_mode",
            "permission_id",
        ],
        unique=True,
        schema="core",
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.drop_index(
        "ix_delegation_grants_tenant_delegate", table_name="delegation_grants", schema="core"
    )
    op.create_index(
        "ix_delegation_grants_tenant_delegate",
        "delegation_grants",
        ["tenant_id", "delegate_principal_type", "delegate_principal_id"],
        schema="core",
    )
    op.drop_constraint(
        "ck_delegation_grants_delegate_pairing", "delegation_grants", schema="core", type_="check"
    )
    op.create_check_constraint(
        "ck_delegation_grants_delegate_pairing",
        "delegation_grants",
        "(delegate_principal_type = 'user' AND delegate_principal_id IS NOT NULL) "
        "OR (delegate_principal_type = 'system' AND delegate_principal_id IS NULL)",
        schema="core",
    )
    op.drop_constraint(
        "ck_delegation_grants_delegate_principal_type",
        "delegation_grants",
        schema="core",
        type_="check",
    )
    op.create_check_constraint(
        "ck_delegation_grants_delegate_principal_type",
        "delegation_grants",
        "delegate_principal_type IN ('user', 'system')",
        schema="core",
    )
    op.drop_column("delegation_grants", "delegate_service_account_id", schema="core")

    # --- core.deny_grants ---------------------------------------------------
    op.drop_index("uq_deny_grants_active_unique", table_name="deny_grants", schema="core")
    op.create_index(
        "uq_deny_grants_active_unique",
        "deny_grants",
        ["tenant_id", "principal_type", "principal_id", "scope_mode", "permission_id"],
        unique=True,
        schema="core",
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.drop_index("ix_deny_grants_tenant_principal", table_name="deny_grants", schema="core")
    op.create_index(
        "ix_deny_grants_tenant_principal",
        "deny_grants",
        ["tenant_id", "principal_type", "principal_id"],
        schema="core",
    )
    op.drop_constraint(
        "ck_deny_grants_principal_pairing", "deny_grants", schema="core", type_="check"
    )
    op.create_check_constraint(
        "ck_deny_grants_principal_pairing",
        "deny_grants",
        "(principal_type = 'user' AND principal_id IS NOT NULL) "
        "OR (principal_type = 'system' AND principal_id IS NULL)",
        schema="core",
    )
    op.drop_constraint("ck_deny_grants_principal_type", "deny_grants", schema="core", type_="check")
    op.create_check_constraint(
        "ck_deny_grants_principal_type",
        "deny_grants",
        "principal_type IN ('user', 'system')",
        schema="core",
    )
    op.drop_column("deny_grants", "principal_service_account_id", schema="core")

    # --- core.service_account_roles / core.service_accounts ---------------
    op.drop_table("service_account_roles", schema="core")
    op.drop_table("service_accounts", schema="core")
