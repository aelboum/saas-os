"""create my_product.items

Revision ID: 0001_my_product_items
Revises:
Create Date: 2026-10-11 00:00:00.000000

The pattern every tenant-owned product table follows:

1. the product's own schema (ADR-0016), never `core`;
2. a non-null `tenant_id` foreign key to `core.tenants.id`, indexed;
3. forced Row-Level Security through `saas_os.infra.db.rls.tenant_rls_statements`
   -- the same DDL SaaS OS's own tenant tables use, not a hand-written
   policy;
4. grants to the restricted application role, and nothing wider.

Step 4 is what lets the application read the table at all. The
application role is created by the deployment (`APP_DB_USER`, default
`saas_os_app`) as NOSUPERUSER NOBYPASSRLS; SaaS OS refuses to start under
a role that can bypass RLS. Migrations run as a different, privileged
role, which is why the grant has to be explicit.
"""

import os
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from saas_os.infra.db.rls import tenant_rls_statements

revision: str = "0001_my_product_items"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "my_product"
_DEFAULT_APP_ROLE = "saas_os_app"


def _app_role() -> str:
    role = os.environ.get("APP_DB_USER", _DEFAULT_APP_ROLE)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", role):
        raise ValueError(f"APP_DB_USER must be a plain SQL identifier, got: {role!r}")
    return role


def upgrade() -> None:
    app_role = _app_role()

    op.execute(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}")
    op.create_table(
        "items",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("core.tenants.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema=_SCHEMA,
    )
    op.create_index("ix_my_product_items_tenant_id", "items", ["tenant_id"], schema=_SCHEMA)

    for statement in tenant_rls_statements("items", schema=_SCHEMA):
        op.execute(statement)

    op.execute(f'GRANT USAGE ON SCHEMA {_SCHEMA} TO "{app_role}"')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {_SCHEMA}.items TO "{app_role}"')


def downgrade() -> None:
    app_role = _app_role()

    op.execute(f'REVOKE ALL ON {_SCHEMA}.items FROM "{app_role}"')
    op.drop_table("items", schema=_SCHEMA)
    op.execute(f'REVOKE USAGE ON SCHEMA {_SCHEMA} FROM "{app_role}"')
    op.execute(f"DROP SCHEMA IF EXISTS {_SCHEMA}")
