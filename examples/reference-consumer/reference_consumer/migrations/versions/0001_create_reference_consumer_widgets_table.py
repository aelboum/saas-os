"""create reference_consumer widgets table

Revision ID: 0001_ref_consumer_widgets
Revises:
Create Date: 2026-09-10 00:00:00.000000

The reference consumer's own project schema (ADR-0016: "<project>.*,
owned by the consuming project"). `tenant_id` is a real foreign key into
`core.tenants` -- SaaS OS's own migrations must have already run
(ADR-0016's fixed ordering) for this migration to succeed, proving "a
project migration can safely reference SaaS-OS-owned tables where
appropriate". Uses `infra.db.rls.tenant_rls_statements()` (reused from
the installed `saas-os` package) rather than hand-rolling the same RLS
DDL SaaS OS's own tenant-owned tables already use.
"""

import os
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from infra.db.rls import tenant_rls_statements

revision: str = "0001_ref_consumer_widgets"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DEFAULT_APP_ROLE = "saas_os_app"


def _app_role() -> str:
    role = os.environ.get("APP_DB_USER", _DEFAULT_APP_ROLE)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", role):
        raise ValueError(f"APP_DB_USER must be a plain SQL identifier, got: {role!r}")
    return role


def upgrade() -> None:
    app_role = _app_role()

    op.execute("CREATE SCHEMA IF NOT EXISTS reference_consumer")
    op.create_table(
        "widgets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("core.tenants.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="reference_consumer",
    )
    op.create_index(
        "ix_reference_consumer_widgets_tenant_id",
        "widgets",
        ["tenant_id"],
        schema="reference_consumer",
    )

    for statement in tenant_rls_statements("widgets", schema="reference_consumer"):
        op.execute(statement)

    op.execute(f'GRANT USAGE ON SCHEMA reference_consumer TO "{app_role}"')
    op.execute(
        f'GRANT SELECT, INSERT, UPDATE, DELETE ON reference_consumer.widgets TO "{app_role}"'
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA reference_consumer "
        f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{app_role}"'
    )


def downgrade() -> None:
    app_role = _app_role()

    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA reference_consumer "
        f'REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM "{app_role}"'
    )
    op.drop_table("widgets", schema="reference_consumer")
    op.execute("DROP SCHEMA IF EXISTS reference_consumer")
