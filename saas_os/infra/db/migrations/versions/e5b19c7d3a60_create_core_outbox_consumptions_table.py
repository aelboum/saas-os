"""create core outbox_consumptions table

Revision ID: e5b19c7d3a60
Revises: c4e8b2a71f93
Create Date: 2026-10-02 18:00:00.000000

Foundation Reliability & Events, RE-5 (consumer idempotency):
`core.outbox_consumptions`, owned by `saas_os/core/outbox` (`consumption.py`).

One row per completed consumption of an outbox event by one consumer. The
composite primary key `(tenant_id, consumer, event_id)` *is* the logical
idempotency identity: a consumer inserts it inside its own transaction, so
PostgreSQL's unique-index locking serializes concurrent executions of the
same identity, and a rollback leaves no row. No payload, result or secret
is stored.

Tenant-owned and RLS-protected (canonical tenant policy, ENABLE + FORCE):
a tenant can neither read nor create another tenant's record. `event_id`
deliberately has no foreign key to `core.outbox_events`: a record must not
depend on the event row's lifetime (both are emptied by the tenant purge's
"outbox" step).

New table only; reversible (downgrade drops it).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from saas_os.infra.db.rls import tenant_rls_statements

# revision identifiers, used by Alembic.
revision: str = "e5b19c7d3a60"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "c4e8b2a71f93"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "outbox_consumptions",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("consumer", sa.String(length=100), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column(
            "consumed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("tenant_id", "consumer", "event_id", name="pk_outbox_consumptions"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["core.tenants.id"], name="fk_outbox_consumptions_tenant_id"
        ),
        schema="core",
    )

    for statement in tenant_rls_statements("outbox_consumptions", schema="core"):
        op.execute(statement)


def downgrade() -> None:
    op.drop_table("outbox_consumptions", schema="core")
