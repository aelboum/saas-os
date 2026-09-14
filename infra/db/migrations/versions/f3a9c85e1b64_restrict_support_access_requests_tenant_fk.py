"""make support_access_requests.tenant_id FK restrictive

Revision ID: f3a9c85e1b64
Revises: cb7120cfa806
Create Date: 2026-09-14 00:00:00.000000

PRIV-03 Phase P1 (approved Tenant Purge / Erasure architecture, "Support
access retention decision"): `core.support_access_requests.tenant_id`
was created (`9aecff1d1135`) with `ON DELETE CASCADE`, mirroring
`DelegationGrant`/`DenyGrant` -- reasonable for those two (pure,
revocable authority grants with no meaning once their tenant is gone),
but wrong for this table: a `SupportAccessRequest` is security/forensic
evidence of who accessed a tenant's data, when, and under what
authorization. The approved tenant-purge architecture requires this
evidence to survive tenant deletion (or be explicitly retained/disposed
of by a future purge-orchestration phase), never to disappear silently
as a side effect of one `DELETE FROM core.tenants` statement.

This migration only changes `ON DELETE CASCADE` to the Postgres default
`NO ACTION` (restrictive) on this one FK. It does not touch any other
foreign key, does not add or remove any column, does not change RLS,
and does not implement tenant-purge orchestration itself (that is a
later phase) -- a tenant with a `support_access_requests` row will now
fail to delete with a `ForeignKeyViolation`, exactly like every other
genuinely-retained-evidence table already does today (`core.audit_log`,
`core.billing_subscriptions`, `core.usage_events`, etc.), rather than
silently losing that evidence.

Runs via the privileged bootstrap/migration role
(`infra.db.config.get_migrations_database_config()`,
`MIGRATIONS_DATABASE_URL`) -- never the restricted application runtime
role, exactly like every migration since Phase 3.1.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3a9c85e1b64"
down_revision: str | Sequence[str] | None = "cb7120cfa806"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "core"
_TABLE = "support_access_requests"
_CONSTRAINT = "support_access_requests_tenant_id_fkey"


def upgrade() -> None:
    op.drop_constraint(_CONSTRAINT, _TABLE, schema=_SCHEMA, type_="foreignkey")
    op.create_foreign_key(
        _CONSTRAINT,
        _TABLE,
        "tenants",
        ["tenant_id"],
        ["id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_constraint(_CONSTRAINT, _TABLE, schema=_SCHEMA, type_="foreignkey")
    op.create_foreign_key(
        _CONSTRAINT,
        _TABLE,
        "tenants",
        ["tenant_id"],
        ["id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
        ondelete="CASCADE",
    )
