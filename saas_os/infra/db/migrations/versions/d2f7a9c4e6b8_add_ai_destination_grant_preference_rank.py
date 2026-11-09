"""add preference_rank to control_plane.ai_tenant_destination_grants

Revision ID: d2f7a9c4e6b8
Revises: b3d6f8a1c5e7
Create Date: 2026-11-09 21:00:00.000000

ADR-0054 amendment of 2026-11-09 (Gap 20a, tenant model ranking). One nullable
column and one partial unique index on the tenant-owned destination grants:

    preference_rank smallint NULL    CHECK (preference_rank IS NULL OR preference_rank >= 0)
    ux_ai_tenant_destination_grants_rank
        UNIQUE (tenant_id, use_case, preference_rank) WHERE preference_rank IS NOT NULL

A tenant orders the models it granted for a use case; the lower rank is tried
first, an unranked grant after every ranked one, ties (only among unranked)
keep the alias order. A rank never adds a model to an alias and never makes an
ineligible model eligible.

**Data safety.** Additive and backwards compatible. No default and no backfill:
every existing row gets NULL, which is exactly today's behaviour (alias order).
Existing code ignores the column. `downgrade()` drops the index, the check and
the column; the ranks the tenants chose are lost (the grants themselves are
untouched), which is the documented cost of a downgrade.

**Locking.** `ADD COLUMN` of a nullable column without a default is a
catalogue-only change (a brief ACCESS EXCLUSIVE lock). The index is built on a
table that holds one row per tenant, use case and granted model and is empty of
non-NULL ranks, so the partial index is empty and instant.

**RLS and roles.** The table keeps its tenant row-level security policy and its
table-level grant to the application role, which covers the new column. No
policy, privilege or other row is changed.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d2f7a9c4e6b8"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "b3d6f8a1c5e7"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "control_plane.ai_tenant_destination_grants"
_CHECK = "ck_ai_tenant_destination_grants_rank"
_INDEX = "ux_ai_tenant_destination_grants_rank"


def upgrade() -> None:
    op.execute(f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS preference_rank smallint")
    op.execute(
        f"ALTER TABLE {_TABLE} ADD CONSTRAINT {_CHECK} "
        "CHECK (preference_rank IS NULL OR preference_rank >= 0)"
    )
    op.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS {_INDEX} "
        f"ON {_TABLE} (tenant_id, use_case, preference_rank) "
        "WHERE preference_rank IS NOT NULL"
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS control_plane.{_INDEX}")
    op.execute(f"ALTER TABLE {_TABLE} DROP CONSTRAINT IF EXISTS {_CHECK}")
    op.execute(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS preference_rank")
