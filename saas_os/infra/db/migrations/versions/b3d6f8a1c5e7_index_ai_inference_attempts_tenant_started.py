"""index control_plane.ai_inference_attempts on (tenant_id, started_at)

Revision ID: b3d6f8a1c5e7
Revises: c8e5a2f7d1b3
Create Date: 2026-11-09 18:00:00.000000

ADR-0054 amendment of 2026-11-09 (Gap 22a, the tenant AI usage report). One
additive index:

    ix_ai_inference_attempts_tenant_started
        ON control_plane.ai_inference_attempts (tenant_id, started_at)

The tenant usage report and the soft token quota both read one tenant's
attempts over a `started_at` window with no `state` filter. The existing index
`ix_ai_inference_attempts_tenant_state_started` leads `(tenant_id, state,
started_at)`, so a window read that does not name a state cannot use the
`started_at` column of it for the range; this one can.

**Data safety.** Additive and backwards compatible. No table, column,
constraint, policy, privilege or row is changed, and nothing is read from or
written to any row. Existing code runs unchanged with or without it.
`downgrade()` drops the index and restores the schema exactly; no data is lost
in either direction.

**Locking.** A plain `CREATE INDEX` blocks writes to
`control_plane.ai_inference_attempts` for the duration of the build (reads
continue). The table first shipped in v0.10.0 and holds one row per provider
attempt, so the build is short; a deployment with a very large attempts table
may create the same index beforehand with `CREATE INDEX CONCURRENTLY IF NOT
EXISTS`, which this migration then finds in place (the `d7e4b2a91c36`
precedent).

**RLS and roles.** An index changes no policy and no privilege; the table's
row-level security and grants are untouched.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3d6f8a1c5e7"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "c8e5a2f7d1b3"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEX = "ix_ai_inference_attempts_tenant_started"


def upgrade() -> None:
    op.execute(
        f"CREATE INDEX IF NOT EXISTS {_INDEX} "
        "ON control_plane.ai_inference_attempts (tenant_id, started_at)"
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS control_plane.{_INDEX}")
