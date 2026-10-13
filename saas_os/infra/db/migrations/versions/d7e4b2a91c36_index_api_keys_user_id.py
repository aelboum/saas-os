"""index core.api_keys on user_id

Revision ID: d7e4b2a91c36
Revises: c4a9e1f07b52
Create Date: 2026-10-12 12:00:00.000000

ADR-0045 Phase C (docs/ADR/0045-installation-scoped-platform-authority.md
sections 11d and 11f). One additive, partial index:

    ix_api_keys_user_id  ON core.api_keys (user_id) WHERE user_id IS NOT NULL

`deactivate_user`, `reactivate_user` and `revoke_user_api_keys` revoke
every unrevoked user-owned key of one user with a single statement,
`UPDATE core.api_keys ... WHERE user_id = :u AND revoked_at IS NULL`.
`core.api_keys` had no index on `user_id` (its composite foreign key leads
with `tenant_id`), so that statement would scan the table. Partial,
because a service-account-owned key has no `user_id` and is never reached
by it.

**Data safety.** Additive and backwards compatible. No table, column,
constraint, policy, privilege or row is changed, and nothing is read from
or written to any row: it creates an index and nothing else. Existing code
runs unchanged with or without it. `downgrade()` drops the index and
restores the schema exactly; no data is lost in either direction.

**Locking.** A plain `CREATE INDEX` holds a lock that blocks writes to
`core.api_keys` for the duration of the build (reads continue). The table
holds one row per issued key, so the build is short; a deployment with a
very large key table may prefer to create the same index beforehand with
`CREATE INDEX CONCURRENTLY IF NOT EXISTS`, which this migration then finds
in place.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d7e4b2a91c36"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "c4a9e1f07b52"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEX = "ix_api_keys_user_id"


def upgrade() -> None:
    op.execute(
        f"CREATE INDEX IF NOT EXISTS {_INDEX} ON core.api_keys (user_id) WHERE user_id IS NOT NULL"
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS core.{_INDEX}")
