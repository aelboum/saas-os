"""add billable-unit rates and reviewed_at to control_plane.ai_model_prices

Revision ID: a4c8e1f3b7d5
Revises: d2f7a9c4e6b8
Create Date: 2026-11-10 10:00:00.000000

ADR-0054 amendment of 2026-11-09 (Gap 21a, price-table extension and price
staleness). Four nullable columns and one check on the global price table:

    cache_write_per_million numeric(18,8) NULL   rate per million cache-write tokens
    per_request             numeric(18,8) NULL   flat amount per provider request
    unit_rates              json          NULL   other billable units: name -> rate
                                                 per one unit, a decimal string
    reviewed_at             timestamptz   NULL   when a platform operator last
                                                 confirmed the price as current
    ck_ai_model_prices_extra_units
        CHECK ((cache_write_per_million IS NULL OR cache_write_per_million >= 0)
           AND (per_request IS NULL OR per_request >= 0)
           AND (unit_rates IS NULL OR json_typeof(unit_rates) = 'object'))

The price age that the 24-hour staleness limit measures is counted from
`reviewed_at`. This migration adds the fields only: nothing refuses a request
on a stale price until the budget stage (Gap 21b) is implemented.

**Data safety.** Additive and backwards compatible. No default and no backfill:
every existing row gets NULL in all four columns. NULL rates mean "this price
has no rate for that unit", which is exactly today's cost estimate. NULL
`reviewed_at` means "never confirmed", so an existing price reads as
unverifiable until an operator confirms it; a backfill would record a review
that did not happen. Existing code ignores the columns. The existing
`ck_ai_model_prices_non_negative`, `ck_ai_model_prices_currency` and
`ux_ai_model_prices_version` are not touched. `downgrade()` drops the check and
the four columns; the extra rates and the review times are lost (the price
versions themselves are untouched), which is the documented cost of a
downgrade.

**Locking.** `ADD COLUMN` of a nullable column without a default is a
catalogue-only change (a brief ACCESS EXCLUSIVE lock). `ADD CONSTRAINT ...
CHECK` validates the existing rows under the same lock; the table holds one
row per model and price version and every new column is NULL, so the scan is
short and cannot fail.

**RLS and roles.** The table is global and has no row-level security
(ADR-0056). Its table-level privileges cover the new columns and are not
changed: the application role keeps `SELECT` only, the platform-configuration
role keeps `SELECT, INSERT, UPDATE` and no role used by SaaS OS can delete.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a4c8e1f3b7d5"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "d2f7a9c4e6b8"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "control_plane.ai_model_prices"
_CHECK = "ck_ai_model_prices_extra_units"


def upgrade() -> None:
    op.execute(
        f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS cache_write_per_million numeric(18,8)"
    )
    op.execute(f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS per_request numeric(18,8)")
    op.execute(f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS unit_rates json")
    op.execute(f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS reviewed_at timestamptz")
    op.execute(
        f"ALTER TABLE {_TABLE} ADD CONSTRAINT {_CHECK} CHECK ("
        "(cache_write_per_million IS NULL OR cache_write_per_million >= 0) "
        "AND (per_request IS NULL OR per_request >= 0) "
        "AND (unit_rates IS NULL OR json_typeof(unit_rates) = 'object'))"
    )


def downgrade() -> None:
    op.execute(f"ALTER TABLE {_TABLE} DROP CONSTRAINT IF EXISTS {_CHECK}")
    op.execute(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS reviewed_at")
    op.execute(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS unit_rates")
    op.execute(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS per_request")
    op.execute(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS cache_write_per_million")
