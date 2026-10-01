"""add billing subscription lifecycle safety

Revision ID: 41e8273a685d
Revises: 6e99825a629c
Create Date: 2026-10-01 00:00:00.000000

Billing Foundation v2 Phase 3 -- lifecycle safety
(`core/billing/lifecycle.py`; docs/ADR/0029-commercial-parties-and-billing-
relationships.md, Decision 0.5 and "Implementation status").

`core.billing_subscriptions` gains:

- `verification` (`verified` | `legacy_unverified`, NOT NULL, server
  default `legacy_unverified`) -- every pre-existing row, including every
  Phase 2 commercial row (whose `active` status was written without
  provider confirmation), becomes explicitly `legacy_unverified`. No row's
  `status` is rewritten: a legacy row keeps exactly the status it had, now
  explicitly marked as an unverified legacy claim.
- `merchant_account_id` -- the payee merchant. Backfilled ONLY for rows
  that already record a billing account (Phase 2 commercial rows), from
  that billing account's own `merchant_account_id`: an existing,
  database-enforced fact, not a guess. Rows without a billing account
  (legacy) keep NULL -- no merchant is invented for them.
- constraints: `ck_billing_subscriptions_merchant_pair` (merchant present
  exactly when a billing account is), `ck_billing_subscriptions_verified_
  is_commercial` (a `verified` row has a billing account),
  `ck_billing_subscriptions_verification_values`, and
  `fk_billing_subscriptions_billing_account_merchant` (the recorded
  merchant IS the billing account's merchant; target: the new
  `uq_billing_accounts_tenant_id_id_merchant` on `core.billing_accounts`).
- `uq_billing_subscriptions_one_live_per_merchant` -- a PARTIAL UNIQUE
  INDEX on `(tenant_id, merchant_account_id) WHERE merchant_account_id IS
  NOT NULL AND status IN ('pending', 'active', 'past_due')`: at most one
  live subscription per (service tenant, merchant), enforced by the
  database. Legacy rows (NULL merchant) are outside it until reconciled.

**Fails safe, never resolves data.** Before creating the index this
migration counts existing duplicate live groups. If any exist it raises
with the number of groups and rows -- it never deletes a row, never picks
a winner, and never changes a status to make the index fit. Remediation is
an explicit, human decision -- the runbook is in docs/ADR/0029-...,
"Implementation status", Phase 3: inspect the `(tenant_id,
merchant_account_id)` groups with more than one live row, cancel the
superfluous subscriptions at the provider and locally, then re-run.
Likewise, if any row with a billing account is still missing its merchant
after the backfill (e.g. because the migration role cannot see rows under
FORCE RLS), it raises instead of continuing with a partial backfill --
`ck_billing_subscriptions_merchant_pair` would otherwise be violated.

Runs via the privileged bootstrap/migration role, which must be able to
read every row (a superuser, as the reference deployment's role is) for
the backfill and the duplicate check to see the whole table.

`downgrade()` drops the index, constraints and both columns; the
`verification` marking and recorded merchants are lost, statuses are
untouched.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "41e8273a685d"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "6e99825a629c"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LIVE = "('pending', 'active', 'past_due')"


def upgrade() -> None:
    op.add_column(
        "billing_subscriptions",
        sa.Column(
            "verification",
            sa.String(length=20),
            nullable=False,
            server_default="legacy_unverified",
        ),
        schema="core",
    )
    op.add_column(
        "billing_subscriptions",
        sa.Column("merchant_account_id", sa.Uuid(), nullable=True),
        schema="core",
    )

    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE core.billing_subscriptions AS s "
            "SET merchant_account_id = a.merchant_account_id "
            "FROM core.billing_accounts AS a "
            "WHERE s.billing_account_id IS NOT NULL "
            "AND a.tenant_id = s.payer_tenant_id AND a.id = s.billing_account_id"
        )
    )
    missing = conn.execute(
        sa.text(
            "SELECT count(*) FROM core.billing_subscriptions "
            "WHERE billing_account_id IS NOT NULL AND merchant_account_id IS NULL"
        )
    ).scalar_one()
    if missing:
        raise RuntimeError(
            f"{missing} billing subscription(s) record a billing account but no merchant "
            "could be backfilled -- the migration role must be able to read every row. "
            "Nothing was changed."
        )

    duplicate_groups, duplicate_rows = conn.execute(
        sa.text(
            "SELECT count(*), coalesce(sum(n), 0) FROM ("
            "  SELECT count(*) AS n FROM core.billing_subscriptions "
            f"  WHERE merchant_account_id IS NOT NULL AND status IN {_LIVE} "
            "  GROUP BY tenant_id, merchant_account_id HAVING count(*) > 1"
            ") AS d"
        )
    ).one()
    if duplicate_groups:
        raise RuntimeError(
            f"{duplicate_groups} (tenant_id, merchant_account_id) group(s) hold "
            f"{duplicate_rows} live subscriptions in total, violating the one-live-"
            "subscription invariant. Resolve them explicitly (cancel the superfluous "
            "subscriptions at the provider and locally) before upgrading; this "
            "migration never deletes or rewrites subscriptions. Nothing was changed."
        )

    op.create_unique_constraint(
        "uq_billing_accounts_tenant_id_id_merchant",
        "billing_accounts",
        ["tenant_id", "id", "merchant_account_id"],
        schema="core",
    )
    op.create_check_constraint(
        "ck_billing_subscriptions_merchant_pair",
        "billing_subscriptions",
        "(merchant_account_id IS NULL) = (billing_account_id IS NULL)",
        schema="core",
    )
    op.create_check_constraint(
        "ck_billing_subscriptions_verified_is_commercial",
        "billing_subscriptions",
        "verification <> 'verified' OR billing_account_id IS NOT NULL",
        schema="core",
    )
    op.create_check_constraint(
        "ck_billing_subscriptions_verification_values",
        "billing_subscriptions",
        "verification IN ('verified', 'legacy_unverified')",
        schema="core",
    )
    op.create_foreign_key(
        "fk_billing_subscriptions_billing_account_merchant",
        "billing_subscriptions",
        "billing_accounts",
        ["payer_tenant_id", "billing_account_id", "merchant_account_id"],
        ["tenant_id", "id", "merchant_account_id"],
        source_schema="core",
        referent_schema="core",
    )
    op.create_index(
        "uq_billing_subscriptions_one_live_per_merchant",
        "billing_subscriptions",
        ["tenant_id", "merchant_account_id"],
        unique=True,
        schema="core",
        postgresql_where=sa.text(f"merchant_account_id IS NOT NULL AND status IN {_LIVE}"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_billing_subscriptions_one_live_per_merchant",
        table_name="billing_subscriptions",
        schema="core",
    )
    op.drop_constraint(
        "fk_billing_subscriptions_billing_account_merchant",
        "billing_subscriptions",
        type_="foreignkey",
        schema="core",
    )
    for name in (
        "ck_billing_subscriptions_verification_values",
        "ck_billing_subscriptions_verified_is_commercial",
        "ck_billing_subscriptions_merchant_pair",
    ):
        op.drop_constraint(name, "billing_subscriptions", type_="check", schema="core")
    op.drop_constraint(
        "uq_billing_accounts_tenant_id_id_merchant",
        "billing_accounts",
        type_="unique",
        schema="core",
    )
    op.drop_column("billing_subscriptions", "merchant_account_id", schema="core")
    op.drop_column("billing_subscriptions", "verification", schema="core")
