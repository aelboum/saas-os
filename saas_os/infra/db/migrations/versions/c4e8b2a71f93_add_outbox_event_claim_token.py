"""add core outbox_events claim_token

Revision ID: c4e8b2a71f93
Revises: 8d3f1a6c2e70
Create Date: 2026-10-02 15:00:00.000000

Foundation Reliability & Events, RE-2 (durable outbox dispatcher): the one
column the dispatcher needs that RE-1 did not create.

`claim_token` identifies the dispatcher claim that currently owns a pending
event. A claim sets it to a fresh UUID and moves `next_attempt_at` to the
lease expiry; every later state change (lease renewal, published, failure)
is conditional on the caller presenting that token, so a worker whose lease
expired and was reclaimed can no longer change the event. While a row is
claimed, `next_attempt_at` *is* the lease expiry -- so "due for a first
attempt", "due for a retry" and "lease expired, reclaim" are one predicate
(`status = 'pending' AND next_attempt_at <= now`) served by RE-1's existing
`ix_outbox_events_pending` partial index. No other column is added.

`ck_outbox_events_claim_only_pending`: only a pending event can be claimed --
a published or dead-lettered event never carries a live claim.

Nullable column on an existing table: no existing row is rewritten or
guessed (every existing row is unclaimed). Reversible: downgrade drops the
constraint and the column.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4e8b2a71f93"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "8d3f1a6c2e70"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "outbox_events", sa.Column("claim_token", sa.Uuid(), nullable=True), schema="core"
    )
    op.create_check_constraint(
        "ck_outbox_events_claim_only_pending",
        "outbox_events",
        "claim_token IS NULL OR status = 'pending'",
        schema="core",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_outbox_events_claim_only_pending", "outbox_events", schema="core", type_="check"
    )
    op.drop_column("outbox_events", "claim_token", schema="core")
