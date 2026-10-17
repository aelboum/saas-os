"""create AI model prices

Revision ID: c5d7e9f1a2b4
Revises: b8e2d4f6a1c3
Create Date: 2026-10-17 20:00:00.000000

docs/ADR/0054-governed-ai-inference-subsystem.md Phase AI-F (pricing table
and versions; cost estimates with provenance).

`control_plane.ai_model_prices`: global, platform-managed (no tenant id, no
RLS), one row per (model, pricing version). A version is immutable once
written -- a price change is a new version with its own `effective_from` --
so an attempt's `pricing_version` always names the exact rates it was
estimated with. Rates are per million tokens in one ISO 4217 currency. The
application role may not delete rows. A cost computed from these rates is an
*estimate*, never a billed amount.

Data safety: one additive table, no backfill. Hand-written.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c5d7e9f1a2b4"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "b8e2d4f6a1c3"  # pragma: allowlist secret
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
    op.create_table(
        "ai_model_prices",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "model_ref", sa.Uuid(), sa.ForeignKey("control_plane.ai_models.id"), nullable=False
        ),
        sa.Column("pricing_version", sa.String(64), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("input_per_million", sa.Numeric(18, 8), nullable=False),
        sa.Column("output_per_million", sa.Numeric(18, 8), nullable=False),
        sa.Column("cached_input_per_million", sa.Numeric(18, 8), nullable=True),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "input_per_million >= 0 AND output_per_million >= 0 "
            "AND (cached_input_per_million IS NULL OR cached_input_per_million >= 0)",
            name="ck_ai_model_prices_non_negative",
        ),
        sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name="ck_ai_model_prices_currency"),
        sa.UniqueConstraint("model_ref", "pricing_version", name="ux_ai_model_prices_version"),
        schema="control_plane",
    )
    table = "control_plane.ai_model_prices"
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON {table} TO "{app_role}"')
    op.execute(f'REVOKE DELETE ON {table} FROM "{app_role}"')


def downgrade() -> None:
    op.drop_table("ai_model_prices", schema="control_plane")
