"""The monthly AI usage rollup (ADR-0054 amendment of 2026-11-11; Gap 22b).

`control_plane.ai_usage_monthly` holds, per tenant and UTC calendar month of
`started_at`, the counts and sums of the tenant's **finished** attempts at the
grain the usage report groups by (provider, model, use case, state, usage
provenance, currency, and whether the attempt had no price). It is written by
no Python code: a database trigger on `ai_inference_attempts` (migration
`c7d2a9f4e1b6`) adds an attempt in the transaction that finishes it, and an
attempt deleted later stays counted, so the rollup outlives the attempts once
their retention is enforced. Read by `tenant_usage.read_tenant_ai_monthly_usage`.
No prompt, completion, identity or request id is stored. Retention:
FINANCIAL_RETAIN for a tenant purge; rows older than 24 months (at least)
can be expired by the opt-in job of `usage_rollup_retention`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from saas_os.infra.db import (
    Base,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Mapped,
    Numeric,
    String,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class AIUsageMonthly(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Read-only mapping. The count columns are `bigint` in the database
    (`Integer` here only types the Python attribute; the schema is the
    migration's)."""

    __tablename__ = "ai_usage_monthly"
    __table_args__ = {"schema": "control_plane"}

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    month_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(64), nullable=False)
    model_id: Mapped[str] = mapped_column(String(200), nullable=False)
    use_case: Mapped[str] = mapped_column(String(100), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    usage_provenance: Mapped[str] = mapped_column(String(20), nullable=False)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    cost_unknown: Mapped[bool] = mapped_column(Boolean, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    cached_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_cost: Mapped[Decimal] = mapped_column(Numeric(24, 8), nullable=False)


__all__ = ["AIUsageMonthly"]
