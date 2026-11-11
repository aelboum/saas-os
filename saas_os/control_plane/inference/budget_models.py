"""Tables of the monetary AI budget (ADR-0054 amendment of 2026-11-10; Gap 21b;
migration f1b9d3e7a5c2).

Two are platform-owned installation-wide configuration (ADR-0056: the
application role reads them, the platform-configuration role writes them):
`AIPlanBudget` and `AIBudgetOverride`. Three are tenant-owned under row-level
security, written by the application role in the tenant's own scope:
`AITenantBudget`, `AIBudgetPeriod` and `AIBudgetReservation`.

Every amount is an **estimate of platform spend** in one currency, never an
amount a provider invoices. No row holds a prompt, a completion, a
credential or free text.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal

from saas_os.infra.db import (
    JSON,
    Base,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Mapped,
    Numeric,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
)

SCHEMA = "control_plane"


class OverrideReason(enum.StrEnum):
    """Why a platform operator raised one tenant's budget: a closed set. No
    free text is stored, logged or audited."""

    CONTRACTUAL = "contractual"
    SUPPORT = "support"
    INCIDENT = "incident"
    OPERATOR = "operator"


class ReservationState(enum.StrEnum):
    # Admitted; the attempt is in flight. Its worst case counts as reserved.
    HELD = "held"
    # The attempt finished with a known estimated cost, now counted as settled.
    SETTLED = "settled"
    # The provider did not accept the request: nothing is charged.
    RELEASED = "released"
    # The outcome is unknown (possibly accepted, interrupted, abandoned, or a
    # cost that could not be estimated): the worst case stays charged.
    EXPIRED_UNKNOWN = "expired_unknown"
    # A platform operator released an `expired_unknown` reservation (audited).
    OPERATOR_RELEASED = "operator_released"


class AIPlanBudget(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One immutable version of a billing plan's monthly AI budget. A
    version with no currency and no amount says the plan has no budget from
    `effective_from` on."""

    __tablename__ = "ai_plan_budgets"
    __table_args__ = (
        UniqueConstraint("plan_id", "budget_version", name="ux_ai_plan_budgets_version"),
        {"schema": SCHEMA},
    )

    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.billing_plans.id"), nullable=False)
    budget_version: Mapped[str] = mapped_column(String(64), nullable=False)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    monthly_amount: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)
    # Gap 21c (warnings). Written by no code in this stage.
    warn_thresholds: Mapped[list | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AIBudgetOverride(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A platform operator's override of one tenant's plan budget: at most
    one row per tenant, in force while `active` and before `expires_at`."""

    __tablename__ = "ai_budget_overrides"
    __table_args__ = (
        UniqueConstraint("target_tenant_id", name="ux_ai_budget_overrides_tenant"),
        {"schema": SCHEMA},
    )

    target_tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False
    )
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False)
    reason: Mapped[str] = mapped_column(String(16), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    set_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cleared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AITenantBudget(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The tenant's own cap. It can only lower the effective budget."""

    __tablename__ = "ai_tenant_budgets"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="ux_ai_tenant_budgets_tenant"),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    cap_amount: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)
    # Gap 21c (warnings). Written by no code in this stage.
    warn_thresholds: Mapped[list | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AIBudgetPeriod(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One tenant's budget in one UTC calendar month."""

    __tablename__ = "ai_budget_periods"
    __table_args__ = (
        UniqueConstraint("tenant_id", "period_start", name="ux_ai_budget_periods_month"),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    # The plan component of the limit, frozen at first use in the month and
    # lowered (never raised) by a later, lower plan budget.
    plan_limit: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)
    reserved: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False, default=Decimal(0))
    retained: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False, default=Decimal(0))
    settled: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False, default=Decimal(0))
    # Gap 21c (warnings). Written by no code in this stage.
    last_threshold_notified: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AIBudgetReservation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The worst-case amount one attempt was admitted with, and how it ended."""

    __tablename__ = "ai_budget_reservations"
    __table_args__ = (
        UniqueConstraint("attempt_id", name="ux_ai_budget_reservations_attempt"),
        UniqueConstraint(
            "tenant_id", "request_id", "attempt_number", name="ux_ai_budget_reservations_number"
        ),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    period_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("control_plane.ai_budget_periods.id"), nullable=False
    )
    attempt_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("control_plane.ai_inference_attempts.id"), nullable=False
    )
    request_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    price_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("control_plane.ai_model_prices.id"), nullable=False
    )
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False)
    settled_amount: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
