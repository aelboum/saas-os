"""ORM models of the AI inference configuration (ADR-0054 Phase AI-C;
migration e4b8c2d6f1a3).

Global, platform-managed catalog (no tenant id, no RLS; never deleted):
`AIProvider`, `AIModel`, `AIAlias`, `AIEndpointTrust`, `AIDestinationPolicy`.
Tenant-owned minimum tenant AI policy (tenant RLS; absent or disabled means
deny): `AITenantPolicy`, `AITenantUseCaseGrant`, `AITenantDestinationGrant`;
and the tenant's data-handling preferences (AI-E, migration b8e2d4f6a1c3):
`AITenantPreferences`, which only ever narrow eligibility.
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
    CheckConstraint,
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


class Protocol(enum.StrEnum):
    OPENAI_CHAT_COMPLETIONS = "openai_chat_completions"
    ANTHROPIC_MESSAGES = "anthropic_messages"
    GEMINI_GENERATE_CONTENT = "gemini_generate_content"


class ProviderStatus(enum.StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class ModelLifecycle(enum.StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    DISABLED = "disabled"


class Classification(enum.StrEnum):
    NONE = "none"
    TENANT_DATA = "tenant_data"
    SENSITIVE = "sensitive"


CLASSIFICATION_ORDER: dict[str, int] = {"none": 0, "tenant_data": 1, "sensitive": 2}


class AIProvider(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_providers"
    __table_args__ = (
        CheckConstraint(
            "protocol IN ('openai_chat_completions', 'anthropic_messages', "
            "'gemini_generate_content')",
            name="ck_ai_providers_protocol",
        ),
        CheckConstraint("status IN ('active', 'disabled')", name="ck_ai_providers_status"),
        UniqueConstraint("key", name="ux_ai_providers_key"),
        {"schema": SCHEMA},
    )

    key: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    credential_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    # The origin the credential is bound to; None means unbound (unusable).
    credential_origin: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    data_handling: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AIModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_models"
    __table_args__ = (
        CheckConstraint(
            "lifecycle IN ('active', 'deprecated', 'disabled')", name="ck_ai_models_lifecycle"
        ),
        UniqueConstraint("provider_id", "model_id", name="ux_ai_models_provider_model"),
        {"schema": SCHEMA},
    )

    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("control_plane.ai_providers.id"), nullable=False
    )
    model_id: Mapped[str] = mapped_column(String(200), nullable=False)
    capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    max_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    context_window_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lifecycle: Mapped[str] = mapped_column(String(16), nullable=False)
    retire_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AIAlias(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_aliases"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'disabled')", name="ck_ai_aliases_status"),
        UniqueConstraint("alias", name="ux_ai_aliases_alias"),
        {"schema": SCHEMA},
    )

    alias: Mapped[str] = mapped_column(String(100), nullable=False)
    # Ordered list of AIModel ids (strings).
    candidates: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AIEndpointTrust(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_endpoint_trust"
    __table_args__ = ({"schema": SCHEMA},)

    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    networks: Mapped[list] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AIDestinationPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_destination_policy"
    __table_args__ = (
        CheckConstraint(
            "classification IN ('none', 'tenant_data', 'sensitive')",
            name="ck_ai_destination_policy_classification",
        ),
        UniqueConstraint(
            "provider_id", "classification", name="ux_ai_destination_policy_provider_class"
        ),
        {"schema": SCHEMA},
    )

    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("control_plane.ai_providers.id"), nullable=False
    )
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)


class AITenantPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_tenant_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="ux_ai_tenant_policies_tenant"),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AITenantUseCaseGrant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_tenant_use_case_grants"
    __table_args__ = (
        UniqueConstraint("tenant_id", "use_case", name="ux_ai_tenant_use_case_grants"),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    use_case: Mapped[str] = mapped_column(String(100), nullable=False)
    classifications: Mapped[list] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)


class AITenantDestinationGrant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_tenant_destination_grants"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "use_case", "model_ref", name="ux_ai_tenant_destination_grants"
        ),
        CheckConstraint(
            "preference_rank IS NULL OR preference_rank >= 0",
            name="ck_ai_tenant_destination_grants_rank",
        ),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    use_case: Mapped[str] = mapped_column(String(100), nullable=False)
    model_ref: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("control_plane.ai_models.id"), nullable=False
    )
    classifications: Mapped[list] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # The tenant's order among the models it granted for the use case: lower
    # first, NULL after every ranked grant (migration d2f7a9c4e6b8, which also
    # owns the partial unique index on (tenant_id, use_case, preference_rank)
    # and makes the column smallint).
    preference_rank: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AITenantPreferences(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_tenant_preferences"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="ux_ai_tenant_preferences_tenant"),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    # Residency tags a destination must stay within (empty: no requirement).
    allowed_residency: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # A destination must declare a retention of at most this many days.
    max_retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # A destination must declare that it does not use data for training.
    exclude_training_use: Mapped[bool] = mapped_column(Boolean, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AIModelPrice(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Rates for one immutable price version of a model (AI-F, migration
    c5d7e9f1a2b4; the billable-unit rates and `reviewed_at` are Gap 21a,
    migration a4c8e1f3b7d5). A cost computed from it is an estimate of
    platform spend, never an amount a provider invoices. The rates of a
    version never change; `reviewed_at` is the only column that does."""

    __tablename__ = "ai_model_prices"
    __table_args__ = (
        UniqueConstraint("model_ref", "pricing_version", name="ux_ai_model_prices_version"),
        {"schema": SCHEMA},
    )

    model_ref: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("control_plane.ai_models.id"), nullable=False
    )
    pricing_version: Mapped[str] = mapped_column(String(64), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    input_per_million: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False)
    output_per_million: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False)
    cached_input_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Gap 21a (migration a4c8e1f3b7d5). NULL: the price has no rate for the
    # unit, so an attempt that used the unit has an unknown cost (never zero).
    cache_write_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)
    # A flat amount per provider request, added once to every estimate.
    per_request: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)
    # Other billable units: unit name -> rate per one unit, a decimal string
    # (JSON has no decimal type). Read it with `decode_unit_rates`.
    # `none_as_null`: Python None is stored as SQL NULL, not as the JSON value
    # `null`, which `ck_ai_model_prices_extra_units` refuses (not an object).
    unit_rates: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    # When a platform operator last confirmed the price as current. NULL:
    # never confirmed, so the price is unverifiable. The price age of the
    # 24-hour staleness limit is counted from it.
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# The largest rate a price may carry, in any unit (`set_model_price`).
MAX_RATE = Decimal("1000000")


def decode_unit_rates(raw: object) -> dict[str, Decimal]:
    """The usable entries of a stored `unit_rates` value: unit name -> rate
    per one unit. An entry that is not a decimal string of a finite rate
    between 0 and `MAX_RATE` is left out, so the unit reads as unpriced and a
    cost that needs it is unknown; it is never read as zero."""
    if not isinstance(raw, dict):
        return {}
    rates: dict[str, Decimal] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        try:
            rate = Decimal(value)
        except ArithmeticError:
            continue
        if rate.is_finite() and 0 <= rate <= MAX_RATE:
            rates[name] = rate
    return rates


class HoldReason(enum.StrEnum):
    """Why a platform operator held a tenant's AI: a closed set. No free
    text is stored, logged or audited (ADR-0054 amendment of 2026-11-09)."""

    SECURITY = "security"
    CONTRACTUAL = "contractual"
    SPENDING = "spending"
    OPERATOR = "operator"


class AITenantHold(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The platform hold on one tenant's AI (migration c8e5a2f7d1b3). Global
    and platform-owned: at most one row per tenant, written only by the
    platform operations `ai_tenant_hold.set` and `ai_tenant_hold.release`. No
    row, or `active` false, means no hold."""

    __tablename__ = "ai_tenant_holds"
    __table_args__ = (
        UniqueConstraint("target_tenant_id", name="ux_ai_tenant_holds_tenant"),
        {"schema": SCHEMA},
    )

    target_tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False
    )
    reason: Mapped[str] = mapped_column(String(16), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    held_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
