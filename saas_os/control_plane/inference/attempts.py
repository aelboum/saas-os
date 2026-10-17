"""The attempt ledger (ADR-0054 Phase AI-D; decisions Q7, Q10;
AI-INFERENCE-CONTRACTS section 7; migration a7f3c91e2d48).

One row per actual provider attempt, tenant-owned (RLS). The row is the
durable decision record of that attempt: it is inserted `started`, with the
data-authorization decision, and committed before any content is sent; it is
finalized after the outcome. It never holds content or a credential.
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


class AttemptState(enum.StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    ABANDONED = "abandoned"


class AIInferenceAttempt(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_inference_attempts"
    __table_args__ = (
        CheckConstraint(
            "state IN ('started', 'succeeded', 'failed', 'interrupted', 'abandoned')",
            name="ck_ai_inference_attempts_state",
        ),
        CheckConstraint(
            "usage_provenance IN ('provider_reported', 'estimated', 'unknown')",
            name="ck_ai_inference_attempts_provenance",
        ),
        UniqueConstraint(
            "tenant_id", "request_id", "attempt_number", name="ux_ai_inference_attempts_number"
        ),
        {"schema": "control_plane"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    request_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    actor_service_account_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    use_case: Mapped[str] = mapped_column(String(100), nullable=False)
    alias: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(64), nullable=False)
    model_id: Mapped[str] = mapped_column(String(200), nullable=False)
    provider_config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    model_config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    effective_classification: Mapped[str] = mapped_column(String(32), nullable=False)
    decision: Mapped[dict] = mapped_column(JSON, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    error_category: Mapped[str | None] = mapped_column(String(40), nullable=True)
    possibly_accepted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    streamed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    output_delivered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    time_to_first_token_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cached_input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cache_write_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    other_usage: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    usage_provenance: Mapped[str] = mapped_column(String(20), nullable=False)
    provider_request_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    estimated_cost: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    pricing_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
