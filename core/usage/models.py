"""Usage event entity (docs/IMPLEMENTATION-ROADMAP.md Phase 5.2;
docs/DATA-ARCHITECTURE.md section 6: "core/usage owns the canonical
usage-event store and aggregation logic").

`core.usage_events` is tenant-owned and RLS-protected -- a usage event
always belongs to exactly one tenant. Unlike `core.notifications`'
`(tenant_id, recipient_user_id)` composite FK, a usage event has no
second identity to guard against (it is not addressed to a specific
user) -- so, mirroring `core.webhook_subscriptions`'/
`core.billing_subscriptions`' own reasoning, `tenant_id` is a plain FK to
`core.tenants.id`, not a composite one.

`metric` is a plain string (e.g. `"api_calls"`, `"storage_bytes"`) that
deliberately reuses the same key vocabulary as `core.billing.Plan.entitlements`'
dict keys (docs/ARCHITECTURE-DISCOVERY.md section 14) -- `core/usage`
does not define its own separate metric catalog/enum; a metric is
whatever string a Product caller and the corresponding plan's
entitlements dict agree on, exactly like `core.notifications.channel`'s
"new channels are added by extending the service, never a schema
migration" convention.

`quantity` is `Numeric`, never `float` -- usage quantities feed
plan-quota comparisons and must never accumulate floating-point rounding
error across many aggregated rows.

`occurred_at` (when the usage actually happened, caller-supplied) is
distinct from `created_at` (when this row was written, i.e. ingested) --
usage events may be ingested slightly after the fact through the async
job queue (`core/usage/service.py::ingest_event()`), so aggregation
windows must be computed against `occurred_at`, not `created_at`.

No `updated_at` -- mirrors `core.audit_log`'s immutability-signaling
schema choice (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4): a usage event
is an append-only fact about something that already happened, never
edited in place. Unlike `core.audit_log`, this phase's roadmap text does
not mandate revoking UPDATE/DELETE from the application runtime role, so
that privilege is deliberately left unmodified (see the accompanying
migration's own docstring for the full reasoning) -- this schema-level
`updated_at` omission is a design signal, not an enforced guarantee.

No idempotency key -- the roadmap's Phase 5.2 Tests/Acceptance Criteria
never require de-duplicating a repeated `ingest_event()` call; this
mirrors the exact same accepted characteristic already documented for
`core/webhooks`/`core/notifications`' own job-queued dispatch.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from infra.db import (
    Base,
    DateTime,
    ForeignKey,
    Mapped,
    Numeric,
    String,
    func,
    mapped_column,
)


class UsageEvent(Base):
    """One immutable, append-only usage fact for a tenant. No
    `UUIDPrimaryKeyMixin`/`TimestampMixin` reuse for `updated_at` --
    this table intentionally has no `updated_at` column (see module
    docstring)."""

    __tablename__ = "usage_events"
    __table_args__ = ({"schema": "core"},)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    metric: Mapped[str] = mapped_column(String(100), nullable=False)
    quantity: Mapped[Decimal] = mapped_column(Numeric, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
