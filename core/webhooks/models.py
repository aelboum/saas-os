"""WebhookSubscription entity (docs/IMPLEMENTATION-ROADMAP.md Phase 4.3;
docs/ARCHITECTURE.md section 4: "core/webhooks -- Outbound webhook
subscriptions, delivery, retry").

`core.webhook_subscriptions` is tenant-owned and RLS-protected -- a
subscription is always local to one tenant, the same posture
`core/rbac`'s `Role` (Phase 3.3) established for the simplest tenant-owned
shape: a plain `tenant_id` foreign key to `core.tenants.id`, no composite
FK needed (unlike `core/api_keys`, there is no second identity -- like a
`user_id` -- a subscription must additionally belong to; it belongs to
exactly one tenant, full stop).

`signing_secret` is stored in plaintext, deliberately unlike
`core/api_keys`' `key_hash` or `core/identity`'s session `token_hash`.
Those are *bearer credentials* validated by one-way hash comparison and
never need to be read back. A webhook signing secret is the opposite: it
is an HMAC key *we* use, repeatedly, to sign every outgoing delivery so
the receiving endpoint can verify authenticity -- there is no operation
that only needs to compare it, so a one-way hash would make delivery
impossible. RLS is this table's confidentiality boundary for that secret
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.3's own Security Requirement:
"no tenant's webhook secret exposed to another tenant") -- the same
boundary every other tenant-owned secret-bearing column in this codebase
relies on.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from infra.db import (
    Base,
    DateTime,
    ForeignKey,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    func,
    mapped_column,
)


class WebhookSubscription(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One tenant's outbound webhook subscription: a destination `url`
    plus the `signing_secret` used to sign every event delivered to it.
    No `event_types` filter, no per-subscription enable/disable flag, no
    delivery-history columns -- none is specified by the roadmap's Phase
    4.3 objective ("subscription management, delivery, retry, signing"),
    and delivery/retry *execution* metadata is `infra/jobs`' own
    generic ownership (docs/DATA-ARCHITECTURE.md section 5), not
    duplicated here. Removing a subscription (`unsubscribe()`) is how
    delivery to it stops.
    """

    __tablename__ = "webhook_subscriptions"
    __table_args__ = ({"schema": "core"},)

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    signing_secret: Mapped[str] = mapped_column(String(64), nullable=False)


class WebhookReplayRecord(Base):
    """P1.10: one immutable fact -- "this `event_id` has already been
    accepted for `subscription_id` within `tenant_id`" -- the atomic
    replay-detection ledger `core.webhooks.service.record_webhook_delivery()`
    inserts into. No `UUIDPrimaryKeyMixin`/`TimestampMixin` reuse for
    `updated_at`, mirroring `core.usage.UsageEvent`'s own "append-only,
    never edited in place" schema signal (`core/usage/models.py`'s own
    docstring) -- a replay record is never updated after insertion.

    The `UniqueConstraint` on `(tenant_id, subscription_id, event_id)` is
    the actual atomicity mechanism (module docstring of
    `core/webhooks/service.py`): two concurrent inserts of the same triple
    can never both succeed -- PostgreSQL's own unique-index enforcement
    rejects the second with an `IntegrityError`, which
    `record_webhook_delivery()` maps to `WebhookReplayDetectedError`. This
    is the same "catch the constraint violation" pattern
    `core/billing/service.py::create_plan()` already established for
    `DuplicatePlanKeyError` -- no `SELECT`-then-`INSERT` race exists here.

    No `REVOKE` on this table (mirrors `core.usage_events`): retention
    cleanup (`purge_expired_replay_records()`) needs ordinary `DELETE`
    privilege on the restricted application role, so none is revoked.
    """

    __tablename__ = "webhook_replay_records"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "subscription_id",
            "event_id",
            name="uq_webhook_replay_records_tenant_subscription_event",
        ),
        {"schema": "core"},
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    subscription_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.webhook_subscriptions.id"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
