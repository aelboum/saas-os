"""WebhookSubscription entity (docs/IMPLEMENTATION-ROADMAP.md Phase 4.3;
docs/ARCHITECTURE.md section 4: "saas_os/core/webhooks -- Outbound webhook
subscriptions, delivery, retry").

`core.webhook_subscriptions` is tenant-owned and RLS-protected -- a
subscription is always local to one tenant, the same posture
`saas_os/core/rbac`'s `Role` (Phase 3.3) established for the simplest tenant-owned
shape: a plain `tenant_id` foreign key to `core.tenants.id`, no composite
FK needed (unlike `saas_os/core/api_keys`, there is no second identity -- like a
`user_id` -- a subscription must additionally belong to; it belongs to
exactly one tenant, full stop).

`signing_secret` is, deliberately, unlike `saas_os/core/api_keys`' `key_hash` or
`saas_os/core/identity`'s session `token_hash`, never a one-way hash: those are
*bearer credentials* validated by comparison and never need to be read
back, whereas a webhook signing secret is an HMAC key *we* use,
repeatedly, to sign every outgoing delivery, so the receiving endpoint
can verify authenticity -- there is no operation that only needs to
compare it, so a one-way hash would make delivery impossible. RLS
remains this table's primary confidentiality boundary
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.3's own Security Requirement:
"no tenant's webhook secret exposed to another tenant"). F-02 (platform
readiness audit) adds a second, defense-in-depth layer on top of RLS: the
column stores an opaque `saas_os.core.crypto.EncryptionService` ciphertext
envelope (`saas_os/core/webhooks/service.py::_encrypt_signing_secret()`/
`_decrypt_signing_secret()`), not the raw secret -- a privileged
connection that structurally bypasses RLS (e.g. the migrations role) no
longer reads a usable plaintext secret directly off this row. Widened
from the original `String(64)` (raw-secret-sized) to fit an envelope
string, which carries its own base64 framing overhead on top of the same
underlying secret material -- see
`saas_os/infra/db/migrations/versions/76a55dfb1782_widen_webhook_signing_secret_for_encryption.py`.
A pre-F-02 row's value has no `efv1:` envelope prefix -- treated as
legacy plaintext by `_decrypt_signing_secret()`, never made unreadable by
this change (that function's own docstring); no data migration/rewrite
of existing rows was required or performed.

Uses saas_os.infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only saas_os/infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from saas_os.infra.db import (
    Base,
    DateTime,
    ForeignKey,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
    now,
)


class WebhookSubscription(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One tenant's outbound webhook subscription: a destination `url`
    plus the `signing_secret` used to sign every event delivered to it.
    No `event_types` filter, no per-subscription enable/disable flag, no
    delivery-history columns -- none is specified by the roadmap's Phase
    4.3 objective ("subscription management, delivery, retry, signing"),
    and delivery/retry *execution* metadata is `saas_os/infra/jobs`' own
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
    # F-02: holds a saas_os.core.crypto ciphertext envelope for a newly created
    # subscription, or a legacy pre-F-02 plaintext secret for an
    # already-existing row (module docstring) -- 512 comfortably fits an
    # envelope built from a 32-byte token_urlsafe secret (~135 chars) with
    # headroom for a longer key-version identifier.
    signing_secret: Mapped[str] = mapped_column(String(512), nullable=False)


class WebhookReplayRecord(Base):
    """P1.10: one immutable fact -- "this `event_id` has already been
    accepted for `subscription_id` within `tenant_id`" -- the atomic
    replay-detection ledger `saas_os.core.webhooks.service.record_webhook_delivery()`
    inserts into. No `UUIDPrimaryKeyMixin`/`TimestampMixin` reuse for
    `updated_at`, mirroring `saas_os.core.usage.UsageEvent`'s own "append-only,
    never edited in place" schema signal (`saas_os/core/usage/models.py`'s own
    docstring) -- a replay record is never updated after insertion.

    The `UniqueConstraint` on `(tenant_id, subscription_id, event_id)` is
    the actual atomicity mechanism (module docstring of
    `saas_os/core/webhooks/service.py`): two concurrent inserts of the same triple
    can never both succeed -- PostgreSQL's own unique-index enforcement
    rejects the second with an `IntegrityError`, which
    `record_webhook_delivery()` maps to `WebhookReplayDetectedError`. This
    is the same "catch the constraint violation" pattern
    `saas_os/core/billing/service.py::create_plan()` already established for
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
        DateTime(timezone=True), nullable=False, server_default=now()
    )
