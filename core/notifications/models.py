"""Notification entity (docs/IMPLEMENTATION-ROADMAP.md Phase 4.4;
docs/ARCHITECTURE.md section 4: "core/notifications -- Notification
dispatch pipeline (templates are Product-supplied via the contract)").

`core.notifications` is tenant-owned and RLS-protected -- a notification
always belongs to exactly one tenant and is addressed to exactly one
recipient (a `core/identity` `User`). Unlike `core/webhooks`' plain
`tenant_id` FK (no second identity to guard against), a notification's
`(tenant_id, recipient_user_id)` pair must be a genuine tenant membership
-- the same composite-FK integrity guarantee `core/api_keys` established
in Phase 4.1 for its own `(tenant_id, user_id)` pair, reused verbatim
here: a notification can only ever exist for a user who is a real member
of that tenant, enforced by Postgres itself via a composite foreign key
to `core.tenant_memberships(tenant_id, user_id)`, not merely by
application code remembering to check.

No template/content-authoring fields exist here -- `docs/ARCHITECTURE.md`
section 4 explicitly defers "templates" to the future Product Contract;
this module owns generic dispatch mechanics only. No `read_at`/`read`
flag either -- that is a Product-layer UX concept (has the recipient seen
this in their inbox?), not part of the roadmap's Phase 4.4 "dispatch"
objective, and is not added speculatively.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid

from infra.db import (
    Base,
    ForeignKeyConstraint,
    Mapped,
    String,
    Text,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class Notification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One dispatched (or attempted) notification. `channel` is a plain
    string (e.g. `"in_app"`) rather than a database enum -- new channels
    are added by extending `core/notifications/service.py`'s dispatch
    registry, never by a schema migration, mirroring how
    `core/audit_log`'s `actor_type`/`outcome` are plain strings validated
    at the application layer. `status` records this dispatch attempt's
    outcome (`"sent"` / `"failed"`) -- generic execution retry/backoff
    bookkeeping itself remains `infra/jobs`' own ownership
    (docs/DATA-ARCHITECTURE.md section 5), not duplicated here.
    """

    __tablename__ = "notifications"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "recipient_user_id"],
            ["core.tenant_memberships.tenant_id", "core.tenant_memberships.user_id"],
            name="fk_notifications_tenant_membership",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    recipient_user_id: Mapped[uuid.UUID] = mapped_column(nullable=False)

    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
