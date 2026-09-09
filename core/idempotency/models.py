"""IdempotencyRecord entity (P1.11 -- Generic Idempotency).

`core.idempotency_records` is tenant-owned and RLS-protected -- an
idempotency record always belongs to exactly one tenant, the same plain
`tenant_id`-FK shape `core.usage_events`/`core.webhook_replay_records`
already established.

Scope is `(tenant_id, operation, idempotency_key)` -- deliberately three
columns, not two (`core/idempotency/service.py`'s own docstring): a bare
`tenant_id + idempotency_key` would let two unrelated operations
(`"billing.subscribe"` vs `"usage.consume_quota"`) collide on a client
that happens to reuse the same key string for both, silently returning
one operation's cached result for a completely different one. Including
`operation` in the unique constraint makes that structurally impossible.

`fingerprint` is a SHA-256 hex digest of the canonicalized request
payload relevant to the operation (`core/idempotency/service.py::
compute_fingerprint()`) -- never the raw payload itself, and never an
authorization header/token/secret. Storing only the digest is what lets
`(same key, different request)` be detected deterministically without
retaining the original request content.

`result` is a small, JSON-serializable, non-sensitive summary of the
operation's outcome -- never a raw HTTP response, a secret, or a large
payload (`core/idempotency/service.py`'s own callers construct this
explicitly, they never serialize an arbitrary object graph).

No `REVOKE` on this table (mirrors `core.usage_events`/
`core.webhook_replay_records`): `status`/`result` are updated in place as
an operation resolves, and retention cleanup needs ordinary `DELETE` --
the default grant is unmodified.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from infra.db import (
    JSON,
    Base,
    DateTime,
    ForeignKey,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class IdempotencyRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One idempotency reservation/outcome for `(tenant_id, operation,
    idempotency_key)`. `TimestampMixin`'s `updated_at` (unlike
    `core.usage_events`/`core.webhook_replay_records`, which are
    append-only) is load-bearing here: a record legitimately transitions
    `pending -> succeeded` (or is reset back to `pending` for a retryable
    abandoned/failed attempt, `core/idempotency/service.py`'s own
    docstring), and `updated_at` is what staleness/TTL checks key off of.
    """

    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "operation",
            "idempotency_key",
            name="uq_idempotency_records_tenant_operation_key",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    operation: Mapped[str] = mapped_column(String(100), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
