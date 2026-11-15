"""ORM models of the tenant audit subject reference tables (migration
`c7e3a9f2b4d8`; docs/architecture/AUDIT-IDENTITY-P3-PLAN.md, phase P3a).

Tenant-owned, under the canonical tenant RLS policy: a session bound to a
tenant sees only that tenant's rows. Only `saas_os.core.audit_log.subjects`
imports these models (owner decision O11 and ADR-0063 option A:
`tests/architecture/test_audit_subject_link_boundary.py` pins the list).

The foreign keys to `core.users` and `core.tenants` are declared by the
migration; the models name the columns only, so this module depends on
nothing outside `saas_os.infra.db` (the audit log's own rule,
`saas_os/core/audit_log/models.py`).
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from saas_os.infra.db import (
    Base,
    DateTime,
    Mapped,
    String,
    Text,
    mapped_column,
    now,
)


class TenantAuditSubjectLink(Base):
    """`subject_ref` is `gen_random_uuid()` and is never derived from the
    user id, the tenant, the day or a key. `user_id` is NULL once unlinked
    (erasure or expiry); `unlinked_at` and `unlink_reason` are then set, and
    the row can never be linked again (the one-way trigger). The partial
    unique index `uq_audit_subject_links_live (tenant_id, user_id,
    subject_day) WHERE user_id IS NOT NULL` is declared in the migration."""

    __tablename__ = "audit_subject_links"
    __table_args__ = {"schema": "core"}

    # The live-link insert omits it and the database generates it; the ORM
    # default is for the born-unlinked insert of an erased subject.
    subject_ref: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    subject_day: Mapped[date] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    unlinked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    unlink_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class TenantAuditSubjectErasure(Base):
    """The marker that a user was erased in a tenant: a later audit write
    for that user in that tenant gets a reference that is born unlinked."""

    __tablename__ = "audit_subject_erasures"
    __table_args__ = {"schema": "core"}

    tenant_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    erased_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )


class TenantAuditIdentityHold(Base):
    """A legal hold on a tenant's audit references (proposal 4.9). Nothing
    writes it in phase P3a; the erasure step reads the active holds."""

    __tablename__ = "audit_identity_holds"
    __table_args__ = {"schema": "core"}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    reference: Mapped[str] = mapped_column(String(100), nullable=False)
    from_day: Mapped[date | None] = mapped_column(nullable=True)
    to_day: Mapped[date | None] = mapped_column(nullable=True)
    subject_ref: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    placed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    placed_by_platform_audit_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_by_platform_audit_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
