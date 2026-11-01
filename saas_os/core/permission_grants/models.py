"""The permission grant migration ledger (ADR 0060, option C), created by
migration `e8f3b1d5a2c7`.

`core.permission_grant_applications` is tenant-owned and RLS-protected: one
row per `(tenant, namespace, migration id)` once that migration was applied
to that tenant. The runtime role may read and insert rows, never update or
delete them (UPDATE and DELETE are revoked). A row means "applied once,
never re-evaluated": a later revocation by the tenant's administrator
stands.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from saas_os.infra.db import (
    Base,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Mapped,
    String,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
    now,
)

APPLICATION_OUTCOME_APPLIED = "applied"
APPLICATION_OUTCOME_ROLE_MISSING = "role_missing"


class PermissionGrantApplication(Base, UUIDPrimaryKeyMixin):
    """One permission grant migration applied to one tenant: `outcome` is
    `applied` (its grants were added, `grants_added` of them new) or
    `role_missing` (the tenant has no role of the declared name; nothing
    was created). `content_digest` is the declaration's digest as applied;
    `applied_by_platform_audit_id` the id of the run's platform audit row."""

    __tablename__ = "permission_grant_applications"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "namespace",
            "migration_id",
            name="uq_permission_grant_applications_tenant_namespace_migration",
        ),
        CheckConstraint(
            "outcome IN ('applied', 'role_missing')",
            name="ck_permission_grant_applications_outcome",
        ),
        CheckConstraint("grants_added >= 0", name="ck_permission_grant_applications_grants_added"),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    namespace: Mapped[str] = mapped_column(String(100), nullable=False)
    migration_id: Mapped[str] = mapped_column(String(100), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    grants_added: Mapped[int] = mapped_column(Integer, nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    applied_by_platform_audit_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
