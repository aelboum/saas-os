"""Platform-authority tables
(docs/ADR/0045-installation-scoped-platform-authority.md sections 3 and 8).

Three global tables. None has a `tenant_id` column and none belongs to a
tenant: they record who may administer this deployment and the evidence of
what was done with that authority.

    core.platform_operators   one live row per enrolled user
    core.platform_grants      one row per platform permission granted
    core.platform_audit_log   platform evidence, append-only

Each carries the tenant-context exclusion policy
(`saas_os.infra.db.tenant_context_exclusion_statements()`): its rows are
unreachable from any transaction bound to a tenant. That policy is defence
in depth. It is not what authorizes a platform operation;
`saas_os.core.platform_authority.authorization` is.

Rows are never deleted. The application role has no `DELETE` on any of the
three tables, and no `UPDATE` on the audit table. An operator is revoked
(terminal) and a grant is revoked (`revoked_at`); granting the same
permission again inserts a new row, so the rows for one
`(operator_id, permission)` are its history.

The partial unique indexes (one non-revoked operator per user; one live
grant per operator and permission) are declared in the migration only, as
elsewhere in this repository: the migration history, not ORM metadata, is
the source of truth for the schema.

`PlatformAuditLogEntry.target_tenant_id` is deliberately not named
`tenant_id`. It records which tenant an action concerned and confers no
ownership, and the isolation and retention audits key on that column name.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from saas_os.infra.db import (
    JSON,
    Base,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Mapped,
    String,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    mapped_column,
    now,
)


class OperatorStatus(enum.StrEnum):
    """`REVOKED` is terminal. A suspended operator keeps its grant rows and
    has no authority until reactivated."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class PlatformActorType(enum.StrEnum):
    """Who acted. A person is always `USER`; `SYSTEM` is the bootstrap and
    recovery command (and, in later phases, provisioning and purge). No
    operation performed by a person is ever recorded as `SYSTEM`."""

    USER = "user"
    SYSTEM = "system"


class PlatformAuditOutcome(enum.StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class PlatformOperator(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A `core.users` user enrolled to hold platform authority in this
    deployment. `enrolled_by_user_id` is `NULL` when the bootstrap or
    recovery command enrolled the operator."""

    __tablename__ = "platform_operators"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'suspended', 'revoked')", name="ck_platform_operators_status"
        ),
        {"schema": "core"},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    enrolled_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    status_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    status_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )


class PlatformGrant(Base, UUIDPrimaryKeyMixin):
    """One platform permission held by one operator. Revoked, never
    deleted. `granted_by_user_id` is `NULL` when the bootstrap or recovery
    command created the grant."""

    __tablename__ = "platform_grants"
    __table_args__ = (
        Index("ix_platform_grants_operator_id", "operator_id"),
        {"schema": "core"},
    )

    operator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.platform_operators.id"), nullable=False
    )
    permission: Mapped[str] = mapped_column(String(100), nullable=False)
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )


class PlatformAuditLogEntry(Base, UUIDPrimaryKeyMixin):
    """One immutable platform audit record. No `updated_at`: the row is
    never changed, and the application role could not change it."""

    __tablename__ = "platform_audit_log"
    __table_args__ = (
        CheckConstraint(
            "(actor_type = 'user' AND actor_user_id IS NOT NULL AND system_authority IS NULL) "
            "OR (actor_type = 'system' AND actor_user_id IS NULL "
            "AND system_authority IS NOT NULL)",
            name="ck_platform_audit_log_actor_pairing",
        ),
        CheckConstraint(
            "actor_type IN ('user', 'system')", name="ck_platform_audit_log_actor_type"
        ),
        CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')", name="ck_platform_audit_log_outcome"
        ),
        CheckConstraint(
            "metadata IS NULL OR octet_length(metadata::text) <= 8192",
            name="ck_platform_audit_log_metadata_size",
        ),
        {"schema": "core"},
    )

    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    system_authority: Mapped[str | None] = mapped_column(String(50), nullable=True)
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    target_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=True
    )
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # `metadata` is reserved on a declarative class; the column itself is
    # named `metadata`, as in `core.audit_log` (same attribute name there).
    entry_metadata: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
