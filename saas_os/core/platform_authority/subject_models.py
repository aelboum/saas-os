"""Platform audit subject reference tables
(docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections 4.3
and 4.4, platform variants; migration `e2b7c4d9a1f6`).

    core.platform_audit_subject_links     reference -> user, one live link per user and UTC day
    core.platform_audit_subject_erasures  one marker per erased user
    core.platform_audit_identity_holds    legal holds (placed and released in a later phase)

All three are global (no `tenant_id`), carry the tenant-context exclusion
policy of the platform tables and are `SECURITY_RETAIN`. The runtime role
has no `DELETE` on any of them and may `UPDATE` only the columns of one
designed one-way change (an unlink; a hold release); a database trigger
refuses every other update for every role.

**Who may import these classes.** The link table is the only place that can
turn a reference in a platform audit row back into a user. Application-role
code could read it (the database does not restrict that: owner decision O11,
2026-11-03, accepts API and code enforcement plus architecture tests for
now), so only the modules that must touch it name these classes:
`saas_os.core.platform_authority.subjects` (get-or-create and the erasure
step) and, in later phases, the lookup and expiry modules.
`tests/architecture/test_audit_subject_link_boundary.py` enforces the list.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from saas_os.infra.db import (
    Base,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Mapped,
    String,
    Text,
    mapped_column,
    now,
)


class PlatformAuditSubjectLink(Base):
    """`subject_ref` is `gen_random_uuid()` and is never derived from the
    user id, the day or a key. `user_id` is NULL once unlinked (erasure or
    expiry); `unlinked_at` and `unlink_reason` are then set, and the row
    can never be linked again (the one-way trigger). The partial unique
    index `uq_platform_audit_subject_links_live (user_id, subject_day) WHERE
    user_id IS NOT NULL` is declared in the migration only."""

    __tablename__ = "platform_audit_subject_links"
    __table_args__ = {"schema": "core"}

    # The live-link insert omits it and the database generates it
    # (`gen_random_uuid()`); the ORM default is for the born-unlinked insert
    # of an erased subject (`uuid.uuid4()`, also `os.urandom`: the proposal,
    # section 4.2, calls the two equivalent).
    subject_ref: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("core.users.id"), nullable=True)
    subject_day: Mapped[date] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    unlinked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    unlink_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class PlatformAuditSubjectErasure(Base):
    """The marker that a user was erased: a later audit write for that user
    gets a reference that is born unlinked."""

    __tablename__ = "platform_audit_subject_erasures"
    __table_args__ = {"schema": "core"}

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), primary_key=True)
    erased_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )


class PlatformAuditIdentityHold(Base):
    """A legal hold on platform audit references (proposal 4.9). Nothing
    writes it in phase P1; the erasure step reads the active holds."""

    __tablename__ = "platform_audit_identity_holds"
    __table_args__ = (
        CheckConstraint(
            "reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$'",
            name="ck_platform_audit_identity_holds_reference",
        ),
        {"schema": "core"},
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
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
