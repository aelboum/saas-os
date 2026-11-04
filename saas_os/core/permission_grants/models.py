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
    UUIDArray,
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


class PermissionGrantLedgerHold(Base, UUIDPrimaryKeyMixin):
    """A legal hold on one tenant's permission grant ledger rows (owner
    policy of 2026-11-02; migration `a9c3e5f7b1d4`). Active while
    `released_at` is NULL: an active hold keeps the tenant's ledger rows
    from becoming eligible for expiry, whatever their age. A released hold
    stays as history.

    Global and platform-owned (the tenant-context exclusion policy of the
    platform-authority tables): no tenant-scoped transaction can read or
    change it. The runtime role may insert a hold and set its two release
    columns, never delete it or change anything else. `reference` is an
    opaque, identifier-shaped reference to the legal matter (no name, no
    personal data); the two `*_platform_audit_id` columns name the
    platform audit rows that placed and released it."""

    __tablename__ = "permission_grant_ledger_holds"
    __table_args__ = (
        CheckConstraint(
            "(released_at IS NULL) = (released_by_platform_audit_id IS NULL)",
            name="ck_permission_grant_ledger_holds_release_pairing",
        ),
        {"schema": "core"},
    )

    target_tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False
    )
    reference: Mapped[str] = mapped_column(String(100), nullable=False)
    placed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    placed_by_platform_audit_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_by_platform_audit_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)


# --- the approval mechanism (owner decisions of 2026-11-02 and 2026-11-03;
# migration `c3f9e1a7b5d2`; docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md).
# Global, platform-owned tables with the tenant-context exclusion policy. The
# database forces every time column from its own clock, checks the copies and
# the shapes, refuses every DELETE and every UPDATE except the one-way consume
# or invalidate pair, and requires each row's own platform audit row in the
# same transaction. Ids, counts, digests and opaque references only.

REGISTER_PROPOSAL = "representative_designation_proposal"
REGISTER_DESIGNATION = "representative_designation"
REGISTER_DESIGNATION_REVOCATION = "representative_revocation"
REGISTER_ENROLMENT = "approver_enrolment"
REGISTER_ENROLMENT_REVOCATION = "approver_revocation"
REGISTER_ENTRY_TYPES: tuple[str, ...] = (
    REGISTER_PROPOSAL,
    REGISTER_DESIGNATION,
    REGISTER_DESIGNATION_REVOCATION,
    REGISTER_ENROLMENT,
    REGISTER_ENROLMENT_REVOCATION,
)


class ApproverRegisterEntry(Base, UUIDPrimaryKeyMixin):
    """One append-only entry of the approver eligibility register: a
    representative designation proposal (by a platform owner), its
    confirmation (by an independent security operator), an approver
    enrolment (by a representative), or a revocation of either. The
    `*_ref` columns are opaque identifiers of records kept outside SaaS OS
    (the designation by the governing body, the verification of a
    distinct natural person, the authorisation by the representative, the
    ticket), never personal data. `recorded_by_user_id` is the
    authenticated user whose platform-admin session wrote it."""

    __tablename__ = "permission_grant_ledger_approver_register"
    __table_args__ = {"schema": "core"}

    entry_type: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), nullable=False)
    recorded_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.users.id"), nullable=False
    )
    designation_ref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    natural_person_ref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verification_ref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    authorisation_ref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ticket_ref: Mapped[str] = mapped_column(String(100), nullable=False)
    proposal_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.permission_grant_ledger_approver_register.id"), nullable=True
    )
    authorised_by_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.permission_grant_ledger_approver_register.id"), nullable=True
    )
    revokes_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.permission_grant_ledger_approver_register.id"), nullable=True
    )
    renews_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.permission_grant_ledger_approver_register.id"), nullable=True
    )
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    eligible_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    proposal_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    recorded_by_platform_audit_id: Mapped[uuid.UUID] = mapped_column(nullable=False)


class LedgerDeletionRequest(Base, UUIDPrimaryKeyMixin):
    """A request to delete the expired ledger rows of exactly `tenant_ids`
    (sorted, distinct), bound to the eligible row count and digest a report
    showed. Expires 72 hours after it is made unless approved."""

    __tablename__ = "permission_grant_ledger_deletion_requests"
    __table_args__ = {"schema": "core"}

    tenant_ids: Mapped[list[uuid.UUID]] = mapped_column(UUIDArray(), nullable=False)
    scope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    eligible_ledger_rows: Mapped[int] = mapped_column(Integer, nullable=False)
    eligible_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.users.id"), nullable=False
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    requested_by_platform_audit_id: Mapped[uuid.UUID] = mapped_column(nullable=False)


class LedgerDeletionApproval(Base, UUIDPrimaryKeyMixin):
    """The approval of one request: copies of its four bound values,
    single use (`consumed_*`, set only by the migrations-role deletion) and
    valid for 72 hours, or invalidated (`invalidated_*`) by a revocation
    of the eligibility of its approver."""

    __tablename__ = "permission_grant_ledger_deletion_approvals"
    __table_args__ = {"schema": "core"}

    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.permission_grant_ledger_deletion_requests.id"), nullable=False
    )
    tenant_ids: Mapped[list[uuid.UUID]] = mapped_column(UUIDArray(), nullable=False)
    scope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    eligible_ledger_rows: Mapped[int] = mapped_column(Integer, nullable=False)
    eligible_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.users.id"), nullable=False
    )
    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    approved_by_platform_audit_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by_platform_audit_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    invalidated_by_platform_audit_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)


class LedgerExecutionAuthorization(Base, UUIDPrimaryKeyMixin):
    """The authorisation, by someone other than the approver, to run the
    migrations-role deletion of one approval: single use, valid for 60
    minutes and never past the approval, invalidated by a revocation of
    the eligibility of its authoriser."""

    __tablename__ = "permission_grant_ledger_deletion_execution_authorizations"
    __table_args__ = {"schema": "core"}

    approval_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.permission_grant_ledger_deletion_approvals.id"), nullable=False
    )
    authorized_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.users.id"), nullable=False
    )
    authorized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
    authorized_by_platform_audit_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by_platform_audit_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    invalidated_by_platform_audit_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
