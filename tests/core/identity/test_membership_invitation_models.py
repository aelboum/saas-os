"""`MembershipStatus`/`TenantMembership.status`/`Invitation` model shape
tests (architecture research: universal multi-tenant tenancy, Phase G --
"Invitation / Membership Lifecycle") -- inspect SQLAlchemy metadata only,
no database connection needed. Mirrors
tests/core/rbac/test_support_access_models.py.
"""

from __future__ import annotations

from core.identity.invitation_status import InvitationStatus, compute_invitation_status
from core.identity.models import Invitation, MembershipStatus, TenantMembership
from sqlalchemy import CheckConstraint, Table

_tenant_memberships: Table = TenantMembership.__table__  # type: ignore[assignment]
_invitations: Table = Invitation.__table__  # type: ignore[assignment]


def test_membership_status_has_three_values() -> None:
    """architecture research Phase G pre-checkpoint review: `INVITED` was
    dropped -- no code path in this phase ever produces it
    (`core/identity/models.py::MembershipStatus`'s own docstring)."""
    assert {member.value for member in MembershipStatus} == {
        "active",
        "suspended",
        "revoked",
    }


def test_tenant_memberships_has_status_column() -> None:
    column = _tenant_memberships.columns["status"]
    assert column.nullable is False
    assert column.default.arg == "active"  # type: ignore[union-attr]


def test_tenant_memberships_has_valid_status_check_constraint() -> None:
    names = {c.name for c in _tenant_memberships.constraints if isinstance(c, CheckConstraint)}
    assert "ck_tenant_memberships_valid_status" in names


def test_invitations_table_is_schema_qualified_core() -> None:
    assert _invitations.schema == "core"
    assert _invitations.name == "invitations"


def test_invitations_has_expected_columns() -> None:
    assert {c.name for c in _invitations.columns} == {
        "id",
        "tenant_id",
        "invited_email",
        "token_hash",
        "inviter_user_id",
        "expires_at",
        "accepted_at",
        "accepted_by_user_id",
        "revoked_at",
        "revoked_by_user_id",
        "created_at",
        "updated_at",
    }


def test_invitations_has_no_stored_status_column() -> None:
    """architecture research Phase G: the conceptual lifecycle is a
    read-time projection of timestamps, never a second, driftable status
    column (`Invitation`'s own docstring)."""
    assert "status" not in {c.name for c in _invitations.columns}


def test_invitations_has_no_raw_token_column() -> None:
    names = {c.name for c in _invitations.columns}
    assert "token" not in names
    assert "raw_token" not in names


def test_invitations_tenant_id_is_not_nullable() -> None:
    assert _invitations.columns["tenant_id"].nullable is False


def test_invitations_tenant_id_fk_cascades_on_delete() -> None:
    fk = next(iter(_invitations.columns["tenant_id"].foreign_keys))
    assert fk.ondelete == "CASCADE"


def test_invitations_invited_email_is_not_nullable() -> None:
    assert _invitations.columns["invited_email"].nullable is False


def test_invitations_token_hash_is_unique_and_not_nullable() -> None:
    column = _invitations.columns["token_hash"]
    assert column.nullable is False
    assert column.unique is True


def test_invitations_inviter_user_id_is_not_nullable() -> None:
    assert _invitations.columns["inviter_user_id"].nullable is False


def test_invitations_expires_at_is_not_nullable() -> None:
    assert _invitations.columns["expires_at"].nullable is False


def test_invitations_acceptance_revocation_columns_are_nullable() -> None:
    for column_name in (
        "accepted_at",
        "accepted_by_user_id",
        "revoked_at",
        "revoked_by_user_id",
    ):
        assert _invitations.columns[column_name].nullable is True


def test_invitations_has_time_range_and_pairing_check_constraints() -> None:
    names = {c.name for c in _invitations.constraints if isinstance(c, CheckConstraint)}
    assert "ck_invitations_valid_time_range" in names
    assert "ck_invitations_acceptance_pairing" in names
    assert "ck_invitations_revocation_pairing" in names
    assert "ck_invitations_not_accepted_and_revoked" in names


def test_invitations_has_live_lookup_and_partial_unique_indexes() -> None:
    index_columns = [{c.name for c in index.columns} for index in _invitations.indexes]
    assert {"tenant_id", "invited_email"} in index_columns
    unique_indexes = [index for index in _invitations.indexes if index.unique]
    assert len(unique_indexes) == 1
    assert unique_indexes[0].dialect_options["postgresql"]["where"] is not None


def test_invitation_status_has_four_values() -> None:
    assert {member.value for member in InvitationStatus} == {
        "pending",
        "accepted",
        "expired",
        "revoked",
    }


def test_compute_invitation_status_projects_timestamps() -> None:
    import uuid
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    pending = Invitation(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        invited_email="a@example.com",
        token_hash="x" * 64,
        inviter_user_id=uuid.uuid4(),
        expires_at=now + timedelta(days=1),
    )
    assert compute_invitation_status(pending, now=now) == InvitationStatus.PENDING

    expired = Invitation(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        invited_email="a@example.com",
        token_hash="y" * 64,
        inviter_user_id=uuid.uuid4(),
        expires_at=now - timedelta(minutes=1),
    )
    assert compute_invitation_status(expired, now=now) == InvitationStatus.EXPIRED

    accepted = Invitation(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        invited_email="a@example.com",
        token_hash="z" * 64,
        inviter_user_id=uuid.uuid4(),
        expires_at=now + timedelta(days=1),
        accepted_at=now,
        accepted_by_user_id=uuid.uuid4(),
    )
    assert compute_invitation_status(accepted, now=now) == InvitationStatus.ACCEPTED

    revoked = Invitation(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        invited_email="a@example.com",
        token_hash="w" * 64,
        inviter_user_id=uuid.uuid4(),
        expires_at=now + timedelta(days=1),
        revoked_at=now,
        revoked_by_user_id=uuid.uuid4(),
    )
    assert compute_invitation_status(revoked, now=now) == InvitationStatus.REVOKED
