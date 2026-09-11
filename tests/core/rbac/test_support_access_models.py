"""`SupportAccessRequest` model shape tests (architecture research:
universal multi-tenant tenancy, Phase F -- "Audit + Support Access") --
inspect SQLAlchemy metadata only, no database connection needed. Mirrors
tests/core/rbac/test_rbac_models.py.
"""

from __future__ import annotations

from core.rbac.models import SupportAccessRequest
from core.rbac.support_status import SupportAccessStatus
from sqlalchemy import CheckConstraint, Table

_support_access_requests: Table = SupportAccessRequest.__table__  # type: ignore[assignment]


def test_support_access_requests_table_is_schema_qualified_core() -> None:
    assert _support_access_requests.schema == "core"
    assert _support_access_requests.name == "support_access_requests"


def test_support_access_requests_has_expected_columns() -> None:
    assert {c.name for c in _support_access_requests.columns} == {
        "id",
        "tenant_id",
        "requester_user_id",
        "scope_mode",
        "reason",
        "requested_starts_at",
        "requested_expires_at",
        "approved_at",
        "approved_by_user_id",
        "denied_at",
        "denied_by_user_id",
        "revoked_at",
        "revoked_by_user_id",
        "created_at",
        "updated_at",
    }


def test_support_access_requests_has_no_stored_status_column() -> None:
    """architecture research Phase F: the conceptual lifecycle is a
    read-time projection of timestamps, never a second, driftable status
    column (`SupportAccessRequest`'s own docstring)."""
    names = {c.name for c in _support_access_requests.columns}
    assert "status" not in names


def test_support_access_requests_has_no_permission_id_column() -> None:
    """architecture research Phase F: tenant-level access, never a
    per-permission grant like `DelegationGrant`/`DenyGrant`."""
    assert "permission_id" not in {c.name for c in _support_access_requests.columns}


def test_support_access_requests_tenant_id_is_not_nullable() -> None:
    assert _support_access_requests.columns["tenant_id"].nullable is False


def test_support_access_requests_tenant_id_fk_cascades_on_delete() -> None:
    fk = next(iter(_support_access_requests.columns["tenant_id"].foreign_keys))
    assert fk.ondelete == "CASCADE"


def test_support_access_requests_requester_user_id_is_not_nullable() -> None:
    assert _support_access_requests.columns["requester_user_id"].nullable is False


def test_support_access_requests_reason_is_not_nullable() -> None:
    assert _support_access_requests.columns["reason"].nullable is False


def test_support_access_requests_requested_expires_at_is_not_nullable() -> None:
    """architecture research Phase F: "have a bounded expiration" -- unlike
    `DelegationGrant.expires_at`, this is required, never optional."""
    assert _support_access_requests.columns["requested_expires_at"].nullable is False


def test_support_access_requests_approval_denial_revocation_columns_are_nullable() -> None:
    for column_name in (
        "approved_at",
        "approved_by_user_id",
        "denied_at",
        "denied_by_user_id",
        "revoked_at",
        "revoked_by_user_id",
    ):
        assert _support_access_requests.columns[column_name].nullable is True


def test_support_access_requests_scope_mode_defaults_to_self() -> None:
    column = _support_access_requests.columns["scope_mode"]
    assert column.nullable is False
    assert column.default.arg == "self"  # type: ignore[union-attr]


def test_support_access_requests_has_valid_scope_mode_check_constraint() -> None:
    names = {c.name for c in _support_access_requests.constraints if isinstance(c, CheckConstraint)}
    assert "ck_support_access_requests_valid_scope_mode" in names


def test_support_access_requests_has_valid_time_range_check_constraint() -> None:
    names = {c.name for c in _support_access_requests.constraints if isinstance(c, CheckConstraint)}
    assert "ck_support_access_requests_valid_time_range" in names


def test_support_access_requests_has_no_self_approval_check_constraint() -> None:
    names = {c.name for c in _support_access_requests.constraints if isinstance(c, CheckConstraint)}
    assert "ck_support_access_requests_no_self_approval" in names


def test_support_access_requests_has_revoke_requires_approval_check_constraint() -> None:
    names = {c.name for c in _support_access_requests.constraints if isinstance(c, CheckConstraint)}
    assert "ck_support_access_requests_revoke_requires_approval" in names


def test_support_access_requests_has_not_approved_and_denied_check_constraint() -> None:
    names = {c.name for c in _support_access_requests.constraints if isinstance(c, CheckConstraint)}
    assert "ck_support_access_requests_not_approved_and_denied" in names


def test_support_access_requests_has_pairing_check_constraints() -> None:
    names = {c.name for c in _support_access_requests.constraints if isinstance(c, CheckConstraint)}
    assert "ck_support_access_requests_approval_pairing" in names
    assert "ck_support_access_requests_denial_pairing" in names
    assert "ck_support_access_requests_revocation_pairing" in names


def test_support_access_requests_has_active_lookup_index() -> None:
    index_columns = [{c.name for c in index.columns} for index in _support_access_requests.indexes]
    assert {"tenant_id", "requester_user_id"} in index_columns


def test_support_access_requests_has_partial_unique_live_index() -> None:
    unique_indexes = [index for index in _support_access_requests.indexes if index.unique]
    assert len(unique_indexes) == 1
    assert unique_indexes[0].dialect_options["postgresql"]["where"] is not None


def test_support_access_status_has_six_values() -> None:
    assert {member.value for member in SupportAccessStatus} == {
        "requested",
        "approved",
        "active",
        "expired",
        "revoked",
        "denied",
    }
