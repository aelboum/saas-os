"""`ServiceAccount` model shape tests (architecture research: universal
multi-tenant tenancy, Phase E -- "Principal + Service Accounts + API Key
Hardening") -- inspect SQLAlchemy metadata only, no database connection
needed. Mirrors tests/core/identity/test_identity_models.py.
"""

from __future__ import annotations

import inspect

from core.identity.models import ServiceAccount, ServiceAccountStatus
from sqlalchemy import CheckConstraint, Table, UniqueConstraint

_service_accounts: Table = ServiceAccount.__table__  # type: ignore[assignment]


def test_service_accounts_table_is_schema_qualified_core() -> None:
    assert _service_accounts.schema == "core"
    assert _service_accounts.name == "service_accounts"


def test_service_accounts_has_expected_columns() -> None:
    assert {c.name for c in _service_accounts.columns} == {
        "id",
        "tenant_id",
        "name",
        "status",
        "created_at",
        "updated_at",
    }


def test_service_accounts_has_no_user_style_columns() -> None:
    """A service account is never a `User` -- no email, no is_active
    boolean (status is the one lifecycle field), no membership-shaped
    column."""
    names = {c.name for c in _service_accounts.columns}
    assert "email" not in names
    assert "is_active" not in names
    assert "user_id" not in names


def test_service_accounts_tenant_id_is_not_nullable() -> None:
    assert _service_accounts.columns["tenant_id"].nullable is False


def test_service_accounts_tenant_id_is_a_foreign_key_to_tenants() -> None:
    fk_targets = {fk.target_fullname for fk in _service_accounts.columns["tenant_id"].foreign_keys}
    assert "core.tenants.id" in fk_targets


def test_service_accounts_name_is_unique_within_tenant_not_globally() -> None:
    unique_column_sets = [
        {c.name for c in constraint.columns}
        for constraint in _service_accounts.constraints
        if isinstance(constraint, UniqueConstraint)
    ]
    assert {"tenant_id", "name"} in unique_column_sets


def test_service_accounts_has_composite_fk_target_shape() -> None:
    """Required by Postgres as the exact tuple `core/rbac/models.py
    ::ServiceAccountRole` and `core/api_keys/models.py::ApiKey` reference
    via composite foreign key."""
    unique_column_sets = [
        {c.name for c in constraint.columns}
        for constraint in _service_accounts.constraints
        if isinstance(constraint, UniqueConstraint)
    ]
    assert {"tenant_id", "id"} in unique_column_sets


def test_service_accounts_status_defaults_to_active() -> None:
    column = _service_accounts.columns["status"]
    assert column.default.arg == ServiceAccountStatus.ACTIVE.value  # type: ignore[union-attr]


def test_service_accounts_has_valid_status_check_constraint() -> None:
    check_constraints = [
        c
        for c in _service_accounts.constraints
        if isinstance(c, CheckConstraint) and c.name == "ck_service_accounts_valid_status"
    ]
    assert len(check_constraints) == 1
    assert "active" in str(check_constraints[0].sqltext)
    assert "disabled" in str(check_constraints[0].sqltext)


def test_service_account_status_has_exactly_two_states() -> None:
    """architecture research Phase E: "Implement only: ACTIVE, DISABLED
    ... Do not introduce complex lifecycle workflows"."""
    assert {member.value for member in ServiceAccountStatus} == {"active", "disabled"}


def test_core_identity_models_does_not_import_sqlalchemy_directly() -> None:
    import core.identity.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source


def test_service_accounts_id_column_has_no_foreign_key() -> None:
    """Sanity check distinguishing `id` (this row's own primary key) from
    `tenant_id` -- guards against accidentally swapping the two in a
    future edit."""
    assert not _service_accounts.columns["id"].foreign_keys


def test_service_account_import_does_not_use_generic_foreign_key_to_users() -> None:
    """A service account is never inserted into `core.users` -- there is
    no column here that could plausibly reference it."""
    for column in _service_accounts.columns:
        for fk in column.foreign_keys:
            assert fk.target_fullname != "core.users.id"
