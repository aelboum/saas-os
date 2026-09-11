"""RBAC model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3) --
inspect SQLAlchemy metadata only, no database connection needed. Mirrors
tests/core/identity/test_identity_models.py.
"""

from __future__ import annotations

import inspect

from core.rbac.models import DelegationGrant, MembershipRole, Permission, Role, RolePermission
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Index, Table, UniqueConstraint

_roles: Table = Role.__table__  # type: ignore[assignment]
_permissions: Table = Permission.__table__  # type: ignore[assignment]
_role_permissions: Table = RolePermission.__table__  # type: ignore[assignment]
_membership_roles: Table = MembershipRole.__table__  # type: ignore[assignment]
_delegation_grants: Table = DelegationGrant.__table__  # type: ignore[assignment]


def _unique_column_sets(table: Table) -> list[set[str]]:
    return [
        {c.name for c in constraint.columns}
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    ]


def _composite_fk_column_sets(table: Table) -> list[set[str]]:
    return [
        {c.name for c in constraint.columns}
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint) and len(constraint.columns) > 1
    ]


# --- roles -------------------------------------------------------------


def test_roles_table_is_schema_qualified_core() -> None:
    assert _roles.schema == "core"
    assert _roles.name == "roles"


def test_roles_has_expected_columns() -> None:
    assert {c.name for c in _roles.columns} == {
        "id",
        "tenant_id",
        "name",
        "created_at",
        "updated_at",
    }


def test_roles_has_no_speculative_fields() -> None:
    """No description/lifecycle/active column -- none is specified by the
    roadmap's Phase 3.3 objective (docs/IMPLEMENTATION-ROADMAP.md Phase
    3.3 section 7: "Do not add speculative fields")."""
    names = {c.name for c in _roles.columns}
    assert "description" not in names
    assert "is_active" not in names
    assert "status" not in names


def test_roles_name_is_unique_within_tenant_not_globally() -> None:
    assert {"tenant_id", "name"} in _unique_column_sets(_roles)


def test_roles_has_composite_fk_target_shape() -> None:
    assert {"tenant_id", "id"} in _unique_column_sets(_roles)


def test_roles_tenant_id_is_a_foreign_key_to_tenants() -> None:
    fk_targets = {fk.target_fullname for fk in _roles.foreign_keys}
    assert "core.tenants.id" in fk_targets


# --- permissions (global) -------------------------------------------------


def test_permissions_table_is_schema_qualified_core() -> None:
    assert _permissions.schema == "core"
    assert _permissions.name == "permissions"


def test_permissions_has_expected_columns() -> None:
    assert {c.name for c in _permissions.columns} == {
        "id",
        "resource",
        "action",
        "created_at",
        "updated_at",
    }


def test_permissions_has_no_tenant_id_column() -> None:
    """Permissions are a global capability catalog, not tenant-owned data
    (core/rbac/models.py's own docstring)."""
    assert "tenant_id" not in {c.name for c in _permissions.columns}


def test_permissions_resource_action_is_unique() -> None:
    assert {"resource", "action"} in _unique_column_sets(_permissions)


# --- role_permissions ------------------------------------------------------


def test_role_permissions_table_is_schema_qualified_core() -> None:
    assert _role_permissions.schema == "core"
    assert _role_permissions.name == "role_permissions"


def test_role_permissions_has_expected_columns() -> None:
    assert {c.name for c in _role_permissions.columns} == {
        "id",
        "tenant_id",
        "role_id",
        "permission_id",
        "created_at",
        "updated_at",
    }


def test_role_permissions_role_and_permission_is_unique() -> None:
    assert {"role_id", "permission_id"} in _unique_column_sets(_role_permissions)


def test_role_permissions_has_composite_fk_to_roles() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 18: a role_id from
    a different tenant must be structurally unreachable, not merely
    filtered by application code."""
    assert {"tenant_id", "role_id"} in _composite_fk_column_sets(_role_permissions)


def test_role_permissions_permission_id_is_a_plain_fk_to_permissions() -> None:
    fk_targets = {fk.target_fullname for fk in _role_permissions.foreign_keys}
    assert "core.permissions.id" in fk_targets


# --- membership_roles -------------------------------------------------------


def test_membership_roles_table_is_schema_qualified_core() -> None:
    assert _membership_roles.schema == "core"
    assert _membership_roles.name == "membership_roles"


def test_membership_roles_has_expected_columns() -> None:
    assert {c.name for c in _membership_roles.columns} == {
        "id",
        "tenant_id",
        "membership_id",
        "role_id",
        "scope",
        "created_at",
        "updated_at",
    }


def test_membership_roles_scope_is_not_nullable_and_defaults_to_self() -> None:
    column = _membership_roles.columns["scope"]
    assert column.nullable is False
    assert column.default.arg == "self"  # type: ignore[union-attr]


def test_membership_roles_membership_and_role_is_unique() -> None:
    assert {"membership_id", "role_id"} in _unique_column_sets(_membership_roles)


def test_membership_roles_has_composite_fk_to_tenant_memberships() -> None:
    assert {"tenant_id", "membership_id"} in _composite_fk_column_sets(_membership_roles)


def test_membership_roles_has_composite_fk_to_roles() -> None:
    assert {"tenant_id", "role_id"} in _composite_fk_column_sets(_membership_roles)


# --- delegation_grants (architecture research Phase C) ---------------------


def test_delegation_grants_table_is_schema_qualified_core() -> None:
    assert _delegation_grants.schema == "core"
    assert _delegation_grants.name == "delegation_grants"


def test_delegation_grants_has_expected_columns() -> None:
    assert {c.name for c in _delegation_grants.columns} == {
        "id",
        "tenant_id",
        "delegator_principal_type",
        "delegator_principal_id",
        "delegate_principal_type",
        "delegate_principal_id",
        "scope_mode",
        "permission_id",
        "starts_at",
        "expires_at",
        "revoked_at",
        "allow_redelegate",
        "created_at",
        "updated_at",
    }


def test_delegation_grants_has_no_resource_constraint_column() -> None:
    """Architecture research Phase C: no generic resource-constraint
    representation exists in the current permission model, so the field
    is absent rather than inventing a mini policy language."""
    assert "resource_constraint" not in {c.name for c in _delegation_grants.columns}


def test_delegation_grants_principal_type_columns_default_to_user() -> None:
    for column_name in ("delegator_principal_type", "delegate_principal_type"):
        column = _delegation_grants.columns[column_name]
        assert column.nullable is False
        assert column.default.arg == "user"  # type: ignore[union-attr]


def test_delegation_grants_principal_id_columns_are_nullable() -> None:
    """Nullable so a `'system'` principal (never constructed in this
    phase, but structurally supported) can leave it unset -- the
    CHECK-pairing invariant is enforced at the database level, not
    testable via metadata inspection alone (see the migration/integration
    tests for the live constraint)."""
    for column_name in ("delegator_principal_id", "delegate_principal_id"):
        assert _delegation_grants.columns[column_name].nullable is True


def test_delegation_grants_scope_mode_defaults_to_self() -> None:
    column = _delegation_grants.columns["scope_mode"]
    assert column.nullable is False
    assert column.default.arg == "self"  # type: ignore[union-attr]


def test_delegation_grants_allow_redelegate_defaults_to_false() -> None:
    column = _delegation_grants.columns["allow_redelegate"]
    assert column.nullable is False
    assert column.default.arg is False  # type: ignore[union-attr]


def test_delegation_grants_starts_at_is_not_nullable() -> None:
    assert _delegation_grants.columns["starts_at"].nullable is False


def test_delegation_grants_expires_at_and_revoked_at_are_nullable() -> None:
    assert _delegation_grants.columns["expires_at"].nullable is True
    assert _delegation_grants.columns["revoked_at"].nullable is True


def test_delegation_grants_permission_id_is_a_plain_fk_to_permissions() -> None:
    """Global reference, no composite-FK tenant pairing -- `Permission` is
    not tenant-owned (core/rbac/models.py::DelegationGrant's docstring)."""
    fk_targets = {fk.target_fullname for fk in _delegation_grants.foreign_keys}
    assert "core.permissions.id" in fk_targets
    assert {"tenant_id", "permission_id"} not in _composite_fk_column_sets(_delegation_grants)


def test_delegation_grants_principal_ids_are_plain_fks_to_users() -> None:
    fk_targets = {fk.target_fullname for fk in _delegation_grants.foreign_keys}
    assert "core.users.id" in fk_targets


def test_delegation_grants_tenant_id_fk_cascades_on_delete() -> None:
    """Unlike `Tenant.parent_id`'s plain (blocking) FK -- a delegation
    grant has no meaning once its own scope tenant no longer exists."""
    tenant_fks = [fk for fk in _delegation_grants.foreign_keys if fk.column.table.name == "tenants"]
    assert len(tenant_fks) == 1
    assert tenant_fks[0].ondelete == "CASCADE"


def test_delegation_grants_has_valid_scope_mode_check_constraint() -> None:
    check_texts = [
        str(c.sqltext) for c in _delegation_grants.constraints if isinstance(c, CheckConstraint)
    ]
    assert any("scope_mode" in text for text in check_texts)


def test_delegation_grants_has_valid_time_range_check_constraint() -> None:
    check_texts = [
        str(c.sqltext) for c in _delegation_grants.constraints if isinstance(c, CheckConstraint)
    ]
    assert any("starts_at" in text and "expires_at" in text for text in check_texts)


def test_delegation_grants_has_active_lookup_index() -> None:
    index_columns = [{c.name for c in index.columns} for index in _delegation_grants.indexes]
    assert {"tenant_id", "delegate_principal_type", "delegate_principal_id"} in index_columns


def test_delegation_grants_has_partial_unique_active_grant_index() -> None:
    unique_indexes = [index for index in _delegation_grants.indexes if index.unique]
    assert len(unique_indexes) == 1
    assert isinstance(unique_indexes[0], Index)
    assert unique_indexes[0].dialect_options["postgresql"]["where"] is not None


def test_no_rbac_table_has_a_direct_user_id_column() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 10: role
    assignment must anchor to TenantMembership, never directly to a
    global User (no `user.role`/`membership.role_name` shortcut)."""
    for table in (_roles, _permissions, _role_permissions, _membership_roles):
        assert "user_id" not in {c.name for c in table.columns}


def test_core_rbac_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.rbac.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
