"""RBAC model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3) --
inspect SQLAlchemy metadata only, no database connection needed. Mirrors
tests/core/identity/test_identity_models.py.
"""

from __future__ import annotations

import inspect

from core.rbac.models import MembershipRole, Permission, Role, RolePermission
from sqlalchemy import ForeignKeyConstraint, Table, UniqueConstraint

_roles: Table = Role.__table__  # type: ignore[assignment]
_permissions: Table = Permission.__table__  # type: ignore[assignment]
_role_permissions: Table = RolePermission.__table__  # type: ignore[assignment]
_membership_roles: Table = MembershipRole.__table__  # type: ignore[assignment]


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
        "created_at",
        "updated_at",
    }


def test_membership_roles_membership_and_role_is_unique() -> None:
    assert {"membership_id", "role_id"} in _unique_column_sets(_membership_roles)


def test_membership_roles_has_composite_fk_to_tenant_memberships() -> None:
    assert {"tenant_id", "membership_id"} in _composite_fk_column_sets(_membership_roles)


def test_membership_roles_has_composite_fk_to_roles() -> None:
    assert {"tenant_id", "role_id"} in _composite_fk_column_sets(_membership_roles)


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
