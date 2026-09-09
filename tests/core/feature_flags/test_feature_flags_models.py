"""Feature-flag model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase
4.2) -- inspect SQLAlchemy metadata only, no database connection needed.
Mirrors tests/core/rbac/test_rbac_models.py.
"""

from __future__ import annotations

import inspect

from core.feature_flags.models import FeatureFlag, FeatureFlagTenantOverride
from sqlalchemy import Table, UniqueConstraint

_feature_flags: Table = FeatureFlag.__table__  # type: ignore[assignment]
_overrides: Table = FeatureFlagTenantOverride.__table__  # type: ignore[assignment]


def _unique_column_sets(table: Table) -> list[set[str]]:
    return [
        {c.name for c in constraint.columns}
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    ]


# --- feature_flags (global) -------------------------------------------------


def test_feature_flags_table_is_schema_qualified_core() -> None:
    assert _feature_flags.schema == "core"
    assert _feature_flags.name == "feature_flags"


def test_feature_flags_has_expected_columns() -> None:
    assert {c.name for c in _feature_flags.columns} == {
        "id",
        "key",
        "enabled_by_default",
        "created_at",
        "updated_at",
    }


def test_feature_flags_has_no_tenant_id_column() -> None:
    """A flag definition is a global capability declaration, not
    tenant-owned data (core/feature_flags/models.py's own docstring)."""
    assert "tenant_id" not in {c.name for c in _feature_flags.columns}


def test_feature_flags_key_is_unique() -> None:
    assert _feature_flags.columns["key"].unique is True


def test_feature_flags_enabled_by_default_is_not_nullable() -> None:
    assert _feature_flags.columns["enabled_by_default"].nullable is False


# --- feature_flag_tenant_overrides ------------------------------------------


def test_overrides_table_is_schema_qualified_core() -> None:
    assert _overrides.schema == "core"
    assert _overrides.name == "feature_flag_tenant_overrides"


def test_overrides_has_expected_columns() -> None:
    assert {c.name for c in _overrides.columns} == {
        "id",
        "tenant_id",
        "flag_id",
        "enabled",
        "created_at",
        "updated_at",
    }


def test_overrides_tenant_id_is_not_nullable() -> None:
    assert _overrides.columns["tenant_id"].nullable is False


def test_overrides_enabled_is_not_nullable() -> None:
    assert _overrides.columns["enabled"].nullable is False


def test_overrides_tenant_and_flag_is_unique() -> None:
    assert {"tenant_id", "flag_id"} in _unique_column_sets(_overrides)


def test_overrides_tenant_id_is_a_foreign_key_to_tenants() -> None:
    fk_targets = {fk.target_fullname for fk in _overrides.foreign_keys}
    assert "core.tenants.id" in fk_targets


def test_overrides_flag_id_is_a_plain_fk_to_feature_flags() -> None:
    """No composite FK here -- feature_flags is global, the same reason
    `core.role_permissions.permission_id` is a plain FK to `core.permissions`
    rather than a composite one (core/feature_flags/models.py docstring)."""
    fk_targets = {fk.target_fullname for fk in _overrides.foreign_keys}
    assert "core.feature_flags.id" in fk_targets


def test_core_feature_flags_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.feature_flags.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
