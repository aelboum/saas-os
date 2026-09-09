"""`Tenant` model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1) --
inspect SQLAlchemy metadata only, no database connection needed.
"""

from __future__ import annotations

from core.tenancy.models import Tenant
from sqlalchemy import Table

_table: Table = Tenant.__table__  # type: ignore[assignment]


def test_tenant_table_is_schema_qualified_core() -> None:
    assert _table.schema == "core"
    assert _table.name == "tenants"


def test_tenant_has_expected_columns() -> None:
    columns = {c.name for c in _table.columns}
    assert columns == {"id", "name", "status", "created_at", "updated_at"}


def test_tenant_id_is_the_primary_key() -> None:
    pk_columns = {c.name for c in _table.primary_key.columns}
    assert pk_columns == {"id"}


def test_name_and_status_are_not_nullable() -> None:
    assert _table.columns["name"].nullable is False
    assert _table.columns["status"].nullable is False


def test_core_tenancy_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import inspect

    import core.tenancy.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
