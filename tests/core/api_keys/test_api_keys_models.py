"""API key model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase 4.1) --
inspect SQLAlchemy metadata only, no database connection needed. Mirrors
tests/core/audit_log/test_audit_log_models.py.
"""

from __future__ import annotations

import inspect

from core.api_keys.models import ApiKey
from sqlalchemy import ForeignKeyConstraint, Table

_api_keys: Table = ApiKey.__table__  # type: ignore[assignment]


def test_api_keys_table_is_schema_qualified_core() -> None:
    assert _api_keys.schema == "core"
    assert _api_keys.name == "api_keys"


def test_api_keys_has_expected_columns() -> None:
    assert {c.name for c in _api_keys.columns} == {
        "id",
        "tenant_id",
        "user_id",
        "name",
        "key_hash",
        "created_at",
        "revoked_at",
    }


def test_api_keys_has_no_updated_at_column() -> None:
    assert "updated_at" not in {c.name for c in _api_keys.columns}


def test_api_keys_has_no_plaintext_key_column() -> None:
    """Only a hash is ever persisted (docs/IMPLEMENTATION-ROADMAP.md Phase
    4.1 Security Requirement: "keys are stored hashed, never in
    plaintext")."""
    names = {c.name for c in _api_keys.columns}
    assert "key" not in names
    assert "raw_key" not in names
    assert "secret" not in names


def test_api_keys_key_hash_is_unique() -> None:
    assert _api_keys.columns["key_hash"].unique is True


def test_api_keys_tenant_id_and_user_id_are_not_nullable() -> None:
    assert _api_keys.columns["tenant_id"].nullable is False
    assert _api_keys.columns["user_id"].nullable is False


def test_api_keys_revoked_at_is_nullable() -> None:
    assert _api_keys.columns["revoked_at"].nullable is True


def test_api_keys_has_composite_fk_to_tenant_memberships() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 4.1: the RLS-equivalent
    integrity guarantee for this global table -- a key can only exist for
    a real (tenant_id, user_id) membership."""
    composite_fks = [
        {c.name for c in constraint.columns}
        for constraint in _api_keys.constraints
        if isinstance(constraint, ForeignKeyConstraint) and len(constraint.columns) > 1
    ]
    assert {"tenant_id", "user_id"} in composite_fks


def test_core_api_keys_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.api_keys.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
