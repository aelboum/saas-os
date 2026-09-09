"""Audit-log model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4)
-- inspect SQLAlchemy metadata only, no database connection needed.
Mirrors tests/core/rbac/test_rbac_models.py.
"""

from __future__ import annotations

import inspect

from core.audit_log.models import ActorType, AuditLogEntry, AuditOutcome
from sqlalchemy import CheckConstraint, Table

_audit_log: Table = AuditLogEntry.__table__  # type: ignore[assignment]


def test_audit_log_table_is_schema_qualified_core() -> None:
    assert _audit_log.schema == "core"
    assert _audit_log.name == "audit_log"


def test_audit_log_has_expected_columns() -> None:
    assert {c.name for c in _audit_log.columns} == {
        "id",
        "tenant_id",
        "actor_type",
        "actor_user_id",
        "action",
        "resource_type",
        "resource_id",
        "outcome",
        "correlation_id",
        "metadata",
        "created_at",
    }


def test_audit_log_has_no_updated_at_column() -> None:
    """Deliberate: an `updated_at` column would signal a row is expected
    to change, contradicting immutability (core/audit_log/models.py's own
    docstring)."""
    assert "updated_at" not in {c.name for c in _audit_log.columns}


def test_audit_log_tenant_id_is_not_nullable() -> None:
    assert _audit_log.columns["tenant_id"].nullable is False


def test_audit_log_tenant_id_is_a_foreign_key_to_tenants() -> None:
    fk_targets = {fk.target_fullname for fk in _audit_log.foreign_keys}
    assert "core.tenants.id" in fk_targets


def test_audit_log_actor_user_id_is_a_foreign_key_to_users() -> None:
    fk_targets = {fk.target_fullname for fk in _audit_log.foreign_keys}
    assert "core.users.id" in fk_targets


def test_audit_log_actor_user_id_is_nullable() -> None:
    """Nullable at the schema level (a "system" actor has none) --
    the pairing with actor_type is enforced by a CHECK constraint, not by
    making the column itself required."""
    assert _audit_log.columns["actor_user_id"].nullable is True


def test_audit_log_action_and_resource_type_are_not_nullable() -> None:
    assert _audit_log.columns["action"].nullable is False
    assert _audit_log.columns["resource_type"].nullable is False


def test_audit_log_resource_id_is_nullable() -> None:
    assert _audit_log.columns["resource_id"].nullable is True


def test_audit_log_outcome_is_not_nullable() -> None:
    assert _audit_log.columns["outcome"].nullable is False


def test_audit_log_created_at_is_not_nullable() -> None:
    assert _audit_log.columns["created_at"].nullable is False


def test_audit_log_has_actor_pairing_check_constraint() -> None:
    names = {c.name for c in _audit_log.constraints if isinstance(c, CheckConstraint)}
    assert "ck_audit_log_actor_type_user_id_pairing" in names
    assert "ck_audit_log_actor_type" in names
    assert "ck_audit_log_outcome" in names
    assert "ck_audit_log_metadata_size" in names


def test_audit_log_has_expected_indexes() -> None:
    index_names = {i.name for i in _audit_log.indexes}
    assert index_names == {
        "ix_audit_log_tenant_created_at",
        "ix_audit_log_tenant_actor",
        "ix_audit_log_tenant_resource",
    }


def test_actor_type_enum_has_only_user_and_system() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 6: "Do NOT add
    actor types merely speculatively." """
    assert {member.value for member in ActorType} == {"user", "system"}


def test_audit_outcome_enum_has_exactly_three_values() -> None:
    assert {member.value for member in AuditOutcome} == {"success", "failure", "denied"}


def test_core_audit_log_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.audit_log.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
