"""Approval request model shape tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 7.2) -- inspect SQLAlchemy metadata only, no database connection
needed. Mirrors tests/core/usage/test_usage_models.py.
"""

from __future__ import annotations

import inspect

from sqlalchemy import CheckConstraint, Table

from control_plane.approvals.models import ApprovalRequest

_approval_requests: Table = ApprovalRequest.__table__  # type: ignore[assignment]


def test_approval_requests_table_is_schema_qualified_control_plane() -> None:
    assert _approval_requests.schema == "control_plane"
    assert _approval_requests.name == "approval_requests"


def test_approval_requests_has_expected_columns() -> None:
    assert {c.name for c in _approval_requests.columns} == {
        "id",
        "tenant_id",
        "proposer_user_id",
        "tool_key",
        "agent_scope_value",
        "payload",
        "status",
        "approver_user_id",
        "decided_at",
        "created_at",
        "updated_at",
    }


def test_approval_requests_required_fields_are_not_nullable() -> None:
    assert _approval_requests.columns["tenant_id"].nullable is False
    assert _approval_requests.columns["proposer_user_id"].nullable is False
    assert _approval_requests.columns["tool_key"].nullable is False
    assert _approval_requests.columns["status"].nullable is False


def test_approval_requests_decision_fields_are_nullable() -> None:
    assert _approval_requests.columns["approver_user_id"].nullable is True
    assert _approval_requests.columns["decided_at"].nullable is True
    assert _approval_requests.columns["agent_scope_value"].nullable is True


def test_approval_requests_has_plain_tenant_id_fk_not_composite() -> None:
    from sqlalchemy import ForeignKeyConstraint

    composite_fks = [
        constraint
        for constraint in _approval_requests.constraints
        if isinstance(constraint, ForeignKeyConstraint) and len(constraint.columns) > 1
    ]
    assert composite_fks == []


def test_approval_requests_has_self_approval_check_constraint() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 7.2's own Security
    Requirement: separation of duties, enforced at the database level as
    defense-in-depth (control_plane/approvals/models.py's own
    docstring)."""
    check_constraints = [
        c for c in _approval_requests.constraints if isinstance(c, CheckConstraint)
    ]
    assert any(c.name == "ck_approval_requests_no_self_approval" for c in check_constraints)


def test_control_plane_approvals_models_does_not_import_sqlalchemy_directly() -> None:
    import control_plane.approvals.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
