"""Notification model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase
4.4) -- inspect SQLAlchemy metadata only, no database connection needed.
Mirrors tests/core/webhooks/test_webhooks_models.py.
"""

from __future__ import annotations

import inspect

from core.notifications.models import Notification
from sqlalchemy import ForeignKeyConstraint, Table

_notifications: Table = Notification.__table__  # type: ignore[assignment]


def test_notifications_table_is_schema_qualified_core() -> None:
    assert _notifications.schema == "core"
    assert _notifications.name == "notifications"


def test_notifications_has_expected_columns() -> None:
    assert {c.name for c in _notifications.columns} == {
        "id",
        "tenant_id",
        "recipient_user_id",
        "channel",
        "subject",
        "body",
        "status",
        "created_at",
        "updated_at",
    }


def test_notifications_has_no_template_or_read_receipt_fields() -> None:
    """Templates are Product-supplied via the future contract
    (docs/ARCHITECTURE.md section 9); read/unread is a Product-UX concern
    -- neither belongs to this phase's generic dispatch objective
    (core/notifications/models.py docstring)."""
    names = {c.name for c in _notifications.columns}
    assert "template_id" not in names
    assert "read_at" not in names
    assert "is_read" not in names


def test_notifications_tenant_id_and_recipient_are_not_nullable() -> None:
    assert _notifications.columns["tenant_id"].nullable is False
    assert _notifications.columns["recipient_user_id"].nullable is False


def test_notifications_body_and_status_are_not_nullable() -> None:
    assert _notifications.columns["body"].nullable is False
    assert _notifications.columns["status"].nullable is False


def test_notifications_subject_is_nullable() -> None:
    assert _notifications.columns["subject"].nullable is True


def test_notifications_has_composite_fk_to_tenant_memberships() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 4.4: a notification recipient
    must be a genuine member of the tenant it's addressed within, the
    same integrity guarantee core/api_keys established in Phase 4.1."""
    composite_fks = [
        {c.name for c in constraint.columns}
        for constraint in _notifications.constraints
        if isinstance(constraint, ForeignKeyConstraint) and len(constraint.columns) > 1
    ]
    assert {"tenant_id", "recipient_user_id"} in composite_fks


def test_core_notifications_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.notifications.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
