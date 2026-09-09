"""Usage event model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase
5.2) -- inspect SQLAlchemy metadata only, no database connection needed.
Mirrors tests/core/notifications/test_notifications_models.py.
"""

from __future__ import annotations

import inspect

from core.usage.models import UsageEvent
from sqlalchemy import ForeignKeyConstraint, Table

_usage_events: Table = UsageEvent.__table__  # type: ignore[assignment]


def test_usage_events_table_is_schema_qualified_core() -> None:
    assert _usage_events.schema == "core"
    assert _usage_events.name == "usage_events"


def test_usage_events_has_expected_columns() -> None:
    assert {c.name for c in _usage_events.columns} == {
        "id",
        "tenant_id",
        "metric",
        "quantity",
        "occurred_at",
        "created_at",
    }


def test_usage_events_has_no_updated_at() -> None:
    """Append-only, immutability-signaling schema choice
    (core/usage/models.py's own docstring) -- mirrors core.audit_log's
    convention, contrast with core.notifications/core.billing_subscriptions'
    updated_at."""
    assert "updated_at" not in {c.name for c in _usage_events.columns}


def test_usage_events_has_no_idempotency_key() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 5.2's own Tests/Acceptance
    Criteria never require de-duplication -- no idempotency-key column is
    invented (core/usage/__init__.py's own Non-Goals)."""
    names = {c.name for c in _usage_events.columns}
    assert "idempotency_key" not in names
    assert "dedupe_key" not in names


def test_usage_events_tenant_id_metric_quantity_occurred_at_are_not_nullable() -> None:
    assert _usage_events.columns["tenant_id"].nullable is False
    assert _usage_events.columns["metric"].nullable is False
    assert _usage_events.columns["quantity"].nullable is False
    assert _usage_events.columns["occurred_at"].nullable is False


def test_usage_events_has_plain_tenant_id_fk_not_composite() -> None:
    """A usage event has no second identity to guard against (unlike
    core.notifications' (tenant_id, recipient_user_id) composite FK) --
    core/usage/models.py's own docstring."""
    composite_fks = [
        constraint
        for constraint in _usage_events.constraints
        if isinstance(constraint, ForeignKeyConstraint) and len(constraint.columns) > 1
    ]
    assert composite_fks == []


def test_core_usage_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.usage.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
