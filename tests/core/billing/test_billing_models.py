"""Billing model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1)
-- inspect SQLAlchemy metadata only, no database connection needed.
Mirrors tests/core/feature_flags/test_feature_flags_models.py.
"""

from __future__ import annotations

import inspect

from core.billing.models import Plan, Subscription
from sqlalchemy import Table

_plans: Table = Plan.__table__  # type: ignore[assignment]
_subscriptions: Table = Subscription.__table__  # type: ignore[assignment]


# --- billing_plans (global) -------------------------------------------------


def test_plans_table_is_schema_qualified_core() -> None:
    assert _plans.schema == "core"
    assert _plans.name == "billing_plans"


def test_plans_has_expected_columns() -> None:
    assert {c.name for c in _plans.columns} == {
        "id",
        "key",
        "name",
        "provider_price_id",
        "entitlements",
        "created_at",
        "updated_at",
    }


def test_plans_has_no_tenant_id_column() -> None:
    """A plan definition is a global pricing-tier declaration, not
    tenant-owned data (core/billing/models.py's own docstring)."""
    assert "tenant_id" not in {c.name for c in _plans.columns}


def test_plans_key_is_unique() -> None:
    assert _plans.columns["key"].unique is True


def test_plans_provider_price_id_is_nullable() -> None:
    assert _plans.columns["provider_price_id"].nullable is True


def test_plans_has_no_tier_rank_or_price_column() -> None:
    """Nothing in this phase's Acceptance Criteria needs plan ordering
    (core/billing/models.py's own docstring)."""
    names = {c.name for c in _plans.columns}
    assert "tier" not in names
    assert "rank" not in names
    assert "price" not in names
    assert "amount" not in names


# --- billing_subscriptions ---------------------------------------------


def test_subscriptions_table_is_schema_qualified_core() -> None:
    assert _subscriptions.schema == "core"
    assert _subscriptions.name == "billing_subscriptions"


def test_subscriptions_has_expected_columns() -> None:
    assert {c.name for c in _subscriptions.columns} == {
        "id",
        "tenant_id",
        "plan_id",
        "status",
        "provider_subscription_id",
        "created_at",
        "updated_at",
    }


def test_subscriptions_tenant_id_is_not_nullable() -> None:
    assert _subscriptions.columns["tenant_id"].nullable is False


def test_subscriptions_tenant_id_is_a_foreign_key_to_tenants() -> None:
    fk_targets = {fk.target_fullname for fk in _subscriptions.foreign_keys}
    assert "core.tenants.id" in fk_targets


def test_subscriptions_plan_id_is_a_plain_fk_to_billing_plans() -> None:
    """No composite FK here -- billing_plans is global, the same reason
    core.webhook_subscriptions' tenant_id FK is plain (core/billing/models.py
    docstring)."""
    fk_targets = {fk.target_fullname for fk in _subscriptions.foreign_keys}
    assert "core.billing_plans.id" in fk_targets


def test_subscriptions_status_and_provider_subscription_id_not_nullable() -> None:
    assert _subscriptions.columns["status"].nullable is False
    assert _subscriptions.columns["provider_subscription_id"].nullable is False


def test_core_billing_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.billing.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
