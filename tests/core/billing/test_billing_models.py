"""Billing model shape tests (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1)
-- inspect SQLAlchemy metadata only, no database connection needed.
Mirrors tests/core/feature_flags/test_feature_flags_models.py.
"""

from __future__ import annotations

import inspect

from sqlalchemy import CheckConstraint, Table

from saas_os.core.billing.models import Plan, PlanOffer, Subscription

_plans: Table = Plan.__table__  # type: ignore[assignment]
_subscriptions: Table = Subscription.__table__  # type: ignore[assignment]
_offers: Table = PlanOffer.__table__  # type: ignore[assignment]


# --- billing_plans (owner-scoped catalog, Catalog v2) ----------------------


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
        # Catalog v2 (Phase 5.3 step 2, ADR-0029 amendment).
        "owner_tenant_id",
        "merchant_account_id",
        "visibility",
        "status",
        "legacy",
        "created_at",
        "updated_at",
    }


def test_plan_ownership_is_explicit_never_a_null_platform() -> None:
    """Supersedes `test_plans_has_no_tenant_id_column` (ADR-0029 amendment:
    plans are owner-scoped). The owner is an explicit column, not the
    RLS `tenant_id` -- the catalog stays outside RLS (ADR-0022) -- and it is
    nullable only for a not-yet-adopted legacy plan: a non-legacy plan must
    have one, and an owner always comes with a merchant."""
    names = {c.name for c in _plans.columns}
    assert "tenant_id" not in names
    assert _plans.columns["owner_tenant_id"].nullable is True
    assert "core.tenants.id" in {fk.target_fullname for fk in _plans.foreign_keys}
    checks = {
        str(c.name): str(c.sqltext) for c in _plans.constraints if isinstance(c, CheckConstraint)
    }
    assert checks["ck_billing_plans_owned_unless_legacy"] == "legacy OR owner_tenant_id IS NOT NULL"
    assert checks["ck_billing_plans_owner_merchant_pair"] == (
        "(owner_tenant_id IS NULL) = (merchant_account_id IS NULL)"
    )


def test_plan_merchant_is_owned_by_the_plan_owner() -> None:
    [fk] = [
        c for c in _plans.foreign_key_constraints if c.name == "fk_billing_plans_owner_merchant"
    ]
    assert [c.name for c in fk.columns] == ["owner_tenant_id", "merchant_account_id"]
    assert [e.target_fullname for e in fk.elements] == [
        "core.billing_merchant_accounts.tenant_id",
        "core.billing_merchant_accounts.id",
    ]


def test_plans_key_is_not_unique_deployment_wide() -> None:
    """Supersedes `test_plans_key_is_unique`: keys are unique per owner
    (and among legacy plans) through partial unique indexes in migration
    `d23cbb2ba746`, so two owners may both have `starter`."""
    assert not _plans.columns["key"].unique


def test_plan_offers_are_owned_by_the_plan_owner() -> None:
    assert _offers.schema == "core" and _offers.name == "billing_plan_offers"
    [fk] = [
        c for c in _offers.foreign_key_constraints if c.name == "fk_billing_plan_offers_plan_owner"
    ]
    assert [c.name for c in fk.columns] == ["tenant_id", "plan_id"]
    assert [e.target_fullname for e in fk.elements] == [
        "core.billing_plans.owner_tenant_id",
        "core.billing_plans.id",
    ]


def test_plans_provider_price_id_is_nullable() -> None:
    assert _plans.columns["provider_price_id"].nullable is True


def test_plans_has_no_tier_rank_or_price_column() -> None:
    """Nothing in this phase's Acceptance Criteria needs plan ordering
    (saas_os/core/billing/models.py's own docstring)."""
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
        # Billing Foundation v2 Phase 2 (ADR-0029): the payer relationship
        # and the holding provider -- nullable, `tenant_id` unchanged.
        "payer_tenant_id",
        "billing_account_id",
        "provider",
        # Billing Foundation v2 Phase 3: lifecycle safety.
        "merchant_account_id",
        "verification",
        # Phase 5.3 step 4: the canonical version the projections fence on.
        "version",
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
    core.webhook_subscriptions' tenant_id FK is plain (saas_os/core/billing/models.py
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
    import saas_os.core.billing.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
