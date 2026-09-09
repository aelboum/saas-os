"""Billing lifecycle integration tests against a real PostgreSQL instance
with the Phase 5.1 tables actually migrated (docs/IMPLEMENTATION-ROADMAP.md
Phase 5.1). Runs against `FakeBillingProvider` -- no live Stripe network
access needed; the substitution test (`test_billing_unit.py`) already
proves `StripeBillingProvider` satisfies the identical interface.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/billing/test_billing_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.service import list as list_audit_entries
from core.billing.errors import (
    DuplicatePlanKeyError,
    PlanNotFoundError,
    SubscriptionNotFoundError,
)
from core.billing.provider import FakeBillingProvider
from core.billing.service import (
    cancel_subscription,
    create_plan,
    get_entitlements,
    get_plan,
    get_subscription,
    list_plans,
    list_subscriptions,
    subscribe,
    upgrade_subscription,
)
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_billing_tables() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.billing_subscriptions LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.billing_subscriptions does not exist yet -- "
            f"run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _unique_key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(f"billing-tenant-{uuid.uuid4().hex[:8]}")
        self.user = create_user()
        self.starter_key = _unique_key("starter")
        self.pro_key = _unique_key("pro")
        self.provider = FakeBillingProvider()

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.billing_plans WHERE key IN (:a, :b)"),
                {"a": self.starter_key, "b": self.pro_key},
            )
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(self.user.id)}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


# --- Plan catalog --------------------------------------------------------


def test_create_and_get_plan(fx: _Fixture) -> None:
    plan = create_plan(fx.starter_key, "Starter", entitlements={"max_users": 5})
    assert plan.key == fx.starter_key
    assert plan.entitlements == {"max_users": 5}

    fetched = get_plan(fx.starter_key)
    assert fetched.id == plan.id


def test_duplicate_plan_key_rejected(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    with pytest.raises(DuplicatePlanKeyError):
        create_plan(fx.starter_key, "Starter Again")


def test_get_unknown_plan_raises(fx: _Fixture) -> None:
    with pytest.raises(PlanNotFoundError):
        get_plan(_unique_key("nonexistent"))


def test_list_plans_includes_created_plan(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    keys = {p.key for p in list_plans()}
    assert fx.starter_key in keys


# --- Subscription lifecycle (the roadmap's own literal Acceptance Criteria) --


def test_subscribe_upgrade_cancel_lifecycle_with_entitlements(fx: _Fixture) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 5.1 Acceptance Criteria: "a
    test subscription can be created, upgraded, and canceled, with
    entitlements reflecting each state correctly."
    """
    create_plan(fx.starter_key, "Starter", entitlements={"max_users": 5, "api_access": False})
    create_plan(fx.pro_key, "Pro", entitlements={"max_users": 50, "api_access": True})

    assert get_entitlements(fx.tenant.id) == {}

    subscription = subscribe(fx.tenant.id, fx.starter_key, provider=fx.provider)
    assert subscription.status == "active"
    assert get_entitlements(fx.tenant.id) == {"max_users": 5, "api_access": False}

    upgraded = upgrade_subscription(fx.tenant.id, subscription.id, fx.pro_key, provider=fx.provider)
    assert upgraded.id == subscription.id
    assert get_entitlements(fx.tenant.id) == {"max_users": 50, "api_access": True}

    canceled = cancel_subscription(fx.tenant.id, subscription.id, provider=fx.provider)
    assert canceled.status == "canceled"
    assert get_entitlements(fx.tenant.id) == {}


def test_get_entitlements_does_not_crash_with_two_active_subscriptions(fx: _Fixture) -> None:
    """Nothing in the schema enforces at most one `"active"` subscription
    per tenant (`core/billing/models.py`'s own docstring) -- a caller
    invoking `subscribe()` twice without canceling the first must not
    crash `get_entitlements()` with `MultipleResultsFound`; it returns the
    most recently created active subscription's entitlements instead.
    """
    from core.billing.models import Subscription

    create_plan(fx.starter_key, "Starter", entitlements={"max_users": 5})
    create_plan(fx.pro_key, "Pro", entitlements={"max_users": 50})

    subscribe(fx.tenant.id, fx.starter_key, provider=fx.provider)
    # A second active subscription for the same tenant -- not something
    # subscribe() would normally produce back-to-back in real usage, but
    # nothing prevents it either; this proves get_entitlements() is
    # robust to that state regardless of how it arises.
    subscribe(fx.tenant.id, fx.pro_key, provider=fx.provider)

    with tenant_session_scope(fx.tenant.id) as session:
        active = (
            session.execute(
                select(Subscription).where(
                    Subscription.tenant_id == fx.tenant.id, Subscription.status == "active"
                )
            )
            .scalars()
            .all()
        )
    assert len(active) == 2  # confirms the precondition this test exercises is real

    assert get_entitlements(fx.tenant.id) == {"max_users": 50}


def test_get_unknown_subscription_raises(fx: _Fixture) -> None:
    with pytest.raises(SubscriptionNotFoundError):
        get_subscription(fx.tenant.id, uuid.uuid4())


def test_list_subscriptions_includes_created_subscription(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    subscription = subscribe(fx.tenant.id, fx.starter_key, provider=fx.provider)
    ids = {s.id for s in list_subscriptions(fx.tenant.id)}
    assert subscription.id in ids


def test_subscribe_calls_the_provider_and_persists_its_subscription_id(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    subscription = subscribe(fx.tenant.id, fx.starter_key, provider=fx.provider)
    assert subscription.provider_subscription_id in fx.provider._subscriptions


def test_cancel_calls_the_provider_which_forgets_the_subscription(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    subscription = subscribe(fx.tenant.id, fx.starter_key, provider=fx.provider)
    cancel_subscription(fx.tenant.id, subscription.id, provider=fx.provider)
    assert subscription.provider_subscription_id not in fx.provider._subscriptions


# --- Audit logging -----------------------------------------------------


def test_subscribe_writes_an_audit_entry(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    subscription = subscribe(
        fx.tenant.id, fx.starter_key, provider=fx.provider, actor_user_id=fx.user.id
    )

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "billing.subscription_created"]
    assert len(matching) == 1
    entry = matching[0]
    assert entry.tenant_id == fx.tenant.id
    assert entry.actor_user_id == fx.user.id
    assert entry.resource_type == "billing_subscription"
    assert entry.resource_id == str(subscription.id)
    assert entry.outcome == "success"
    assert entry.entry_metadata == {"plan_key": fx.starter_key}


def test_upgrade_writes_an_audit_entry(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    create_plan(fx.pro_key, "Pro")
    subscription = subscribe(fx.tenant.id, fx.starter_key, provider=fx.provider)
    upgrade_subscription(
        fx.tenant.id, subscription.id, fx.pro_key, provider=fx.provider, actor_user_id=fx.user.id
    )

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "billing.subscription_upgraded"]
    assert len(matching) == 1
    metadata = matching[0].entry_metadata
    assert metadata is not None
    assert metadata["new_plan_key"] == fx.pro_key


def test_cancel_writes_an_audit_entry(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    subscription = subscribe(fx.tenant.id, fx.starter_key, provider=fx.provider)
    cancel_subscription(
        fx.tenant.id, subscription.id, provider=fx.provider, actor_user_id=fx.user.id
    )

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "billing.subscription_canceled"]
    assert len(matching) == 1
    assert matching[0].resource_id == str(subscription.id)


def test_audit_entries_never_carry_a_provider_api_key(fx: _Fixture) -> None:
    create_plan(fx.starter_key, "Starter")
    subscription = subscribe(fx.tenant.id, fx.starter_key, provider=fx.provider)
    entries = list_audit_entries(fx.tenant.id)
    for entry in entries:
        assert "sk_" not in str(entry.entry_metadata)
        assert "sk_" not in (entry.resource_id or "")
    assert subscription  # keep referenced
