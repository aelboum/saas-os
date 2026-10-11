"""Subscription lifecycle integration test against Stripe's real
sandbox/test mode (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1's own Tests
requirement, quoted verbatim: "subscription lifecycle integration test
against Stripe's sandbox/test mode, run through the abstraction
interface (not the Stripe SDK directly, in test assertions)").

Every assertion below is against `saas_os/core/billing/service.py`'s own return
values (`Subscription.status`, `get_entitlements()`) -- never against a
raw `stripe.Subscription` object -- exactly as the roadmap requires, so
this test would still pass unmodified if the Stripe adapter were swapped
for a different provider entirely.

Marked `integration` and excluded from the default `pytest` run. Skips
cleanly (mirrors `tests/infra/test_db_integration.py`'s own unreachable-
dependency convention) when `STRIPE_API_KEY` is not configured for the
local/CI environment -- this environment has no real Stripe test-mode
account, so this test is expected to skip here, not fail. A maintainer
with a real Stripe test-mode secret key can run it locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        STRIPE_API_KEY=sk_test_... \\
        pytest -m integration tests/core/billing/test_billing_stripe_integration.py
"""

from __future__ import annotations

import uuid

import pytest
import stripe
from sqlalchemy import text

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/billing/test_billing_isolation_integration.py's identical
# import for the full rationale.
import saas_os.core.identity.models  # noqa: F401
from saas_os.core.billing.service import (
    cancel_subscription,
    create_plan,
    get_entitlements,
    subscribe,
    upgrade_subscription,
)
from saas_os.core.billing.stripe_provider import StripeBillingProvider
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.secrets import get_secrets_provider


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from sqlalchemy import text

    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine
    from saas_os.infra.db.session import build_session_factory, session_scope

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
    finally:
        engine.dispose()


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.billing_subscriptions LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.billing_subscriptions not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture
def stripe_api_key() -> str:
    try:
        api_key = get_secrets_provider().get_required("STRIPE_API_KEY")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"STRIPE_API_KEY not configured for the integration test: {exc}")
    if not api_key.startswith("sk_test_"):
        pytest.skip(
            "STRIPE_API_KEY is not a test-mode key (must start with 'sk_test_') -- "
            "refusing to run against a live account."
        )
    return api_key


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


def test_stripe_subscription_lifecycle_create_upgrade_cancel(stripe_api_key: str) -> None:
    client = stripe.StripeClient(api_key=stripe_api_key)
    starter_price = client.v1.prices.create(
        params={
            "currency": "usd",
            "unit_amount": 1000,
            "recurring": {"interval": "month"},
            "product_data": {"name": f"Test Starter {uuid.uuid4().hex[:8]}"},
        }
    )
    pro_price = client.v1.prices.create(
        params={
            "currency": "usd",
            "unit_amount": 5000,
            "recurring": {"interval": "month"},
            "product_data": {"name": f"Test Pro {uuid.uuid4().hex[:8]}"},
        }
    )

    tenant = create_tenant(f"stripe-live-{uuid.uuid4().hex[:8]}")
    starter_key = f"stripe-starter-{uuid.uuid4().hex[:8]}"
    pro_key = f"stripe-pro-{uuid.uuid4().hex[:8]}"
    provider = StripeBillingProvider(api_key=stripe_api_key)

    try:
        create_plan(
            starter_key,
            "Starter",
            entitlements={"max_users": 5},
            provider_price_id=starter_price.id,
        )
        create_plan(pro_key, "Pro", entitlements={"max_users": 50}, provider_price_id=pro_price.id)

        subscription = subscribe(tenant.id, starter_key, provider=provider)
        assert subscription.status == "active"
        assert get_entitlements(tenant.id) == {"max_users": 5}

        upgraded = upgrade_subscription(tenant.id, subscription.id, pro_key, provider=provider)
        assert upgraded.status == "active"
        assert get_entitlements(tenant.id) == {"max_users": 50}

        canceled = cancel_subscription(tenant.id, subscription.id, provider=provider)
        assert canceled.status == "canceled"
        assert get_entitlements(tenant.id) == {}
    finally:
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.billing_plans WHERE key IN (:a, :b)"),
                {"a": starter_key, "b": pro_key},
            )
            _admin_clear_audit_references({"id": str(tenant.id)}, table="tenants")
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
