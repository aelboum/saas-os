"""Hierarchy-aware usage aggregation integration tests against a real
PostgreSQL instance (architecture research: universal multi-tenant
tenancy, Phase H -- "Hierarchy-Aware Billing & Usage").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/usage/test_quota_enforcement_integration.py` (no Redis
needed -- usage rows are seeded via direct, synchronous insertion, the
same way `consume_quota()` itself writes, never through the async
`ingest_event()` job queue).

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/usage/test_usage_hierarchy_integration.py
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from core.billing.provider import FakeBillingProvider
from core.billing.service import create_plan, subscribe
from core.usage.models import UsageEvent
from core.usage.service import aggregate_usage, aggregate_usage_including_descendants, check_quota
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant, set_tenant_billing_inheritance

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.usage_events LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(f"core.usage_events does not exist yet -- run `alembic upgrade head`: {exc}")
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


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


def _cleanup_tenant_tree(*tenant_ids_leaf_to_root: uuid.UUID) -> None:
    for tenant_id in tenant_ids_leaf_to_root:
        _admin_delete_audit_log_for_tenant(tenant_id)
        with tenant_session_scope(tenant_id) as session:
            session.execute(
                text("DELETE FROM core.usage_events WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_plan(key: str) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": key})


def _seed_usage(
    tenant_id: uuid.UUID, metric: str, quantity: Decimal, occurred_at: datetime
) -> None:
    """Synchronous, direct insertion -- exactly the shape
    `consume_quota()` itself writes, never through the async
    `ingest_event()` job queue (module docstring)."""
    with tenant_session_scope(tenant_id) as session:
        session.add(
            UsageEvent(
                tenant_id=tenant_id, metric=metric, quantity=quantity, occurred_at=occurred_at
            )
        )
        session.flush()


_WINDOW = (datetime.now(UTC) - timedelta(minutes=1), datetime.now(UTC) + timedelta(hours=1))


# --- Usage stays attributed to the originating tenant -----------------------


def test_usage_remains_owned_by_originating_tenant() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    metric = _unique_name("metric")
    try:
        _seed_usage(child.id, metric, Decimal("5"), datetime.now(UTC))

        with tenant_session_scope(child.id) as session:
            row = session.execute(
                text("SELECT tenant_id FROM core.usage_events WHERE tenant_id = :t"),
                {"t": str(child.id)},
            ).scalar_one()
        assert str(row) == str(child.id)

        # The child's own usage never appears under the parent's id.
        assert aggregate_usage(parent.id, metric, since=_WINDOW[0], until=_WINDOW[1]) == Decimal(
            "0"
        )
    finally:
        _cleanup_tenant_tree(child.id, parent.id)


# --- Descendant / parent / nested aggregation --------------------------


def test_aggregate_including_descendants_sums_parent_and_children() -> None:
    parent = create_tenant(_unique_name("parent"))
    child_a = create_tenant(_unique_name("child-a"), parent_id=parent.id)
    child_b = create_tenant(_unique_name("child-b"), parent_id=parent.id)
    metric = _unique_name("metric")
    try:
        _seed_usage(parent.id, metric, Decimal("10"), datetime.now(UTC))
        _seed_usage(child_a.id, metric, Decimal("3"), datetime.now(UTC))
        _seed_usage(child_b.id, metric, Decimal("7"), datetime.now(UTC))

        total = aggregate_usage_including_descendants(
            parent.id, metric, since=_WINDOW[0], until=_WINDOW[1]
        )
        assert total == Decimal("20")

        # Each tenant's own rollup is unaffected by its siblings.
        assert aggregate_usage_including_descendants(
            child_a.id, metric, since=_WINDOW[0], until=_WINDOW[1]
        ) == Decimal("3")
    finally:
        _cleanup_tenant_tree(child_a.id, child_b.id, parent.id)


def test_aggregate_including_descendants_handles_nested_hierarchy() -> None:
    grandparent = create_tenant(_unique_name("gp"))
    parent = create_tenant(_unique_name("parent"), parent_id=grandparent.id)
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    metric = _unique_name("metric")
    try:
        _seed_usage(grandparent.id, metric, Decimal("1"), datetime.now(UTC))
        _seed_usage(parent.id, metric, Decimal("2"), datetime.now(UTC))
        _seed_usage(child.id, metric, Decimal("4"), datetime.now(UTC))

        assert aggregate_usage_including_descendants(
            grandparent.id, metric, since=_WINDOW[0], until=_WINDOW[1]
        ) == Decimal("7")
        assert aggregate_usage_including_descendants(
            parent.id, metric, since=_WINDOW[0], until=_WINDOW[1]
        ) == Decimal("6")
        assert aggregate_usage_including_descendants(
            child.id, metric, since=_WINDOW[0], until=_WINDOW[1]
        ) == Decimal("4")
    finally:
        _cleanup_tenant_tree(child.id, parent.id, grandparent.id)


def test_aggregate_including_descendants_with_no_usage_is_zero() -> None:
    tenant = create_tenant(_unique_name("lonely"))
    metric = _unique_name("metric")
    try:
        assert aggregate_usage_including_descendants(
            tenant.id, metric, since=_WINDOW[0], until=_WINDOW[1]
        ) == Decimal("0")
    finally:
        _cleanup_tenant_tree(tenant.id)


def test_aggregate_including_descendants_does_not_duplicate_or_rewrite_rows() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    metric = _unique_name("metric")
    try:
        _seed_usage(child.id, metric, Decimal("5"), datetime.now(UTC))

        aggregate_usage_including_descendants(parent.id, metric, since=_WINDOW[0], until=_WINDOW[1])
        aggregate_usage_including_descendants(parent.id, metric, since=_WINDOW[0], until=_WINDOW[1])

        with tenant_session_scope(child.id) as session:
            count = session.execute(
                text("SELECT COUNT(*) FROM core.usage_events WHERE tenant_id = :t"),
                {"t": str(child.id)},
            ).scalar_one()
        assert count == 1
    finally:
        _cleanup_tenant_tree(child.id, parent.id)


# --- Historical usage is unaffected by later hierarchy/billing changes -----


def test_historical_usage_unchanged_by_billing_inheritance_flag() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    metric = _unique_name("metric")
    try:
        _seed_usage(child.id, metric, Decimal("9"), datetime.now(UTC))
        before = aggregate_usage(child.id, metric, since=_WINDOW[0], until=_WINDOW[1])

        set_tenant_billing_inheritance(child.id, True)

        after = aggregate_usage(child.id, metric, since=_WINDOW[0], until=_WINDOW[1])
        assert before == after == Decimal("9")
    finally:
        _cleanup_tenant_tree(child.id, parent.id)


# --- check_quota(): hierarchy-aware limit, tenant-own usage -----------------


def test_check_quota_uses_resolved_owners_limit_but_own_usage() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    set_tenant_billing_inheritance(child.id, True)
    plan_key = _unique_name("plan")
    metric = _unique_name("metric")
    try:
        create_plan(plan_key, "Parent Plan", entitlements={metric: 100})
        subscribe(parent.id, plan_key, provider=FakeBillingProvider())
        _seed_usage(child.id, metric, Decimal("30"), datetime.now(UTC))
        _seed_usage(parent.id, metric, Decimal("999"), datetime.now(UTC))

        result = check_quota(child.id, metric, since=_WINDOW[0], until=_WINDOW[1])
        assert result.limit == Decimal("100")
        assert result.used == Decimal("30")
        assert result.exceeded is False
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)
