"""Usage ingestion/aggregation/quota integration tests: real PostgreSQL
(the usage events themselves) + real Redis (the `infra.jobs` queue/worker,
docs/IMPLEMENTATION-ROADMAP.md Phase 2.4) + real `core.billing` Plan/
Subscription rows (docs/IMPLEMENTATION-ROADMAP.md Phase 5.2's own Tests
requirement: quota-check integration against a real entitlement).

Marked `integration` and excluded from the default `pytest` run. Mirrors
`tests/core/notifications/test_notifications_integration.py`'s structure
(uuid-namespaced queue name, fast retry backoff).

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/core/usage/test_usage_integration.py
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/billing/test_billing_isolation_integration.py's identical
# import for the full rationale (subscribe()'s audit write needs
# core.users mapped).
import core.identity.models  # noqa: F401
import pytest
from arq import create_pool
from arq.connections import RedisSettings
from core.billing.provider import FakeBillingProvider
from core.billing.service import create_plan, subscribe
from core.usage.service import aggregate_usage, check_quota, ingest_event
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.jobs.config import JobsConfig
from infra.jobs.queue import build_worker, register_job
from sqlalchemy import text

from core.tenancy import create_tenant
from core.usage import service as usage_service

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.usage_events LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.usage_events not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, max_tries=2, retry_backoff_base_seconds=0.01)


@pytest.fixture
def queue_name() -> str:
    return f"core-usage-phase52-{uuid.uuid4().hex[:8]}"


@pytest.fixture(autouse=True)
async def _require_reachable_redis(jobs_config: JobsConfig) -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(jobs_config.redis_url))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    try:
        await pool.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Redis not reachable at the configured REDIS_URL "
            f"({jobs_config.redis_url.split('@')[-1]}): {exc}. Run "
            "`docker compose up -d redis` first -- see this file's module docstring."
        )
    finally:
        await pool.aclose()


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
        self.tenant = create_tenant(f"usage-tenant-{uuid.uuid4().hex[:8]}")
        self.plan_key = _unique_key("usage-plan")

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.usage_events WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": self.plan_key}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


async def _burst_ingest(jobs_config: JobsConfig, queue_name: str) -> None:
    functions = [register_job(usage_service._ingest_usage_event_job, config=jobs_config)]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        await worker.main()
    finally:
        await worker.close()


# --- Ingestion end-to-end ----------------------------------------------


async def test_ingest_event_end_to_end_persists_via_worker(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    occurred_at = datetime.now(UTC)
    job_id = await ingest_event(
        fx.tenant.id, "api_calls", Decimal("5"), occurred_at=occurred_at, queue_name=queue_name
    )
    assert job_id
    await _burst_ingest(jobs_config, queue_name)

    total = aggregate_usage(
        fx.tenant.id,
        "api_calls",
        since=occurred_at - timedelta(minutes=1),
        until=occurred_at + timedelta(minutes=1),
    )
    assert total == Decimal("5")


async def test_ingest_event_does_not_block_the_caller(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 5.2 Security/Acceptance
    requirement: confirms async ingestion doesn't block callers -- a
    timing-based proof that `ingest_event()` returns quickly even while
    persistence has not happened yet (no worker running during this
    measurement)."""
    started = time.monotonic()
    for i in range(20):
        await ingest_event(
            fx.tenant.id, "api_calls", Decimal("1"), queue_name=queue_name + f"-{i % 3}"
        )
    elapsed = time.monotonic() - started
    assert elapsed < 2.0  # enqueueing 20 events must be fast -- no synchronous DB write


# --- Aggregation correctness ---------------------------------------------


async def test_aggregate_usage_sums_multiple_events_correctly(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    base = datetime.now(UTC)
    for quantity in (Decimal("1.5"), Decimal("2.25"), Decimal("10")):
        await ingest_event(
            fx.tenant.id, "storage_bytes", quantity, occurred_at=base, queue_name=queue_name
        )
    await _burst_ingest(jobs_config, queue_name)

    total = aggregate_usage(
        fx.tenant.id,
        "storage_bytes",
        since=base - timedelta(minutes=1),
        until=base + timedelta(minutes=1),
    )
    assert total == Decimal("13.75")


async def test_aggregate_usage_excludes_events_outside_window(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    now = datetime.now(UTC)
    old = now - timedelta(days=40)
    await ingest_event(
        fx.tenant.id, "api_calls", Decimal("100"), occurred_at=old, queue_name=queue_name
    )
    await ingest_event(
        fx.tenant.id, "api_calls", Decimal("3"), occurred_at=now, queue_name=queue_name
    )
    await _burst_ingest(jobs_config, queue_name)

    total = aggregate_usage(
        fx.tenant.id,
        "api_calls",
        since=now - timedelta(minutes=1),
        until=now + timedelta(minutes=1),
    )
    assert total == Decimal("3")


async def test_aggregate_usage_returns_zero_for_no_events(fx: _Fixture) -> None:
    now = datetime.now(UTC)
    total = aggregate_usage(
        fx.tenant.id, "never_used_metric", since=now - timedelta(days=1), until=now
    )
    assert total == Decimal("0")


# --- Quota checking against real core.billing entitlements ---------------


async def test_check_quota_against_real_plan_entitlement(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    create_plan(fx.plan_key, "Usage Plan", entitlements={"api_calls": 10})
    subscribe(fx.tenant.id, fx.plan_key, provider=FakeBillingProvider())

    now = datetime.now(UTC)
    await ingest_event(
        fx.tenant.id, "api_calls", Decimal("4"), occurred_at=now, queue_name=queue_name
    )
    await _burst_ingest(jobs_config, queue_name)

    result = check_quota(
        fx.tenant.id,
        "api_calls",
        since=now - timedelta(minutes=1),
        until=now + timedelta(minutes=1),
    )
    assert result.used == Decimal("4")
    assert result.limit == Decimal("10")
    assert result.exceeded is False


async def test_check_quota_detects_exceeded_usage(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    create_plan(fx.plan_key, "Usage Plan", entitlements={"api_calls": 5})
    subscribe(fx.tenant.id, fx.plan_key, provider=FakeBillingProvider())

    now = datetime.now(UTC)
    await ingest_event(
        fx.tenant.id, "api_calls", Decimal("9"), occurred_at=now, queue_name=queue_name
    )
    await _burst_ingest(jobs_config, queue_name)

    result = check_quota(
        fx.tenant.id,
        "api_calls",
        since=now - timedelta(minutes=1),
        until=now + timedelta(minutes=1),
    )
    assert result.exceeded is True


async def test_check_quota_with_no_subscription_has_no_configured_limit(fx: _Fixture) -> None:
    result = check_quota(fx.tenant.id, "api_calls")
    assert result.limit is None
    assert result.exceeded is False
    assert result.used == Decimal("0")


async def test_check_quota_with_non_numeric_entitlement_has_no_configured_limit(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    create_plan(fx.plan_key, "Usage Plan", entitlements={"api_access": True})
    subscribe(fx.tenant.id, fx.plan_key, provider=FakeBillingProvider())

    result = check_quota(fx.tenant.id, "api_access")
    assert result.limit is None
    assert result.exceeded is False


async def test_check_quota_defaults_to_current_utc_calendar_month(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    create_plan(fx.plan_key, "Usage Plan", entitlements={"api_calls": 100})
    subscribe(fx.tenant.id, fx.plan_key, provider=FakeBillingProvider())

    now = datetime.now(UTC)
    await ingest_event(
        fx.tenant.id, "api_calls", Decimal("7"), occurred_at=now, queue_name=queue_name
    )
    await _burst_ingest(jobs_config, queue_name)

    result = check_quota(fx.tenant.id, "api_calls")
    assert result.used == Decimal("7")
