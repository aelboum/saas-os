"""Notification dispatch integration tests: real PostgreSQL (the
notification itself) + real Redis (the `infra.jobs` queue/worker,
docs/IMPLEMENTATION-ROADMAP.md Phase 2.4) -- docs/IMPLEMENTATION-ROADMAP.md
Phase 4.4's own Tests requirement: "dispatch integration test against a
test provider/sandbox for each channel implemented." For the one channel
implemented (`"in_app"`), the "provider/sandbox" is the platform's own
database -- no external network call, no external account needed.

Marked `integration` and excluded from the default `pytest` run. Mirrors
`tests/core/webhooks/test_webhooks_delivery_integration.py`'s structure
(uuid-namespaced queue name, fast retry backoff).

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/core/notifications/test_notifications_integration.py
"""

from __future__ import annotations

import os
import uuid

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from core.identity.service import add_tenant_membership, create_user
from core.notifications.errors import NotificationNotFoundError
from core.notifications.service import (
    dispatch_notification,
    get_notification,
    list_notifications,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.jobs.config import JobsConfig
from infra.jobs.dead_letter import count_dead_letters, list_dead_letters
from infra.jobs.queue import build_worker, get_redis_pool, register_job
from sqlalchemy import text

from core.notifications import service as notifications_service
from core.tenancy import create_tenant

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
            conn.execute(text("SELECT 1 FROM core.notifications LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.notifications not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, max_tries=2, retry_backoff_base_seconds=0.01)


@pytest.fixture
def queue_name() -> str:
    return f"core-notifications-phase44-{uuid.uuid4().hex[:8]}"


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


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(f"notif-tenant-{uuid.uuid4().hex[:8]}")
        self.user = create_user()
        add_tenant_membership(self.tenant.id, self.user.id)

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.notifications WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
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


async def test_dispatch_in_app_notification_end_to_end(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    functions = [register_job(notifications_service._dispatch_notification_job, config=jobs_config)]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        job_id = await dispatch_notification(
            fx.tenant.id,
            fx.user.id,
            "in_app",
            "Your order has shipped.",
            subject="Order update",
            queue_name=queue_name,
        )
        assert job_id
        await worker.main()
    finally:
        await worker.close()

    notifications = list_notifications(fx.tenant.id, fx.user.id)
    assert len(notifications) == 1
    notification = notifications[0]
    assert notification.channel == "in_app"
    assert notification.subject == "Order update"
    assert notification.body == "Your order has shipped."
    assert notification.status == "sent"

    fetched = get_notification(fx.tenant.id, notification.id)
    assert fetched.id == notification.id


async def test_get_unknown_notification_raises(fx: _Fixture) -> None:
    with pytest.raises(NotificationNotFoundError):
        get_notification(fx.tenant.id, uuid.uuid4())


async def test_list_notifications_scoped_to_recipient(fx: _Fixture) -> None:
    other_user = create_user()
    add_tenant_membership(fx.tenant.id, other_user.id)
    try:
        with tenant_session_scope(fx.tenant.id) as session:
            from core.notifications.models import Notification

            session.add(
                Notification(
                    tenant_id=fx.tenant.id,
                    recipient_user_id=other_user.id,
                    channel="in_app",
                    subject=None,
                    body="not for fx.user",
                    status="sent",
                )
            )

        assert list_notifications(fx.tenant.id, fx.user.id) == []
        assert len(list_notifications(fx.tenant.id, other_user.id)) == 1
    finally:
        with tenant_session_scope(fx.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.notifications WHERE recipient_user_id = :u"),
                {"u": str(other_user.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE user_id = :u"),
                {"u": str(other_user.id)},
            )
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(other_user.id)}
            )


async def test_dispatch_to_non_member_recipient_dead_letters(
    fx: _Fixture, jobs_config: JobsConfig, queue_name: str
) -> None:
    """`(tenant_id, recipient_user_id)` must be a real `TenantMembership`
    -- enforced structurally by the composite FK
    (`core/notifications/models.py`), not merely by application code
    remembering to check. A non-member recipient's dispatch attempt fails
    at the database level and is proven to dead-letter, never silently
    succeed."""
    non_member = create_user()
    try:
        functions = [
            register_job(notifications_service._dispatch_notification_job, config=jobs_config)
        ]
        worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
        try:
            pool = await get_redis_pool(jobs_config)
            try:
                assert await count_dead_letters(pool, jobs_config) == 0
            finally:
                await pool.aclose()

            await dispatch_notification(
                fx.tenant.id, non_member.id, "in_app", "body", queue_name=queue_name
            )
            await worker.main()
            import asyncio

            await asyncio.sleep(0.05)
            await worker.main()
        finally:
            await worker.close()

        verify_pool = await get_redis_pool(jobs_config)
        try:
            assert await count_dead_letters(verify_pool, jobs_config) == 1
            entries = await list_dead_letters(verify_pool, jobs_config)
            assert entries[0].function_name == "_dispatch_notification_job"
            assert entries[0].tenant_id == str(fx.tenant.id)
        finally:
            await verify_pool.delete(jobs_config.dead_letter_key)
            await verify_pool.aclose()

        assert list_notifications(fx.tenant.id, non_member.id) == []
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(non_member.id)}
            )
