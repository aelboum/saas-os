"""PRIV-03 Phase P10 (privacy re-audit RA-06) -- a Core job executed for a
tenant that closed after it was queued leaves no arq result record, against
real PostgreSQL and real Redis + arq.

The RA-03 fence (`tests/core/test_job_lifecycle_fencing_integration.py`)
makes such a job a clean drop: a normal return, no side effect, no retry,
no dead-letter. To arq that is a *successful* execution, and the RA-06
audit showed the default `keep_result=3600` then wrote the whole pickled
call -- the purged tenant's notification body, recipient address and usage
event -- under `arq:result:<job_id>` for another hour, keyed by nothing a
purge could find. With `infra.jobs` registering every function and
building every worker with `keep_result=0`, that record is never created.

Only the two producers with no external side effect are used here (in-app
notification and usage ingestion), so no e-mail or HTTP fake is needed;
the fence itself for every handler is already proven by the RA-03 suite.
Every persisted-state assertion goes through the privileged migrations
role; every action under test runs as the ordinary application role.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/core/test_job_result_retention_integration.py
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal

import core.notifications.service as notifications_service
import core.usage.service as usage_service
import pytest
from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus
from core.identity.service import add_tenant_membership, create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from infra.jobs.dead_letter import count_dead_letters
from infra.jobs.queue import get_redis_pool
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

import core.rbac  # noqa: F401 -- registers the mappers core.audit_log references by name
from core.tenancy import (
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)
from infra.jobs import JobsConfig, build_worker, register_job

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_CLOSED = [TenantStatus.DELETED, TenantStatus.PURGING, TenantStatus.PURGED]
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_BODY = "private notification body ra06"


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
        pytest.skip(f"PostgreSQL/core.notifications not reachable: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, max_tries=2, retry_backoff_base_seconds=0.01)


@pytest.fixture(autouse=True)
async def _require_reachable_redis(jobs_config: JobsConfig) -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(jobs_config.redis_url))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    try:
        await pool.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at REDIS_URL: {exc}")
    finally:
        await pool.aclose()


@dataclass
class Rig:
    tenant_id: uuid.UUID
    user_id: uuid.UUID


def _build_rig() -> Rig:
    tenant = create_tenant(f"priv03-p10-{uuid.uuid4().hex[:8]}")
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    user = create_user()
    add_tenant_membership(tenant.id, user.id)
    return Rig(tenant_id=tenant.id, user_id=user.id)


def _teardown(admin: sessionmaker[Session], rig: Rig) -> None:
    with session_scope(session_factory=admin) as session:
        for table in (
            "core.audit_log",
            "core.notifications",
            "core.usage_events",
            "core.tenant_memberships",
            "core.tenant_ancestry",
        ):
            session.execute(
                text(f"DELETE FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
                {"t": str(rig.tenant_id)},
            )
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)})
        session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(rig.user_id)})


@pytest.fixture
def rig(admin: sessionmaker[Session]) -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(admin, built)


def _count(admin: sessionmaker[Session], table: str, tenant_id: uuid.UUID) -> int:
    with session_scope(session_factory=admin) as session:
        return session.execute(
            text(f"SELECT count(*) FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
            {"t": str(tenant_id)},
        ).scalar_one()


def _close(tenant_id: uuid.UUID, status: TenantStatus) -> None:
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    if status is TenantStatus.PURGING:
        transition_tenant_status(tenant_id, TenantStatus.PURGING)
    elif status is TenantStatus.PURGED:
        purge_tenant(tenant_id)


async def _enqueue_tenant_jobs(rig: Rig, queue_name: str) -> list[str]:
    notification_job = await notifications_service.dispatch_notification(
        rig.tenant_id, rig.user_id, "in_app", _BODY, subject="Order update", queue_name=queue_name
    )
    usage_job = await usage_service.ingest_event(
        rig.tenant_id, "api_calls", Decimal("1"), queue_name=queue_name
    )
    return [notification_job, usage_job]


async def _run_burst(jobs_config: JobsConfig, queue_name: str) -> None:
    functions = [
        register_job(notifications_service._dispatch_notification_job, config=jobs_config),
        register_job(usage_service._ingest_usage_event_job, config=jobs_config),
    ]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        await worker.main()
        await worker.main()  # would run a retry if there were one -- there must be none
    finally:
        await worker.close()


async def _assert_forgotten(pool, queue_name: str, job_ids: list[str]) -> None:
    for job_id in job_ids:
        assert await pool.exists(f"arq:result:{job_id}") == 0, job_id
        assert await pool.exists(f"arq:job:{job_id}") == 0, job_id
        assert await pool.exists(f"arq:retry:{job_id}") == 0, job_id
        assert await Job(job_id, redis=pool, _queue_name=queue_name).status() == JobStatus.not_found
    async for key in pool.scan_iter(match="arq:result:*"):
        raw = await pool.get(key) or b""
        assert _BODY.encode() not in raw, "a result record still carries the tenant's content"


async def test_active_tenant_jobs_do_their_work_and_leave_no_result_record(
    rig: Rig, admin: sessionmaker[Session], jobs_config: JobsConfig
) -> None:
    """Regression guard for the normal path: the real handlers still write
    their rows, and arq keeps nothing about the finished jobs."""
    queue_name = f"priv03-p10-{uuid.uuid4().hex[:8]}"
    job_ids = await _enqueue_tenant_jobs(rig, queue_name)
    await _run_burst(jobs_config, queue_name)

    assert _count(admin, "core.notifications", rig.tenant_id) == 1
    assert _count(admin, "core.usage_events", rig.tenant_id) == 1
    pool = await get_redis_pool(jobs_config)
    try:
        await _assert_forgotten(pool, queue_name, job_ids)
    finally:
        await pool.aclose()


@pytest.mark.parametrize("status", _CLOSED)
async def test_jobs_of_a_tenant_closed_after_enqueue_are_dropped_and_leave_no_result_record(
    status: TenantStatus, rig: Rig, admin: sessionmaker[Session], jobs_config: JobsConfig
) -> None:
    """Enqueue while ACTIVE, close the tenant (DELETED / PURGING / PURGED),
    then let a real burst worker execute the queued jobs: the RA-03 fence
    drops them (no row, no retry, no dead-letter) -- and the RA-06 fix
    means the drop leaves no `arq:result` record either, so nothing of the
    closed tenant's payload outlives the execution in Redis."""
    queue_name = f"priv03-p10-{uuid.uuid4().hex[:8]}"
    job_ids = await _enqueue_tenant_jobs(rig, queue_name)
    _close(rig.tenant_id, status)
    assert get_tenant(rig.tenant_id).status == status.value

    pool = await get_redis_pool(jobs_config)
    try:
        dead_before = await count_dead_letters(pool, jobs_config)
        # The queued payloads are still there (bounded, transient queue
        # state) -- what this test proves is that executing them leaves
        # nothing behind, not that purge drains the queue (deferred).
        for job_id in job_ids:
            assert await pool.exists(f"arq:job:{job_id}") == 1
    finally:
        await pool.aclose()

    await _run_burst(jobs_config, queue_name)

    assert _count(admin, "core.notifications", rig.tenant_id) == 0
    assert _count(admin, "core.usage_events", rig.tenant_id) == 0
    pool = await get_redis_pool(jobs_config)
    try:
        assert await count_dead_letters(pool, jobs_config) == dead_before
        await _assert_forgotten(pool, queue_name, job_ids)
    finally:
        await pool.aclose()
