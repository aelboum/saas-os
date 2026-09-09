"""P2.1: real-process runtime validation of the production worker
entrypoint (`python -m api.worker`) -- the exact command the Compose
`worker` service runs, spawned as a real subprocess against a real Redis
and a real PostgreSQL (mirrors `tests/api/test_runtime_integration.py`'s
approach for `api.server`).

Proves, end to end and through the real worker process (never a burst
`Worker` inside the test):

    enqueue (core.usage.ingest_event) -> Redis -> worker -> RLS-scoped
    write as the restricted role -> success observable via aggregate_usage()

    enqueue a job that must fail (usage event for a nonexistent tenant,
    rejected by the FK) -> existing retry policy -> existing dead-letter list

plus the process contract: the arq health sentinel appears (`--check`
exits 0), an invalid Redis configuration exits non-zero, an unsafe
database role exits non-zero, and `SIGTERM` terminates cleanly.

Marked `integration`; excluded from the default `pytest` run. Run locally:

    docker compose up -d db redis
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/api/test_worker_runtime_integration.py

The worker consumes arq's *default* queue (the one every production
`enqueue_job()` call uses), so these tests deliberately enqueue onto that
default queue too -- each test uses a freshly created tenant / a fresh
random tenant id, so nothing here collides with, or depends on, other
work that may be on a shared development Redis.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Awaitable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import cast

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope, tenant_session_scope
from infra.jobs.config import JobsConfig, get_jobs_config
from infra.jobs.dead_letter import list_dead_letters
from infra.jobs.payload import TenantJobPayload
from infra.jobs.queue import enqueue_job, get_redis_pool
from sqlalchemy import text

from core.tenancy import create_tenant
from core.usage import aggregate_usage, ingest_event

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_STARTUP_TIMEOUT_SECONDS = 30
_JOB_TIMEOUT_SECONDS = 30
_SHUTDOWN_TIMEOUT_SECONDS = 15


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_jobs_config.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.usage_events LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.usage_events not reachable: {exc}")
    finally:
        probe.dispose()


async def _ping_redis() -> None:
    pool = await create_pool(RedisSettings.from_dsn(_REDIS_URL))
    try:
        await pool.ping()
    finally:
        await pool.aclose()


@pytest.fixture(autouse=True)
def _require_reachable_redis() -> None:
    # Synchronous on purpose: this module mixes sync (subprocess/signal)
    # and async tests, and an async autouse fixture cannot serve the sync
    # ones -- a short-lived event loop for the probe is enough.
    try:
        asyncio.run(_ping_redis())
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}")


def _jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, max_tries=2, retry_backoff_base_seconds=0.01)


class _WorkerProcess:
    """One real `python -m api.worker` subprocess plus its captured log."""

    def __init__(self, env_overrides: dict[str, str] | None = None) -> None:
        env = {
            **os.environ,
            "REDIS_URL": _REDIS_URL,
            "ENVIRONMENT": "test",
            # Fast retry policy so the dead-letter test does not wait out
            # real backoff; the worker reads these through the same
            # infra.jobs config as everything else.
            "JOBS_MAX_TRIES": "2",
            "JOBS_RETRY_BACKOFF_BASE_SECONDS": "0.01",
            **(env_overrides or {}),
        }
        self.log_file = tempfile.NamedTemporaryFile(
            mode="w+", prefix="api_worker_", suffix=".log", delete=False
        )
        self.process = subprocess.Popen(
            [sys.executable, "-m", "api.worker"],
            env=env,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )

    def log(self) -> str:
        self.log_file.flush()
        with open(self.log_file.name, encoding="utf-8", errors="replace") as f:
            return f.read()

    def wait_for_exit(self, timeout: float) -> int:
        return self.process.wait(timeout=timeout)

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
        self.log_file.close()
        try:
            os.unlink(self.log_file.name)
        except OSError:
            pass


def _health_check_exit_code() -> int:
    """`python -m api.worker --check`, as the Compose healthcheck runs it."""
    return subprocess.run(
        [sys.executable, "-m", "api.worker", "--check"],
        env={**os.environ, "REDIS_URL": _REDIS_URL, "ENVIRONMENT": "test"},
        capture_output=True,
        timeout=30,
        check=False,
    ).returncode


def _wait_until_healthy(worker: _WorkerProcess) -> None:
    deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if worker.process.poll() is not None:
            pytest.fail(f"worker exited during startup:\n{worker.log()[-3000:]}")
        if _health_check_exit_code() == 0:
            return
        time.sleep(0.5)
    pytest.fail(f"worker never became healthy:\n{worker.log()[-3000:]}")


@pytest.fixture
def running_worker():
    worker = _WorkerProcess()
    try:
        _wait_until_healthy(worker)
        yield worker
    finally:
        worker.close()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --- Startup + health ----------------------------------------------------------


def test_real_worker_process_starts_and_reports_healthy(running_worker: _WorkerProcess) -> None:
    assert running_worker.process.poll() is None
    assert _health_check_exit_code() == 0
    log = running_worker.log()
    assert "worker_starting" in log
    assert "_ingest_usage_event_job" in log
    assert "_deliver_webhook" in log
    assert "_dispatch_notification_job" in log


def test_worker_log_never_contains_the_redis_or_database_credentials(
    running_worker: _WorkerProcess,
) -> None:
    log = running_worker.log()
    for url in (_REDIS_URL, get_database_config().url, get_migrations_database_config().url):
        assert url not in log
    assert "changeme" not in log


# --- Job execution through the real worker ------------------------------------


async def test_real_worker_executes_an_enqueued_job_end_to_end(
    running_worker: _WorkerProcess,
) -> None:
    tenant = create_tenant(f"p21-worker-{uuid.uuid4().hex[:8]}")
    since = datetime.now(UTC) - timedelta(minutes=5)
    until = datetime.now(UTC) + timedelta(minutes=5)
    try:
        job_id = await ingest_event(tenant.id, "p21_runtime", Decimal("1"))
        assert job_id

        deadline = time.monotonic() + _JOB_TIMEOUT_SECONDS
        total = Decimal("0")
        while time.monotonic() < deadline:
            total = aggregate_usage(tenant.id, "p21_runtime", since=since, until=until)
            if total == Decimal("1"):
                break
            await asyncio.sleep(0.25)
        assert total == Decimal("1"), running_worker.log()[-3000:]

        log = running_worker.log()
        assert "job_started" in log
        assert "job_succeeded" in log
    finally:
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.usage_events WHERE tenant_id = :t"), {"t": str(tenant.id)}
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


async def test_real_worker_retries_then_dead_letters_a_failing_job(
    running_worker: _WorkerProcess,
) -> None:
    """A usage event for a tenant that does not exist is rejected by the
    database (FK), so the registered handler raises `UsageIngestionError`
    every time -- the *existing* retry policy (`JOBS_MAX_TRIES=2` in the
    worker's environment) and the *existing* dead-letter recording are
    what this test observes, through the real worker process."""
    ghost_tenant_id = str(uuid.uuid4())
    payload = TenantJobPayload(
        tenant_id=ghost_tenant_id,
        data={
            "metric": "p21_ghost",
            "quantity": "1",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    config = _jobs_config()
    pool = await get_redis_pool(config)
    try:
        await enqueue_job("_ingest_usage_event_job", payload, pool=pool)
    finally:
        await pool.aclose()

    deadline = time.monotonic() + _JOB_TIMEOUT_SECONDS
    matching = []
    while time.monotonic() < deadline:
        verify_pool = await get_redis_pool(config)
        try:
            entries = await list_dead_letters(verify_pool, config, limit=1000)
        finally:
            await verify_pool.aclose()
        matching = [e for e in entries if e.tenant_id == ghost_tenant_id]
        if matching:
            break
        await asyncio.sleep(0.25)

    assert len(matching) == 1, running_worker.log()[-3000:]
    assert matching[0].function_name == "_ingest_usage_event_job"
    assert matching[0].attempts == 2
    assert "UsageIngestionError" in matching[0].error

    log = running_worker.log()
    assert "job_retry_scheduled" in log
    assert "job_dead_lettered" in log

    # Remove exactly this test's entry from the shared list (never the
    # whole key -- other entries may belong to other work).
    # redis-py's shared sync/async command typing needs the same casts
    # infra/jobs/dead_letter.py already documents.
    cleanup_pool = await get_redis_pool(config)
    try:
        raw_entries = await cast(
            "Awaitable[list[bytes]]", cleanup_pool.lrange(config.dead_letter_key, 0, -1)
        )
        for raw in raw_entries:
            if json.loads(raw)["tenant_id"] == ghost_tenant_id:
                await cast(
                    "Awaitable[int]",
                    cleanup_pool.lrem(config.dead_letter_key, 0, raw.decode("utf-8")),
                )
    finally:
        await cleanup_pool.aclose()


# --- Fail closed ----------------------------------------------------------------


def test_worker_exits_nonzero_when_redis_is_unreachable() -> None:
    worker = _WorkerProcess({"REDIS_URL": f"redis://127.0.0.1:{_free_port()}/0"})
    try:
        return_code = worker.wait_for_exit(timeout=60)
        assert return_code != 0
        log = worker.log()
        assert "worker_failed" in log or "worker_startup_failed" in log
    finally:
        worker.close()


def test_worker_exits_nonzero_when_redis_url_is_missing() -> None:
    env = {k: v for k, v in os.environ.items() if k != "REDIS_URL"}
    env.update({"ENVIRONMENT": "test"})
    result = subprocess.run(
        [sys.executable, "-m", "api.worker"], env=env, capture_output=True, timeout=60, check=False
    )
    assert result.returncode != 0
    assert b"worker_startup_failed" in result.stdout
    assert b"JobsConfigurationError" in result.stdout


def test_worker_refuses_to_run_under_the_migration_admin_role() -> None:
    """The worker gets no broader database privilege than the API: pointed
    at the superuser/migrations role it must exit non-zero before ever
    polling a job, and its log must not echo the connection string."""
    admin_url = get_migrations_database_config().url
    worker = _WorkerProcess({"DATABASE_URL": admin_url})
    try:
        return_code = worker.wait_for_exit(timeout=60)
        assert return_code != 0
        log = worker.log()
        assert "worker_startup_failed" in log
        assert "UnsafeDatabaseRoleError" in log
        assert admin_url not in log
        assert "changeme" not in log
    finally:
        worker.close()


# --- Graceful shutdown ----------------------------------------------------------


def test_real_worker_terminates_cleanly_on_sigterm(running_worker: _WorkerProcess) -> None:
    process = running_worker.process
    assert process.poll() is None

    if hasattr(signal, "SIGTERM"):
        process.send_signal(signal.SIGTERM)
    else:  # pragma: no cover -- Windows has no SIGTERM
        process.terminate()

    return_code = process.wait(timeout=_SHUTDOWN_TIMEOUT_SECONDS)

    if os.name == "posix":
        assert return_code == 0
        assert "worker_stopped" in running_worker.log()
        # arq's close() deletes the health sentinel -- a stopped worker
        # must no longer look healthy.
        assert _health_check_exit_code() == 1
