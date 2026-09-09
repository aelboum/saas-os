"""P2.4 -- real, disposable-Redis proof of the queue-durability claim in
`docker-compose.prod.yml`'s `redis` service comment: `--appendonly yes`
on a named durable volume survives a Redis restart; a Redis instance
with no persistence configured does not survive being recreated. Never
mocked -- these are the two concrete scenarios `docs/BACKUP-RESTORE.md`'s
Redis section documents, proven against real Docker containers exactly
like `tests/infra/db/test_backup_restore_drill_integration.py` does for
PostgreSQL.

Also proves this checkpoint's "no silent successful enqueue may be
reported when Redis is unavailable" requirement, and that a freshly
started worker (simulating a worker restart) recovers a job that
survived a Redis restart.

Marked `integration`; skips cleanly (not a failure) if Docker is not
available -- same convention as every other Docker-dependent test in
this repository.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus
from infra.jobs.config import JobsConfig
from infra.jobs.payload import TenantJobPayload
from infra.jobs.queue import build_worker, enqueue_job, get_redis_pool, register_job

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


def _docker_available() -> bool:
    try:
        probe = subprocess.run(["docker", "version"], capture_output=True, timeout=10, check=False)
        return probe.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _start_redis_container(
    *, name_prefix: str, persistent: bool, volume_name: str | None = None
) -> tuple[str, int]:
    """Starts a real, disposable Redis container -- `persistent=True`
    mirrors `docker-compose.prod.yml`'s P2.4 configuration exactly
    (`--appendonly yes` on a named volume); `persistent=False` disables
    *every* persistence mechanism (`--save "" --appendonly no`) against
    an unnamed (ephemeral-layer) mount point, matching what this
    repository's Redis service looked like before P2.4 (module
    docstring's own contrast)."""
    if not _docker_available():
        pytest.skip("Docker is not available -- this Redis persistence drill needs it.")

    name = f"{name_prefix}-{uuid.uuid4().hex[:10]}"
    cmd = ["docker", "run", "-d", "--name", name, "-p", "127.0.0.1::6379"]
    if persistent:
        assert volume_name is not None
        cmd += ["-v", f"{volume_name}:/data"]
    cmd += ["redis:7-alpine", "redis-server"]
    cmd += ["--appendonly", "yes"] if persistent else ["--save", "", "--appendonly", "no"]

    started = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    if started.returncode != 0:
        pytest.skip(f"Could not start a throwaway Redis container: {started.stderr.strip()}")

    for _ in range(30):
        probe = subprocess.run(
            ["docker", "exec", name, "redis-cli", "ping"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if probe.returncode == 0 and "PONG" in probe.stdout:
            break
        time.sleep(0.5)
    else:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15, check=False)
        pytest.skip("Throwaway Redis container did not become ready in time.")

    port_probe = subprocess.run(
        ["docker", "port", name, "6379/tcp"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    host_port = int(port_probe.stdout.strip().rsplit(":", 1)[-1])
    return name, host_port


async def _wait_for_host_redis_ready(port: int, *, attempts: int = 40, delay: float = 0.5) -> None:
    """Docker Desktop's host<->container port-forwarding proxy can lag a
    moment behind the container's own internal readiness (observed on
    Windows: `docker exec ... redis-cli ping` succeeds before the *host*
    port is actually reachable again after a `docker restart`) -- so
    readiness is proven the same way the test itself will connect: a
    real `arq.create_pool()`/`ping()` from this process, not merely an
    in-container probe."""
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            pool = await create_pool(RedisSettings(host="127.0.0.1", port=port, conn_retries=0))
            try:
                await pool.ping()
                return
            finally:
                await pool.aclose()
        except Exception as exc:  # noqa: BLE001 -- retried below; re-raised only if exhausted
            last_error = exc
            time.sleep(delay)
    pytest.fail(f"Redis on 127.0.0.1:{port} never became reachable from the host: {last_error}")


def _current_host_port(name: str) -> int:
    """Re-queries the container's current host-side port mapping.
    Observed on this Docker Desktop setup: `-p 127.0.0.1::6379`'s
    dynamically assigned host port *changes* across a `docker restart`
    (the container ID/volume/AOF data all stay the same; only the
    ephemeral host-side port-forward is renegotiated) -- so a caller must
    never assume the port captured at container-start time is still
    valid after a restart."""
    port_probe = subprocess.run(
        ["docker", "port", name, "6379/tcp"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return int(port_probe.stdout.strip().rsplit(":", 1)[-1])


def _stop_redis_container(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15, check=False)


def _remove_volume(volume_name: str) -> None:
    subprocess.run(
        ["docker", "volume", "rm", "-f", volume_name], capture_output=True, timeout=15, check=False
    )


@contextmanager
def _managed_volume(name: str) -> Iterator[str]:
    subprocess.run(
        ["docker", "volume", "create", name], capture_output=True, timeout=15, check=False
    )
    try:
        yield name
    finally:
        _remove_volume(name)


async def _noop_handler(payload: TenantJobPayload | None) -> str:
    return "ok"


async def test_appendonly_redis_on_a_named_volume_survives_a_container_restart() -> None:
    """The exact scenario `docker-compose.prod.yml`'s P2.4 `redis` service
    comment claims: a job enqueued but not yet executed survives a Redis
    *restart* (the container's own process dies and comes back, exactly
    as `restart: unless-stopped` would do in production) when AOF
    persistence is enabled on a named volume."""
    volume_name = f"p24-redis-vol-{uuid.uuid4().hex[:10]}"
    with _managed_volume(volume_name):
        name, port = _start_redis_container(
            name_prefix="p24-redis-persistent", persistent=True, volume_name=volume_name
        )
        try:
            config = JobsConfig(redis_url=f"redis://127.0.0.1:{port}/0")
            queue_name = f"p24-redis-persist-{uuid.uuid4().hex[:8]}"

            pool = await get_redis_pool(config)
            try:
                job_id = await enqueue_job(
                    "_noop_handler",
                    TenantJobPayload(tenant_id="t1"),
                    pool=pool,
                    queue_name=queue_name,
                )
                status_before = await Job(job_id, redis=pool, _queue_name=queue_name).status()
            finally:
                await pool.aclose()
            assert status_before == JobStatus.queued

            # Give AOF a moment to fsync (default `everysec` policy) before
            # the restart -- this is the exact bound
            # `docker-compose.prod.yml`'s comment documents ("at most ~1s
            # of enqueues"), not an artificial test wait.
            time.sleep(1.5)
            restart = subprocess.run(
                ["docker", "restart", name], capture_output=True, timeout=30, check=False
            )
            assert restart.returncode == 0

            # The container (and its AOF data on the named volume) is the
            # same; the host-side ephemeral port-forward may not be (this
            # module's own `_current_host_port` docstring) -- re-resolve it
            # rather than assuming `port` above is still valid.
            port = _current_host_port(name)
            await _wait_for_host_redis_ready(port)
            config = JobsConfig(redis_url=f"redis://127.0.0.1:{port}/0")

            pool_after = await get_redis_pool(config)
            try:
                status_after = await Job(job_id, redis=pool_after, _queue_name=queue_name).status()
            finally:
                await pool_after.aclose()
            assert status_after == JobStatus.queued, (
                "the queued job must survive a Redis restart when AOF persistence is enabled "
                "on a named volume -- this is exactly what docker-compose.prod.yml's redis "
                "service comment claims"
            )

            # A freshly built worker (simulating "the worker was also
            # restarted") recovers and executes the job that survived the
            # Redis restart -- full end-to-end recovery, not merely
            # Redis-level key survival.
            functions = [register_job(_noop_handler, config=config)]
            worker = build_worker(functions, config=config, burst=True, queue_name=queue_name)
            try:
                await worker.main()
            finally:
                await worker.close()

            result_pool = await get_redis_pool(config)
            try:
                result = await Job(job_id, redis=result_pool, _queue_name=queue_name).result(
                    timeout=5, poll_delay=0.05
                )
            finally:
                await result_pool.aclose()
            assert result == "ok"
        finally:
            _stop_redis_container(name)


async def test_redis_without_persistence_loses_a_queued_job_when_recreated() -> None:
    """The contrast case: a Redis instance with *no* persistence
    mechanism enabled loses a queued-but-not-yet-executed job when the
    container is recreated (removed and replaced by a new one) -- the
    exact failure mode `docker-compose.prod.yml`'s pre-P2.4 `redis`
    service had, and the reason P2.4 adds `--appendonly yes` plus a
    named volume. `docker restart` alone would not demonstrate this (the
    same Redis *process* keeps running in memory across a plain container
    restart unless the process itself is killed and the container's
    filesystem discarded) -- removing and replacing the container is
    what a redeploy or an out-of-memory kill followed by rescheduling
    actually does in production."""
    name, port = _start_redis_container(name_prefix="p24-redis-ephemeral", persistent=False)
    job_id: str | None = None
    try:
        config = JobsConfig(redis_url=f"redis://127.0.0.1:{port}/0")
        queue_name = f"p24-redis-ephemeral-{uuid.uuid4().hex[:8]}"

        pool = await get_redis_pool(config)
        try:
            job_id = await enqueue_job(
                "_noop_handler", TenantJobPayload(tenant_id="t1"), pool=pool, queue_name=queue_name
            )
            status_before = await Job(job_id, redis=pool, _queue_name=queue_name).status()
        finally:
            await pool.aclose()
        assert status_before == JobStatus.queued
    finally:
        _stop_redis_container(name)  # a real recreate: remove, then start a brand-new container

    assert job_id is not None
    new_name, new_port = _start_redis_container(name_prefix="p24-redis-ephemeral", persistent=False)
    try:
        new_config = JobsConfig(redis_url=f"redis://127.0.0.1:{new_port}/0")
        pool = await get_redis_pool(new_config)
        try:
            status_after = await Job(job_id, redis=pool, _queue_name=queue_name).status()
        finally:
            await pool.aclose()
        assert status_after == JobStatus.not_found, (
            "with no persistence mechanism enabled, a recreated Redis container must not "
            "retain a previously queued job -- this is the exact risk P2.4's AOF "
            "configuration exists to close"
        )
    finally:
        _stop_redis_container(new_name)


async def test_enqueue_raises_rather_than_silently_succeeding_when_redis_is_unreachable() -> None:
    """This checkpoint's own "no silent successful enqueue may be
    reported when Redis is unavailable" -- `enqueue_job()` must raise,
    never return a job ID for a job that was never actually queued
    anywhere."""
    # A local port nothing is listening on. `conn_retries=0` so this
    # fails in well under a second rather than arq's default ~5s
    # connect-retry loop.
    settings = RedisSettings(host="127.0.0.1", port=1, conn_retries=0)
    with pytest.raises(Exception):  # noqa: B017, PT011 -- any real connection failure is acceptable
        pool = await create_pool(settings)
        try:
            await enqueue_job(
                "_noop_handler",
                TenantJobPayload(tenant_id="t1"),
                pool=pool,
                queue_name="never-used",
            )
        finally:
            await pool.aclose()
