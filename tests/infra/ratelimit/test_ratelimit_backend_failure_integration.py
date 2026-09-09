"""P1.5 -- rate limiter backend-failure tests against *real* Redis failure
conditions (docs/IMPLEMENTATION-ROADMAP.md P1.5's own Security Decision:
"backend failure behavior must be deliberate, deterministic, and
tested").

`tests/infra/ratelimit/test_ratelimit_backend_failure_unit.py` covers the
same contract with a duck-typed fake client (every `redis.exceptions`
subclass, fast, no external dependency); this file proves it holds
against genuine network failures a mock cannot fully stand in for:

  1. connection refused -- nothing listening on the target port at all.
  2. a real Redis instance that *was* reachable and is then stopped
     mid-test (docs/IMPLEMENTATION-ROADMAP.md P1.5 section 13: "safely
     stop/isolate the test Redis instance").

Both use a throwaway, disposable container this file starts and tears
down itself -- never the developer's own `saas-os-redis-1`, never any
shared/project Redis a caller might be relying on for something else.

Marked `integration` and excluded from the default `pytest` run.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest
from infra.ratelimit.config import RateLimitConfig
from infra.ratelimit.errors import RateLimitBackendError
from infra.ratelimit.limiter import check_rate_limit

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _docker_available() -> bool:
    try:
        probe = subprocess.run(["docker", "version"], capture_output=True, timeout=10, check=False)
        return probe.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _unique_key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# --- 1. Connection refused: nothing listening at all -----------------------


async def test_connection_refused_becomes_a_rate_limit_backend_error() -> None:
    """Port 1 is a real, privileged TCP port nothing binds to in this
    environment -- a genuine `ConnectionRefusedError` from the OS/kernel,
    not a mock. No Docker dependency; runs whenever the integration suite
    does."""
    config = RateLimitConfig(redis_url="redis://127.0.0.1:1/0")
    with pytest.raises(RateLimitBackendError) as excinfo:
        await check_rate_limit(_unique_key("refused"), config=config)
    assert excinfo.value.__cause__ is not None


# --- 2. A real instance that was reachable, then stopped --------------------


@pytest.fixture
def throwaway_redis() -> Iterator[tuple[str, int]]:
    if not _docker_available():
        pytest.skip("Docker is not available -- this test needs a disposable Redis container.")

    name = f"p15-ratelimit-drill-{uuid.uuid4().hex[:10]}"
    run_cmd = ["docker", "run", "-d", "--name", name, "-p", "127.0.0.1::6379", "redis:7-alpine"]
    started = subprocess.run(run_cmd, capture_output=True, text=True, timeout=60, check=False)
    if started.returncode != 0:
        pytest.skip(f"Could not start a throwaway Redis container: {started.stderr.strip()}")

    try:
        for _ in range(30):
            probe = subprocess.run(
                ["docker", "exec", name, "redis-cli", "ping"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if probe.returncode == 0 and b"PONG" in probe.stdout:
                break
            time.sleep(1)
        else:
            pytest.skip("Throwaway Redis container did not become ready in time.")

        port_probe = subprocess.run(
            ["docker", "port", name, "6379/tcp"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        host_port = int(port_probe.stdout.strip().rsplit(":", 1)[-1])
        yield name, host_port
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30, check=False)


async def test_a_previously_healthy_redis_that_goes_down_becomes_a_backend_error(
    throwaway_redis: tuple[str, int],
) -> None:
    name, port = throwaway_redis
    config = RateLimitConfig(redis_url=f"redis://127.0.0.1:{port}/0", requests_per_window=5)
    key = _unique_key("outage-drill")

    # Sanity: genuinely healthy and working before the outage.
    healthy_result = await check_rate_limit(key, config=config)
    assert healthy_result.allowed is True

    # Simulate the outage: stop (not remove -- the fixture removes it) the
    # container the configured REDIS_URL points at.
    stopped = subprocess.run(["docker", "stop", name], capture_output=True, timeout=30, check=False)
    assert stopped.returncode == 0, f"failed to stop throwaway Redis container: {stopped.stderr}"

    try:
        with pytest.raises(RateLimitBackendError) as excinfo:
            await check_rate_limit(key, config=config)
        assert excinfo.value.key == key
        assert excinfo.value.__cause__ is not None
    finally:
        # docker rm -f in the fixture's own teardown works on a stopped
        # container too, but starting it back up first keeps this test's
        # own intent explicit: prove recovery is possible, not just that
        # teardown doesn't error.
        subprocess.run(["docker", "start", name], capture_output=True, timeout=30, check=False)


def _free_tcp_port() -> int:
    """A genuinely free host port, obtained the standard way (bind to
    port 0, read back what the OS assigned, release it immediately)."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def throwaway_redis_fixed_port() -> Iterator[tuple[str, int]]:
    """Like `throwaway_redis`, but published on a *fixed* (not
    Docker-ephemeral) host port -- needed only by the recovery test
    below. Docker Desktop on Windows reassigns a new random host port
    every time an ephemeral (`-p 127.0.0.1::6379`) container is
    restarted (confirmed empirically while building this test: the same
    container's published port changed across a stop/start cycle) --
    a Windows/Docker Desktop networking artifact of *how this test
    container is published*, unrelated to real Redis restart-in-place
    behavior (a real deployment's `REDIS_URL` does not change when Redis
    restarts). Publishing on a fixed port sidesteps that artifact so this
    test proves the property it actually intends to: the exact same,
    unchanged `RateLimitConfig` resumes working once Redis is reachable
    again."""
    if not _docker_available():
        pytest.skip("Docker is not available -- this test needs a disposable Redis container.")

    name = f"p15-ratelimit-recovery-{uuid.uuid4().hex[:10]}"
    port = _free_tcp_port()
    run_cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "-p",
        f"127.0.0.1:{port}:6379",
        "redis:7-alpine",
    ]
    started = subprocess.run(run_cmd, capture_output=True, text=True, timeout=60, check=False)
    if started.returncode != 0:
        pytest.skip(f"Could not start a throwaway Redis container: {started.stderr.strip()}")

    try:
        for _ in range(30):
            probe = subprocess.run(
                ["docker", "exec", name, "redis-cli", "ping"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if probe.returncode == 0 and b"PONG" in probe.stdout:
                break
            time.sleep(1)
        else:
            pytest.skip("Throwaway Redis container did not become ready in time.")
        yield name, port
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30, check=False)


async def test_service_recovers_once_redis_is_back(
    throwaway_redis_fixed_port: tuple[str, int],
) -> None:
    """The failure is transient, not a permanent trip -- once Redis is
    reachable again, the exact same config/key resumes working normally
    (no persistent circuit-breaker state, no process-local fallback
    counter left over from the outage)."""
    name, port = throwaway_redis_fixed_port
    config = RateLimitConfig(redis_url=f"redis://127.0.0.1:{port}/0", requests_per_window=5)
    key = _unique_key("recovery-drill")

    healthy_before = await check_rate_limit(key, config=config)
    assert healthy_before.allowed is True

    subprocess.run(["docker", "stop", name], capture_output=True, timeout=30, check=False)
    with pytest.raises(RateLimitBackendError):
        await check_rate_limit(key, config=config)

    restarted = subprocess.run(
        ["docker", "start", name], capture_output=True, timeout=30, check=False
    )
    assert restarted.returncode == 0

    # `docker exec ... redis-cli ping` only proves the process inside the
    # container is up -- it talks over the container's internal loopback,
    # not the published host port this test actually connects through.
    # Poll the real host-port path (what check_rate_limit itself uses)
    # instead, since the two can become ready at slightly different times.
    recovered_result = None
    last_error: RateLimitBackendError | None = None
    for _ in range(30):
        try:
            recovered_result = await check_rate_limit(key, config=config)
            break
        except RateLimitBackendError as exc:
            last_error = exc
            time.sleep(1)
    assert recovered_result is not None, f"host port never became reachable again: {last_error}"
    assert recovered_result.allowed is True
