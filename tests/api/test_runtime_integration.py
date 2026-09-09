"""P1.8: real-process runtime validation of the production ASGI entrypoint
(`api/server.py`) -- deliberately NOT a `TestClient`-only test.

`TestClient` runs the ASGI app in-process and never proves the actual
production container command (`python -m api.server`, `Dockerfile`'s own
`CMD`) is a genuine, long-running, foreground HTTP server that a real
socket-level HTTP client can reach and that terminates cleanly on
`SIGTERM`. This file spawns that exact command as a real subprocess and
talks to it over a real TCP socket with `httpx` (already a project
dependency).

Marked `integration`; excluded from the default `pytest` run (mirrors
`tests/infra/health/test_health_integration.py`). Run locally the same
way:

    docker compose up -d db redis
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/api/test_runtime_integration.py

If PostgreSQL is unreachable, the subprocess's own P1.2 startup guard
fails fast (by design -- `infra/db/role_guard.py`) and this file's
`_wait_until_ready` helper turns that into a clear skip rather than a
confusing timeout.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

import httpx
import pytest

pytestmark = pytest.mark.integration

_DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os"
)
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

_STARTUP_TIMEOUT_SECONDS = 15
_SHUTDOWN_TIMEOUT_SECONDS = 10


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def running_server():
    port = _free_port()
    env = {
        **os.environ,
        "DATABASE_URL": _DATABASE_URL,
        "REDIS_URL": _REDIS_URL,
        "HOST": "127.0.0.1",
        "PORT": str(port),
        "ENVIRONMENT": "test",
    }
    # stdout/stderr go to a real file, never an unread `subprocess.PIPE`:
    # `infra.observability`'s console span exporter writes a line per
    # request, and an unread pipe fills its OS buffer after enough
    # requests (readiness polling below plus each test's own calls) --
    # once full, the child blocks on its own `write()` and every
    # in-flight HTTP request hangs with it. A file has no such backpressure.
    log_file = tempfile.NamedTemporaryFile(
        mode="w+", prefix="api_server_", suffix=".log", delete=False
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "api.server"],
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"

    def _read_log() -> str:
        log_file.flush()
        with open(log_file.name, encoding="utf-8", errors="replace") as f:
            return f.read()

    deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
    ready = False
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.skip(
                "api.server subprocess exited during startup (likely PostgreSQL/Redis "
                f"not reachable at the configured URL): {_read_log()[-2000:]}"
            )
        try:
            response = httpx.get(f"{base_url}/healthz", timeout=1)
        except httpx.TransportError:
            time.sleep(0.3)
            continue
        if response.status_code == 200:
            ready = True
            break
        time.sleep(0.3)

    if not ready:
        process.kill()
        process.wait(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
        pytest.fail(f"api.server subprocess never became reachable: {_read_log()[-2000:]}")

    try:
        yield process, base_url
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
        log_file.close()
        try:
            os.unlink(log_file.name)
        except OSError:
            pass


def test_real_server_process_serves_liveness(running_server) -> None:
    _process, base_url = running_server
    response = httpx.get(f"{base_url}/healthz", timeout=10)
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_real_server_process_serves_readiness(running_server) -> None:
    _process, base_url = running_server
    response = httpx.get(f"{base_url}/readyz", timeout=10)
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_real_server_process_preserves_correlation_header(running_server) -> None:
    _process, base_url = running_server
    response = httpx.get(
        f"{base_url}/healthz", headers={"X-Request-ID": "runtime-integration-id"}, timeout=10
    )
    assert response.status_code == 200
    assert response.headers["x-request-id"] == "runtime-integration-id"

    generated = httpx.get(f"{base_url}/healthz", timeout=10)
    assert generated.headers.get("x-request-id")


def test_real_server_process_serves_representative_existing_route(running_server) -> None:
    """No Authorization header -- proves the real server routes the request
    all the way through `api.dependencies.get_current_actor` (401), not
    just the two new health routes."""
    _process, base_url = running_server
    response = httpx.get(
        f"{base_url}/v1/tenants/00000000-0000-0000-0000-000000000000/status", timeout=10
    )
    assert response.status_code == 401
    assert response.headers.get("x-request-id")


def test_real_server_process_terminates_cleanly_on_sigterm(running_server) -> None:
    process, base_url = running_server
    assert process.poll() is None  # still running before the signal

    if hasattr(signal, "SIGTERM"):
        process.send_signal(signal.SIGTERM)
    else:  # pragma: no cover -- Windows has no SIGTERM
        process.terminate()

    return_code = process.wait(timeout=_SHUTDOWN_TIMEOUT_SECONDS)

    if os.name == "posix":
        assert return_code == 0

    with pytest.raises(httpx.TransportError):
        httpx.get(f"{base_url}/healthz", timeout=1)
