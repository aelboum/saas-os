"""`scripts/check-docker.sh` publishes no host port (AI gap register,
Stage 4 table: the check failed on a machine where another stack held
port 8000, before any runtime probe ran).

- The script's Compose command takes `local-dev/compose.check-docker.yml`.
- With that override, no service the script starts publishes a port. The
  services are read from the script's own `up -d` lines, so a service added
  there without a cleared port fails this test.
- The override clears ports and nothing else (no environment, no other key).

The rendering check (`docker compose config --format json`, as in
`test_email_provider_topology.py`) is skipped when the `docker` CLI is
absent; the text checks always run.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-docker.sh"
OVERRIDE = "local-dev/compose.check-docker.yml"

requires_docker = pytest.mark.skipif(
    shutil.which("docker") is None, reason="docker CLI not available"
)


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _runtime_command() -> str:
    match = re.search(r'^COMPOSE_RUNTIME="([^"]*)"$', _script(), re.MULTILINE)
    assert match, "COMPOSE_RUNTIME is not defined in scripts/check-docker.sh"
    return match.group(1)


def _started_services() -> set[str]:
    services: set[str] = set()
    for line in re.findall(
        r"^\$COMPOSE_RUNTIME (?:up -d|start) ([^\n>]+)", _script(), re.MULTILINE
    ):
        services.update(word for word in line.split() if not word.startswith("-"))
    return services


def test_the_runtime_compose_command_takes_the_check_override() -> None:
    assert _runtime_command().split() == [
        "docker",
        "compose",
        "-p",
        "saas-os-check-runtime",
        "-f",
        "docker-compose.yml",
        "-f",
        OVERRIDE,
    ]


def test_the_script_starts_the_services_this_test_expects() -> None:
    # Guards the parsing below: if the script stops naming services this
    # way, the rendering check would silently check nothing.
    assert {"db", "redis", "backend", "worker"} <= _started_services()


def test_the_override_only_clears_ports() -> None:
    text = (REPO_ROOT / OVERRIDE).read_text(encoding="utf-8")
    body = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    assert body[0] == "services:"
    for line in body[1:]:
        assert re.fullmatch(r"  [a-z][a-z0-9-]*:|    ports: !reset \[\]", line), line


@requires_docker
def test_no_service_the_script_starts_publishes_a_host_port() -> None:
    env_path = REPO_ROOT / ".env"
    created_env = not env_path.exists()
    if created_env:
        shutil.copy(REPO_ROOT / ".env.example", env_path)
    try:
        result = subprocess.run(
            [*_runtime_command().split(), "config", "--format", "json"],
            cwd=REPO_ROOT,
            env={**os.environ},
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        if created_env:
            env_path.unlink(missing_ok=True)
    if result.returncode != 0:
        pytest.fail(f"`docker compose config` failed with exit code {result.returncode}")
    services = json.loads(result.stdout)["services"]
    published = {name: services[name].get("ports") for name in _started_services()}
    assert not any(published.values()), published
