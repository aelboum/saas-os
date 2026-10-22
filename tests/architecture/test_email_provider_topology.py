"""ADR-0057 -- structural checks that Mailpit stays a development-only mail
catcher:

- the development Compose file runs it from an exactly pinned image, keeps
  its SMTP listener inside the Compose network, and publishes only its web
  UI, on loopback;
- the check-only no-host-ports override clears that one published port;
- nothing production-facing mentions it: not `docker-compose.prod.yml`,
  not the production settings template `.env.app.example`, not `deploy/`;
- the production settings template selects a real provider with TLS.

The development check renders `docker-compose.yml` (`docker compose config
--format json`), the same way `test_single_origin_edge.py` does, and is
skipped when the `docker` CLI is absent. The production checks are text
checks and always run: the strongest statement about production is that
the word does not appear at all.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

requires_docker = pytest.mark.skipif(
    shutil.which("docker") is None, reason="docker CLI not available"
)

MAILPIT_IMAGE = "axllent/mailpit:v1.31.3"


def _render(*compose_files: str) -> dict:
    # `docker-compose.yml`'s services declare `env_file: .env`, which Compose
    # requires to exist. Same convention as `test_single_origin_edge.py`:
    # create `.env` from `.env.example` only when genuinely absent, and
    # always remove exactly what was created -- a developer's own `.env` is
    # never modified.
    env_path = REPO_ROOT / ".env"
    created_env = not env_path.exists()
    if created_env:
        shutil.copy(REPO_ROOT / ".env.example", env_path)
    try:
        args = [arg for name in compose_files for arg in ("-f", name)]
        result = subprocess.run(
            ["docker", "compose", *args, "config", "--format", "json"],
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
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def dev_config() -> dict:
    return _render("docker-compose.yml")


@requires_docker
def test_mailpit_is_pinned_to_an_exact_release(dev_config: dict) -> None:
    assert dev_config["services"]["mailpit"]["image"] == MAILPIT_IMAGE


@requires_docker
def test_mailpit_publishes_only_its_web_ui_on_loopback(dev_config: dict) -> None:
    ports = dev_config["services"]["mailpit"].get("ports", [])
    assert len(ports) == 1
    (port,) = ports
    assert port["target"] == 8025
    assert port["host_ip"] == "127.0.0.1"


@requires_docker
def test_mailpit_smtp_is_never_published_to_the_host(dev_config: dict) -> None:
    for name, service in dev_config["services"].items():
        for port in service.get("ports", []):
            assert port["target"] != 1025, f"{name} publishes an SMTP catcher port"
            assert str(port.get("published")) != "1025", f"{name} publishes host port 1025"


@requires_docker
def test_the_worker_starts_after_mailpit(dev_config: dict) -> None:
    depends_on = dev_config["services"]["worker"]["depends_on"]
    assert depends_on["mailpit"]["condition"] == "service_healthy"


@requires_docker
def test_mailpit_receives_no_application_credential(dev_config: dict) -> None:
    """Mailpit gets only its own `MP_*` settings -- no `env_file`, so no
    application secret or SMTP relay credential reaches it."""
    service = dev_config["services"]["mailpit"]
    assert "env_file" not in service
    assert set(service.get("environment", {})) <= {"MP_MAX_MESSAGES"}


@requires_docker
def test_the_no_host_ports_override_clears_mailpit() -> None:
    config = _render("docker-compose.yml", "local-dev/compose.no-host-ports.yml")
    assert not config["services"]["mailpit"].get("ports")


def _production_facing_files() -> list[Path]:
    files = [REPO_ROOT / "docker-compose.prod.yml", REPO_ROOT / ".env.app.example"]
    files += sorted(p for p in (REPO_ROOT / "deploy").rglob("*") if p.is_file())
    return [p for p in files if "__pycache__" not in p.parts]


@pytest.mark.parametrize(
    "path", _production_facing_files(), ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_no_production_facing_file_mentions_mailpit(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace").lower()
    # `.env.app.example` may say that Mailpit is refused; it must never
    # select it or configure it.
    if path.name == ".env.app.example":
        lines = [line.strip() for line in text.splitlines() if not line.startswith("#")]
        assert not any("mailpit" in line for line in lines)
    else:
        assert "mailpit" not in text


def _settings(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, value = stripped.partition("=")
            values[key.strip()] = value.strip()
    return values


def test_the_production_template_selects_smtp_with_tls() -> None:
    values = _settings(REPO_ROOT / ".env.app.example")
    assert values["ENVIRONMENT"] == "production"
    assert values["EMAIL_PROVIDER"] == "smtp"
    assert values["SMTP_TLS_MODE"] in {"starttls", "implicit"}
    assert values.get("SMTP_REQUIRE_TLS", "true").lower() not in {"0", "false", "no", "off"}
    assert "SMTP_USE_TLS" not in values  # one TLS setting, no alias to contradict it


def test_the_development_template_selects_mailpit_for_development_only() -> None:
    values = _settings(REPO_ROOT / ".env.example")
    assert values["ENVIRONMENT"] == "development"
    assert values["EMAIL_PROVIDER"] == "mailpit"
