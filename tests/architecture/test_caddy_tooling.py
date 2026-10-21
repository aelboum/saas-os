"""The proxy routing suite (`test_identity_proxy_routing.py`) needs the Caddy
release `docker-compose.prod.yml` pins. CI installs that release and requires
it, so the suite runs there instead of being skipped. These checks keep the
three version statements in step and the requirement switched on."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _routing_suite_version() -> str:
    text = (REPO_ROOT / "tests/architecture/test_identity_proxy_routing.py").read_text(
        encoding="utf-8"
    )
    match = re.search(r'^PINNED_CADDY_VERSION = "v([0-9.]+)"$', text, re.MULTILINE)
    assert match, "PINNED_CADDY_VERSION not found"
    return match.group(1)


def test_ci_installs_the_caddy_release_the_production_compose_file_pins() -> None:
    version = _routing_suite_version()
    compose = (REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert f"image: caddy:{version}-alpine" in compose
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert f"/releases/download/v{version}/caddy_{version}_linux_amd64.tar.gz" in ci, (
        "CI must download the pinned Caddy release"
    )
    assert "sha512sum -c -" in ci, "CI must verify the Caddy archive"


def test_ci_requires_caddy_for_the_backend_suite() -> None:
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    backend = ci.split("\n  frontend:", 1)[0]
    assert 'SAAS_OS_REQUIRE_CADDY: "1"' in backend
