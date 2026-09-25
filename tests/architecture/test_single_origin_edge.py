"""ADR-0024 -- structural verification of the reusable single-origin edge:
the packaged Caddy configuration implements exactly the declared routing
contract (`infra/edge/routing.py`), exposes no internal service, and is the
same file the development Compose topology mounts.

Two halves, deliberately: the configuration-text assertions need nothing
but the repository, while the Compose assertions render
`docker-compose.yml` through `docker compose config` (the same mechanism
and skip-if-unavailable posture `test_production_identity_topology.py`
already uses). Nothing is started, and no rendered value is printed --
that file's services carry `env_file: .env`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from infra.edge import (
    BACKEND_EXACT_PATHS,
    BACKEND_ROUTE_PREFIXES,
    CADDY_BACKEND_PATH_MATCHER,
    read_local_edge_caddyfile,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGED_ASSET = REPO_ROOT / "infra" / "edge" / "assets" / "Caddyfile.local-edge"

requires_docker = pytest.mark.skipif(
    shutil.which("docker") is None, reason="docker CLI not available"
)


# --- the packaged local edge configuration --------------------------------


def test_the_asset_on_disk_is_what_the_package_serves() -> None:
    assert read_local_edge_caddyfile() == PACKAGED_ASSET.read_text(encoding="utf-8")


def test_the_backend_matcher_is_exactly_the_declared_contract() -> None:
    """One source of truth: the declared prefixes/paths and the matcher the
    proxy actually enforces are the same string."""
    caddyfile = read_local_edge_caddyfile()
    assert f"@backend path {CADDY_BACKEND_PATH_MATCHER}" in caddyfile
    for prefix in BACKEND_ROUTE_PREFIXES:
        assert f"{prefix}/*" in CADDY_BACKEND_PATH_MATCHER
    for path in BACKEND_EXACT_PATHS:
        assert path in CADDY_BACKEND_PATH_MATCHER


def test_exactly_two_upstreams_exist_and_both_are_application_services() -> None:
    """The edge proxies the product backend and the product frontend, and
    nothing else -- no internal service has a route through it."""
    upstreams = [
        line.strip().split(None, 1)[1]
        for line in read_local_edge_caddyfile().splitlines()
        if line.strip().startswith("reverse_proxy ")
    ]
    assert upstreams == [
        "{$SAAS_OS_BACKEND_INTERNAL_ORIGIN:http://backend:8000}",
        "{$SAAS_OS_FRONTEND_INTERNAL_ORIGIN:http://frontend:3000}",
    ]


@pytest.mark.parametrize(
    "forbidden",
    ["postgres", "5432", "redis", "6379", "zitadel", "worker", "temporal", "/bootstrap"],
)
def test_no_internal_service_is_reachable_through_the_edge(forbidden: str) -> None:
    configuration = "\n".join(
        line
        for line in read_local_edge_caddyfile().splitlines()
        if not line.strip().startswith("#")
    )
    assert forbidden not in configuration.lower()


def test_the_caddy_admin_api_is_disabled() -> None:
    """Caddy's admin endpoint is a full runtime configuration-rewrite
    surface; nothing here reconfigures Caddy at runtime."""
    assert "admin off" in read_local_edge_caddyfile()


def test_the_local_edge_makes_no_tls_or_certificate_claim() -> None:
    """It is a development composition, never a production edge."""
    caddyfile = read_local_edge_caddyfile()
    assert "auto_https off" in caddyfile
    for production_only in ("tls ", "Strict-Transport-Security", "acme", "email "):
        assert production_only not in caddyfile


PRODUCTION_PROFILE_DIR = REPO_ROOT / "deploy" / "caddy"
PRODUCTION_PROFILES = ("fresh", "existing")


def _block_after(text: str, opener: str) -> str:
    """The body of the brace block that starts at `opener` (which must end
    with `{`), found by brace matching rather than by line layout."""
    start = text.index(opener) + len(opener)
    depth = 1
    for position in range(start, len(text)):
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
            if depth == 0:
                return text[start:position]
    raise AssertionError(f"unterminated block after {opener!r}")


def test_the_production_edge_loads_its_site_blocks_from_the_identity_profile() -> None:
    """The production site blocks live in the ADR-0025 identity-profile files
    that the repository-root Caddyfile imports; the root file itself routes
    nothing."""
    root = (REPO_ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert (
        "import /etc/caddy/identity-profiles/identity-profile-{$IDENTITY_PROFILE}.caddyfile" in root
    )
    directives = [line for line in root.splitlines() if not line.lstrip().startswith("#")]
    assert not any("reverse_proxy" in line for line in directives)
    for profile in PRODUCTION_PROFILES:
        assert (PRODUCTION_PROFILE_DIR / f"identity-profile-{profile}.caddyfile").is_file()


@pytest.mark.parametrize("profile", PRODUCTION_PROFILES)
def test_the_production_edge_still_withholds_the_health_endpoints(profile: str) -> None:
    """The local edge exposes /healthz and /readyz on the public origin as a
    developer convenience; the production edge's deliberate decision not to
    proxy them to the backend is unchanged by ADR-0024, in both ADR-0025
    identity profiles. Checked on the application site (`{$PUBLIC_DOMAIN}`)
    of each profile file, the configuration production actually loads."""
    text = (PRODUCTION_PROFILE_DIR / f"identity-profile-{profile}.caddyfile").read_text(
        encoding="utf-8"
    )
    site = _block_after(text, "{$PUBLIC_DOMAIN} {")

    assert "@internal_health path /healthz /readyz" in site
    health = _block_after(site, "handle @internal_health {")
    assert "reverse_proxy frontend:3000" in health
    assert "backend:8000" not in health

    assert "@backend path /auth/* /v1/*" in site
    backend = _block_after(site, "handle @backend {")
    assert "reverse_proxy backend:8000" in backend
    backend_matcher = next(
        line for line in site.splitlines() if line.strip().startswith("@backend path")
    )
    for health_path in BACKEND_EXACT_PATHS:
        assert health_path not in backend_matcher


# --- the development Compose topology -------------------------------------


@pytest.fixture(scope="module")
def dev_config() -> dict:
    # `docker-compose.yml`'s services declare `env_file: .env`, which
    # Compose requires to exist on disk. Same convention as
    # `test_production_identity_topology.py` and `scripts/check-docker.sh`:
    # create `.env` from `.env.example` (placeholders only, no real secret)
    # only when genuinely absent, and always remove exactly what was
    # created -- a developer's own `.env` is never read, modified, or
    # touched.
    env_path = REPO_ROOT / ".env"
    created_env = not env_path.exists()
    if created_env:
        shutil.copy(REPO_ROOT / ".env.example", env_path)
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", "docker-compose.yml", "config", "--format", "json"],
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
        # Never echo the rendered configuration -- only the (short) error.
        pytest.fail(f"`docker compose config` failed with exit code {result.returncode}")
    return json.loads(result.stdout)


@requires_docker
def test_the_development_compose_declares_the_edge_service(dev_config: dict) -> None:
    edge = dev_config["services"]["edge"]
    assert edge["image"] == "caddy:2-alpine"
    # The production `proxy` service's own posture: everything dropped, one
    # capability re-added (the image's `caddy` binary carries it in its own
    # file-capability set and cannot exec without it in the bounding set).
    assert edge["cap_drop"] == ["ALL"]
    assert edge["cap_add"] == ["NET_BIND_SERVICE"]


@requires_docker
def test_the_edge_mounts_the_packaged_asset_read_only(dev_config: dict) -> None:
    """This repository is the first consumer of its own reusable edge --
    not a parallel, hand-maintained copy of it."""
    mounts = [
        volume
        for volume in dev_config["services"]["edge"].get("volumes", [])
        if volume.get("target") == "/etc/caddy/Caddyfile"
    ]
    assert len(mounts) == 1
    assert Path(mounts[0]["source"]).resolve() == PACKAGED_ASSET.resolve()
    assert mounts[0]["read_only"] is True


@requires_docker
def test_the_edge_publishes_exactly_one_port_targeting_the_documented_listener(
    dev_config: dict,
) -> None:
    ports = dev_config["services"]["edge"].get("ports", [])
    assert len(ports) == 1
    assert ports[0]["target"] == 8080


@requires_docker
def test_the_edge_receives_no_credential(dev_config: dict) -> None:
    """A reverse proxy needs no application secret: the service declares no
    `env_file` and no environment at all."""
    edge = dev_config["services"]["edge"]
    assert not edge.get("env_file")
    assert not edge.get("environment")
