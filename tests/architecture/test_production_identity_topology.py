"""ADR-0023 Phase 3 -- structural verification of the production identity
network topology (`docker-compose.prod.yml`) via its own *rendered*
configuration (`docker compose ... config --format json`), not YAML
text-matching. Complements `scripts/check-docker-prod.sh`'s own heavier,
full-stack runtime checks (real containers, real negative-connectivity
`docker exec` probes) with a fast, Docker-daemon-optional check of the
same architectural properties -- network membership is what actually
enforces the intended least-privilege topology in this repository's own
established style (`docker-compose.prod.yml`'s own P2.3 comments: "a
service with no `ports:` entry and no membership in `edge` is unreachable
... by construction, not merely by a documented intention").

Requires the `docker` CLI on PATH; skipped (not failed) if unavailable --
the same posture `tests/infra/db/test_backup_restore_drill_integration.py`
and others already take for Docker-dependent checks.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

requires_docker = pytest.mark.skipif(
    shutil.which("docker") is None, reason="docker CLI not available"
)

# Deterministic, non-secret, throwaway values -- only ever used to let
# `docker compose config` render without warning; no container is started
# by this module (that is `scripts/check-docker-prod.sh`'s job).
_ENV = {
    "PUBLIC_DOMAIN": "app.test.invalid",
    "IDENTITY_PUBLIC_DOMAIN": "id.test.invalid",
    "ZITADEL_MASTERKEY": "0" * 32,
    "ZITADEL_DB_USER": "zitadel",
    "ZITADEL_DB_PASSWORD": "x",  # pragma: allowlist secret
    "ZITADEL_DB_NAME": "zitadel",
    "ZITADEL_FIRSTINSTANCE_ADMIN_USERNAME": "admin",
    "ZITADEL_FIRSTINSTANCE_ADMIN_PASSWORD": "x",  # pragma: allowlist secret
    "ZITADEL_FIRSTINSTANCE_ADMIN_EMAIL": "admin@id.test.invalid",
}


@pytest.fixture(scope="module")
def prod_config() -> dict:
    import os

    env = {**os.environ, **_ENV}
    result = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.prod.yml", "config", "--format", "json"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.fail(f"docker compose config failed:\n{result.stderr}")
    return json.loads(result.stdout)


@requires_docker
def test_production_compose_config_renders(prod_config: dict) -> None:
    assert "services" in prod_config
    for expected in (
        "backend",
        "worker",
        "frontend",
        "db",
        "redis",
        "proxy",
        "zitadel",
        "zitadel-db",
        "zitadel-bootstrap",
    ):
        assert expected in prod_config["services"], f"{expected!r} missing from rendered config"


@requires_docker
def test_only_proxy_publishes_host_ports(prod_config: dict) -> None:
    for name, svc in prod_config["services"].items():
        ports = svc.get("ports", [])
        if name == "proxy":
            published = sorted(str(p.get("published")) for p in ports)
            assert published == ["443", "80"], f"proxy publishes unexpected ports: {published}"
        else:
            assert not ports, f"{name!r} publishes a host port: {ports}"


@requires_docker
def test_identity_network_membership_matches_the_required_matrix(prod_config: dict) -> None:
    """The exact connectivity matrix ADR-0023 Phase 3 requires -- network
    membership is the enforcement mechanism, not credentials (docker-
    compose.prod.yml's own comments, mirrored here as an assertion)."""
    svcs = prod_config["services"]

    def networks(name: str) -> set[str]:
        return set(svcs[name].get("networks", {}).keys())

    expected = {
        "backend": {"edge", "internal", "identity-edge"},
        "proxy": {"edge", "identity-edge"},
        "worker": {"internal"},
        "frontend": {"edge"},
        "db": {"internal"},
        "redis": {"internal"},
        "zitadel": {"identity-edge", "identity-db"},
        "zitadel-db": {"identity-db"},
        "zitadel-bootstrap": {"identity-edge"},
    }
    for name, expected_nets in expected.items():
        actual = networks(name)
        assert actual == expected_nets, f"{name}: {sorted(actual)} != {sorted(expected_nets)}"


@requires_docker
def test_backend_is_not_a_member_of_identity_db(prod_config: dict) -> None:
    """The one connectivity property this ADR calls out explicitly as a
    structural requirement, not merely implied by the matrix above."""
    backend_networks = set(prod_config["services"]["backend"].get("networks", {}).keys())
    assert "identity-db" not in backend_networks


@requires_docker
def test_worker_is_not_a_member_of_either_identity_network(prod_config: dict) -> None:
    worker_networks = set(prod_config["services"]["worker"].get("networks", {}).keys())
    assert "identity-edge" not in worker_networks
    assert "identity-db" not in worker_networks


@requires_docker
def test_zitadel_network_alias_matches_identity_public_domain(prod_config: dict) -> None:
    """The mechanism that lets `backend`/`zitadel-bootstrap` reach
    `https://<IDENTITY_PUBLIC_DOMAIN>` directly, without hairpinning
    through Caddy -- verified empirically (ADR-0023 Phase 3 implementation
    report) against a real running stack; this test only proves the
    Compose-level wiring stays correct, not the runtime behavior."""
    zitadel = prod_config["services"]["zitadel"]
    aliases = zitadel.get("networks", {}).get("identity-edge", {}).get("aliases", [])
    assert aliases == [_ENV["IDENTITY_PUBLIC_DOMAIN"]]


@requires_docker
def test_zitadel_and_zitadel_db_have_dedicated_volumes_distinct_from_saas_db(
    prod_config: dict,
) -> None:
    """ADR-0023 S5, restated structurally: ZITADEL's own database must
    never share a volume (and therefore never share data/migration
    history) with the SaaS-OS `db` service."""
    volumes = set(prod_config.get("volumes", {}).keys())
    assert "zitadel-db-data-prod" in volumes
    assert "db-data-prod" in volumes
    assert "zitadel-db-data-prod" != "db-data-prod"

    zitadel_db_mounts = {
        m["source"] for m in prod_config["services"]["zitadel-db"].get("volumes", [])
    }
    saas_db_mounts = {m["source"] for m in prod_config["services"]["db"].get("volumes", [])}
    assert zitadel_db_mounts.isdisjoint(saas_db_mounts)


@requires_docker
def test_zitadel_bootstrap_reuses_the_phase_1_script_unmodified(prod_config: dict) -> None:
    """ADR-0023 Phase 3's own explicit requirement: the production
    bootstrap wrapper (deploy/bootstrap_zitadel_production.py) must
    delegate to, not duplicate, local-dev/bootstrap_zitadel.py."""
    mounts = prod_config["services"]["zitadel-bootstrap"].get("volumes", [])
    # `source` is rendered as an absolute, OS-native path (backslashes on
    # Windows) -- normalize before matching rather than assuming a
    # particular separator or a repo-root-relative form.
    sources = {Path(m["source"]) for m in mounts if m.get("type") == "bind"}
    assert any(s == REPO_ROOT / "local-dev" / "bootstrap_zitadel.py" for s in sources), (
        f"zitadel-bootstrap does not bind-mount the original, unmodified Phase 1 script: {sources}"
    )
