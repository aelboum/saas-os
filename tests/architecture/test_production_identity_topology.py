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
    "ZITADEL_BOOTSTRAP_PAT_EXPIRATION": "2026-11-14T00:00:00Z",
    "ZITADEL_SESSION_COOKIE_SECRET": "c" * 32,
    "OIDC_REDIRECT_URI": "https://app.test.invalid/auth/callback",
    "POSTGRES_USER": "postgres",
    "POSTGRES_PASSWORD": "x",  # pragma: allowlist secret
    "POSTGRES_DB": "saas_os",
    "APP_DB_USER": "app",
    "APP_DB_PASSWORD": "x",  # pragma: allowlist secret
    "IDENTITY_PROFILE": "existing",
}

# The one ZITADEL release every identity image is pinned to. v4.19.5 carries
# the v4.19.2 security fixes (GHSA-jh92-5mrj-p2w2: unsigned Login V2 session
# cookie; docs/SECURITY.md section 2.2).
ZITADEL_VERSION = "v4.19.5"

# ADR-0025 §1a: the fresh (Topology A) profile -- ZITADEL on PUBLIC_DOMAIN.
_FRESH_ENV = {
    **_ENV,
    "IDENTITY_PROFILE": "fresh",
    "IDENTITY_PUBLIC_DOMAIN": _ENV["PUBLIC_DOMAIN"],
}

# Variables whose value this module controls. Stripped from the inherited
# process environment before rendering, and Compose's own `.env`
# interpolation is replaced by an empty `--env-file`, so a developer's
# shell or `.env` can never change what is being asserted -- in particular
# the `IDENTITY_PROFILE` default an existing deployment gets when it never
# sets the variable at all.
_CONTROLLED = (*_ENV, "ZITADEL_LOGIN_V2_ENABLED")


def _render(
    env_overrides: dict[str, str], tmp_dir: Path, *, profiles: tuple[str, ...] = ()
) -> dict:
    import os

    # `docker-compose.prod.yml` declares `env_file: - .env` on four
    # services -- Compose requires that file to actually exist on disk,
    # independent of the `_ENV` process-environment overrides below
    # (those only satisfy `${VAR}` substitution, never `env_file:`). A
    # clean CI checkout has no `.env` (gitignored). Compose resolves a
    # relative `env_file:`/bind-mount path against the *project
    # directory* (this compose file's own directory here, since no
    # `--project-directory` override is passed) -- `--project-directory`
    # was tried and rejected: it also redirects every relative bind
    # mount (e.g. `./local-dev/bootstrap_zitadel.py`) into the same
    # throwaway directory, breaking
    # test_zitadel_bootstrap_reuses_the_phase_1_script_unmodified's own
    # real-repo-path assertion. Instead, this fixture follows
    # `scripts/check-docker.sh`'s own established convention (`[ -f .env
    # ] || cp .env.example .env`) directly at the real repository root
    # -- the only place Compose will actually look -- but, unlike that
    # script, only ever creates the file when one is genuinely absent,
    # and always removes exactly what it created afterward: a
    # developer's own pre-existing `.env` is never read, modified, or
    # touched.
    env_path = REPO_ROOT / ".env"
    created_env = not env_path.exists()
    if created_env:
        shutil.copy(REPO_ROOT / ".env.example", env_path)

    empty_env_file = tmp_dir / "empty.env"
    empty_env_file.write_text("", encoding="utf-8")
    try:
        env = {k: v for k, v in os.environ.items() if k not in _CONTROLLED}
        env.update(env_overrides)
        result = subprocess.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(empty_env_file),
                "-f",
                "docker-compose.prod.yml",
                # ADR-0028 D1: `db`/`redis` carry
                # `profiles: ["bundled-stateful"]`, so a default render is the
                # *production* topology and a profile-activated render is the
                # *bundled/reference* one. Which topology a test means is
                # therefore an explicit argument here, never an implicit
                # default -- see `prod_config` vs `bundled_config` below.
                *[arg for profile in profiles for arg in ("--profile", profile)],
                "config",
                "--format",
                "json",
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            pytest.fail(f"docker compose config failed:\n{result.stderr}")
        return json.loads(result.stdout)
    finally:
        if created_env:
            env_path.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def prod_config(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """The existing-deployment (ADR-0023 §9) profile, as ADR-0025 §1a
    keeps it: a separate IDENTITY_PUBLIC_DOMAIN."""
    return _render(_ENV, tmp_path_factory.mktemp("existing"))


@pytest.fixture(scope="module")
def bundled_config(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """The *bundled/reference* topology -- `docker-compose.prod.yml` with the
    `bundled-stateful` profile activated, which is what
    `scripts/check-docker-prod.sh` exercises. Only tests whose subject is the
    retained bundled `db`/`redis` may use this; everything describing the
    production contract uses `prod_config`."""
    return _render(_ENV, tmp_path_factory.mktemp("bundled"), profiles=("bundled-stateful",))


@pytest.fixture(scope="module")
def fresh_config(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """The fresh-deployment (ADR-0025 Topology A) profile."""
    return _render(_FRESH_ENV, tmp_path_factory.mktemp("fresh"))


@pytest.fixture(scope="module")
def unset_profile_config(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """An existing deployment that predates ADR-0025 and never sets
    IDENTITY_PROFILE or ZITADEL_LOGIN_V2_ENABLED."""
    env = {k: v for k, v in _ENV.items() if k != "IDENTITY_PROFILE"}
    return _render(env, tmp_path_factory.mktemp("unset"))


@requires_docker
def test_production_compose_config_renders(prod_config: dict) -> None:
    assert "services" in prod_config
    for expected in (
        "backend",
        "worker",
        "frontend",
        "proxy",
        "zitadel",
        "zitadel-db",
        "zitadel-bootstrap",
        "zitadel-login",
        "identity-profile-guard",
        "login-client-key-init",
    ):
        assert expected in prod_config["services"], f"{expected!r} missing from rendered config"


@requires_docker
def test_default_production_topology_has_no_bundled_stateful_services(
    prod_config: dict,
) -> None:
    """ADR-0028 D1: production PostgreSQL and Redis are operator-managed
    external endpoints. A default render must therefore contain neither
    service -- if either reappears here, a production `up` would start an
    unused stateful container alongside the real endpoint, which is exactly
    the ambiguous hybrid the ADR forbids."""
    services = prod_config["services"]
    assert "db" not in services
    assert "redis" not in services
    assert "db-data-prod" not in prod_config.get("volumes", {})
    assert "redis-data-prod" not in prod_config.get("volumes", {})


@requires_docker
def test_bundled_stateful_reference_topology_still_provides_db_and_redis(
    bundled_config: dict,
) -> None:
    """The other half of the same decision: the bundled services are
    retained, not deleted, so `scripts/check-docker-prod.sh` can still
    validate the reference perimeter (ADR-0027). Activating the profile must
    bring back both services and both named volumes."""
    services = bundled_config["services"]
    assert "db" in services
    assert "redis" in services
    assert "db-data-prod" in bundled_config.get("volumes", {})
    assert "redis-data-prod" in bundled_config.get("volumes", {})


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
        "zitadel": {"identity-edge", "identity-db"},
        "zitadel-db": {"identity-db"},
        "zitadel-bootstrap": {"identity-edge"},
        "zitadel-login": {"identity-edge"},
    }
    for name, expected_nets in expected.items():
        actual = networks(name)
        assert actual == expected_nets, f"{name}: {sorted(actual)} != {sorted(expected_nets)}"


@requires_docker
def test_bundled_stateful_services_stay_internal_only(bundled_config: dict) -> None:
    """The `db`/`redis` rows of the same matrix. They describe the retained
    bundled tier, so they are asserted against the profile-activated render
    rather than the production one -- the isolation property itself is
    unchanged from ADR-0023 Phase 3."""
    svcs = bundled_config["services"]
    for name in ("db", "redis"):
        actual = set(svcs[name].get("networks", {}).keys())
        assert actual == {"internal"}, f"{name}: {sorted(actual)} != ['internal']"


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
    bundled_config: dict,
) -> None:
    """ADR-0023 S5, restated structurally: ZITADEL's own database must
    never share a volume (and therefore never share data/migration
    history) with the SaaS-OS `db` service. Its subject is that `db`
    service, so it is asserted against the bundled/reference render -- in
    the production topology (ADR-0028 D1) there is no SaaS-OS `db` service
    to collide with in the first place."""
    volumes = set(bundled_config.get("volumes", {}).keys())
    assert "zitadel-db-data-prod" in volumes
    assert "db-data-prod" in volumes
    assert "zitadel-db-data-prod" != "db-data-prod"

    zitadel_db_mounts = {
        m["source"] for m in bundled_config["services"]["zitadel-db"].get("volumes", [])
    }
    saas_db_mounts = {m["source"] for m in bundled_config["services"]["db"].get("volumes", [])}
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


# --- ADR-0025: split-profile Login V2 ---------------------------------------


def _env(svc: dict) -> dict[str, str]:
    return {k: ("" if v is None else str(v)) for k, v in (svc.get("environment") or {}).items()}


def _volume_sources(svc: dict) -> set[str]:
    return {m["source"] for m in svc.get("volumes", []) if m.get("type") == "volume"}


def _bind_targets(svc: dict) -> dict[str, Path]:
    return {
        m["target"]: Path(m["source"]) for m in svc.get("volumes", []) if m.get("type") == "bind"
    }


@requires_docker
def test_unset_identity_profile_defaults_to_the_existing_profile(
    unset_profile_config: dict, prod_config: dict
) -> None:
    """An existing deployment that never sets IDENTITY_PROFILE is never
    switched to PUBLIC_DOMAIN: it renders exactly like the explicit
    `existing` profile, with Login V2 enablement off."""
    for name in ("proxy", "identity-profile-guard", "zitadel-bootstrap"):
        assert _env(unset_profile_config["services"][name])["IDENTITY_PROFILE"] == "existing"
    assert (
        _env(unset_profile_config["services"]["zitadel-bootstrap"])["ZITADEL_LOGIN_V2_ENABLED"]
        == "false"
    )
    for name in ("zitadel", "zitadel-login", "zitadel-bootstrap", "proxy"):
        assert _env(unset_profile_config["services"][name]) == _env(prod_config["services"][name])


@requires_docker
def test_existing_profile_keeps_its_identity_domain_and_issuer(prod_config: dict) -> None:
    """ADR-0025 §1a: no issuer, ExternalDomain or RP-ID host change for an
    existing deployment."""
    identity = _ENV["IDENTITY_PUBLIC_DOMAIN"]
    svcs = prod_config["services"]
    assert _env(svcs["zitadel"])["ZITADEL_EXTERNALDOMAIN"] == identity
    assert _env(svcs["zitadel-bootstrap"])["ZITADEL_INTERNAL_URL"] == f"https://{identity}"
    login = _env(svcs["zitadel-login"])
    assert login["ZITADEL_API_URL"] == f"https://{identity}"
    assert login["AUDIENCE"] == f"https://{identity}"
    assert _env(svcs["identity-tls-init"])["IDENTITY_PUBLIC_DOMAIN"] == identity


@requires_docker
def test_fresh_profile_puts_zitadel_on_public_domain(fresh_config: dict) -> None:
    """ADR-0025 Topology A: ExternalDomain (therefore the issuer
    https://<PUBLIC_DOMAIN>), the identity TLS certificate and the internal
    alias are all PUBLIC_DOMAIN -- one domain, one issuer."""
    public = _FRESH_ENV["PUBLIC_DOMAIN"]
    svcs = fresh_config["services"]
    assert _env(svcs["zitadel"])["ZITADEL_EXTERNALDOMAIN"] == public
    assert _env(svcs["zitadel"])["ZITADEL_EXTERNALSECURE"] == "true"
    assert _env(svcs["zitadel"])["ZITADEL_EXTERNALPORT"] == "443"
    aliases = svcs["zitadel"]["networks"]["identity-edge"]["aliases"]
    assert aliases == [public]
    assert _env(svcs["identity-tls-init"])["IDENTITY_PUBLIC_DOMAIN"] == public
    assert _env(svcs["zitadel-login"])["AUDIENCE"] == f"https://{public}"
    bootstrap = _env(svcs["zitadel-bootstrap"])
    assert bootstrap["IDENTITY_PROFILE"] == "fresh"
    assert bootstrap["PUBLIC_DOMAIN"] == bootstrap["IDENTITY_PUBLIC_DOMAIN"] == public
    assert _env(svcs["proxy"])["IDENTITY_PROFILE"] == "fresh"


@requires_docker
def test_login_v2_is_the_official_pinned_artifact_behind_the_proxy(prod_config: dict) -> None:
    svcs = prod_config["services"]
    login = svcs["zitadel-login"]
    assert login["image"] == f"ghcr.io/zitadel/zitadel-login:{ZITADEL_VERSION}"
    assert svcs["zitadel"]["image"] == f"ghcr.io/zitadel/zitadel:{ZITADEL_VERSION}"
    assert "build" not in login
    assert not login.get("ports")


@requires_docker
def test_login_v2_uses_a_system_user_jwt_and_only_it_holds_the_private_key(
    prod_config: dict,
) -> None:
    """ADR-0025 §7: system-user JWT (SYSTEM_USER_ID / SYSTEM_USER_PRIVATE_KEY
    / AUDIENCE), no PAT, and the private-key volume reaches no other
    long-running service."""
    svcs = prod_config["services"]
    login = _env(svcs["zitadel-login"])
    assert login["SYSTEM_USER_ID"] == "login-client"
    assert login["SYSTEM_USER_PRIVATE_KEY_FILE"] == "/login-client-private/login-client.pem"
    assert "SYSTEM_USER_PRIVATE_KEY" not in login
    assert not any("SERVICE_USER_TOKEN" in k for k in login)
    holders = {n for n, s in svcs.items() if "login-client-private" in _volume_sources(s)}
    assert holders == {"zitadel-login", "login-client-key-init"}
    login_mount = next(
        m for m in svcs["zitadel-login"]["volumes"] if m["source"] == "login-client-private"
    )
    assert login_mount.get("read_only") is True
    public_holders = {n for n, s in svcs.items() if "login-client-public" in _volume_sources(s)}
    assert public_holders == {"zitadel", "login-client-key-init"}


@requires_docker
def test_zitadel_registers_the_login_client_system_user(prod_config: dict) -> None:
    zitadel = prod_config["services"]["zitadel"]
    command = zitadel["command"]
    assert command[command.index("--config") + 1] == "/zitadel-config/login-client-system-user.yaml"
    binds = _bind_targets(zitadel)
    assert binds["/zitadel-config/login-client-system-user.yaml"] == (
        REPO_ROOT / "deploy" / "zitadel-login-client-system-user.yaml"
    )
    # Per-application Login V2 (loginVersion.loginV2.baseUri) is only honored
    # while the instance-wide requirement stays off.
    assert _env(zitadel)["ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED"] == "false"


def test_login_client_system_user_has_only_the_documented_login_role() -> None:
    """A system user without memberships would be SYSTEM_OWNER; this one is
    limited to ZITADEL's documented IAM_LOGIN_CLIENT role, and the file holds
    a public-key *path*, never key material."""
    text = (REPO_ROOT / "deploy" / "zitadel-login-client-system-user.yaml").read_text()
    body = [
        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]
    assert body == [
        "SystemAPIUsers:",
        "- login-client:",
        "Path: /login-client-public/login-client.pub",
        "Memberships:",
        "- MemberType: System",
        "Roles:",
        '- "IAM_LOGIN_CLIENT"',
    ]
    assert "PRIVATE KEY" not in text and "BEGIN" not in text


@requires_docker
def test_identity_tls_is_verified_never_disabled(prod_config: dict, fresh_config: dict) -> None:
    """No service turns certificate verification off (ADR-0025: no insecure
    TLS exceptions); Login V2 trusts ZITADEL's internal certificate via the
    image's own SSL_CERT_DIR support."""
    for config in (prod_config, fresh_config):
        for name, svc in config["services"].items():
            env = _env(svc)
            assert env.get("NODE_TLS_REJECT_UNAUTHORIZED") != "0", name
            assert "PYTHONHTTPSVERIFY" not in env, name
        login = config["services"]["zitadel-login"]
        assert _env(login)["SSL_CERT_DIR"] == "/identity-ca"
        assert "identity-ca" in _volume_sources(login)
    assert (
        "tls_insecure_skip_verify"
        not in (REPO_ROOT / "deploy" / "caddy" / "identity-profile-fresh.caddyfile").read_text()
    )


@requires_docker
def test_identity_profile_guard_gates_identity_startup(prod_config: dict) -> None:
    svcs = prod_config["services"]
    guard = svcs["identity-profile-guard"]
    assert guard.get("network_mode") == "none"
    assert "identity-profile-state" in _volume_sources(guard)
    tls_mount = next(m for m in guard["volumes"] if m["source"] == "identity-tls-server")
    assert tls_mount.get("read_only") is True
    # ZITADEL's database volume: read-only, existence check only, and
    # PostgreSQL may not initialize it before the guard has run.
    db_mount = next(m for m in guard["volumes"] if m["source"] == "zitadel-db-data-prod")
    assert db_mount["target"] == "/zitadel-db-data"
    assert db_mount.get("read_only") is True
    assert svcs["zitadel-db"]["depends_on"]["identity-profile-guard"]["condition"] == (
        "service_completed_successfully"
    )
    assert svcs["identity-tls-init"]["depends_on"]["identity-profile-guard"]["condition"] == (
        "service_completed_successfully"
    )
    zitadel_deps = svcs["zitadel"]["depends_on"]
    assert zitadel_deps["identity-tls-init"]["condition"] == "service_completed_successfully"
    assert zitadel_deps["login-client-key-init"]["condition"] == "service_completed_successfully"


@requires_docker
def test_proxy_is_pinned_and_mounts_both_identity_profiles(prod_config: dict) -> None:
    proxy = prod_config["services"]["proxy"]
    assert proxy["image"] == "caddy:2.11.4-alpine"
    binds = _bind_targets(proxy)
    assert binds["/etc/caddy/Caddyfile"] == REPO_ROOT / "Caddyfile"
    assert binds["/etc/caddy/identity-profiles"] == REPO_ROOT / "deploy" / "caddy"
    caddyfile = (REPO_ROOT / "Caddyfile").read_text()
    assert (
        "import /etc/caddy/identity-profiles/identity-profile-{$IDENTITY_PROFILE}.caddyfile"
        in caddyfile
    )
    for profile in ("fresh", "existing"):
        assert (REPO_ROOT / "deploy" / "caddy" / f"identity-profile-{profile}.caddyfile").is_file()
    ca_mount = next(m for m in proxy["volumes"] if m["source"] == "identity-ca")
    assert ca_mount.get("read_only") is True


def test_the_bootstrap_token_expiry_comes_from_the_deployment(prod_config: dict) -> None:
    """ADR-0045, "The bootstrap PAT": the IAM_OWNER token's expiry is the
    deployment's own value, never a far-future literal in the file."""
    environment = prod_config["services"]["zitadel"]["environment"]
    assert (
        environment["ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE"]
        == _ENV["ZITADEL_BOOTSTRAP_PAT_EXPIRATION"]
    )
    source = (REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert "2100-" not in source
    assert "${ZITADEL_BOOTSTRAP_PAT_EXPIRATION:?" in source


def test_rendering_without_a_bootstrap_token_expiry_fails(
    prod_config: dict, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """`prod_config` only to share its skip when Docker is unavailable."""
    env = {k: v for k, v in _ENV.items() if k != "ZITADEL_BOOTSTRAP_PAT_EXPIRATION"}
    with pytest.raises(pytest.fail.Exception, match="ZITADEL_BOOTSTRAP_PAT_EXPIRATION"):
        _render(env, tmp_path_factory.mktemp("no-pat-expiry"))


# --- ZITADEL version pins and the Login V2 session-cookie secret -------------


def _zitadel_images(path: Path) -> dict[str, str]:
    """`image:` references to ZITADEL's own images, by repository."""
    import re

    text = path.read_text(encoding="utf-8")
    found = re.findall(r"^\s*image:\s*ghcr\.io/zitadel/([a-z-]+):(\S+)\s*$", text, re.M)
    images: dict[str, str] = {}
    for repository, tag in found:
        assert images.setdefault(repository, tag) == tag, (path.name, repository)
    return images


def test_every_zitadel_image_is_pinned_to_one_release() -> None:
    """Local ZITADEL, production ZITADEL and production Login V2 move
    together, and the backup drill restores the same release's schema."""
    assert _zitadel_images(REPO_ROOT / "docker-compose.yml") == {"zitadel": ZITADEL_VERSION}
    assert _zitadel_images(REPO_ROOT / "docker-compose.prod.yml") == {
        "zitadel": ZITADEL_VERSION,
        "zitadel-login": ZITADEL_VERSION,
    }
    drill = (
        REPO_ROOT / "tests" / "infra" / "db" / "test_zitadel_backup_restore_drill_integration.py"
    ).read_text(encoding="utf-8")
    assert f'ZITADEL_IMAGE = "ghcr.io/zitadel/zitadel:{ZITADEL_VERSION}"' in drill


@requires_docker
def test_login_v2_receives_the_session_cookie_secret(prod_config: dict, fresh_config: dict) -> None:
    """GHSA-jh92-5mrj-p2w2: Login V2 signs its session cookie with this
    secret. Both profiles run Login V2, so both pass it; ZITADEL itself
    does not read it."""
    for config in (prod_config, fresh_config):
        svcs = config["services"]
        login = _env(svcs["zitadel-login"])
        assert login["ZITADEL_SESSION_COOKIE_SECRET"] == _ENV["ZITADEL_SESSION_COOKIE_SECRET"]
        assert "ZITADEL_SESSION_COOKIE_SECRET" not in _env(svcs["zitadel"])
    source = (REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert "ZITADEL_SESSION_COOKIE_SECRET: ${ZITADEL_SESSION_COOKIE_SECRET:?" in source


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_rendering_without_a_session_cookie_secret_fails(
    prod_config: dict, tmp_path_factory: pytest.TempPathFactory, value: str | None
) -> None:
    """`prod_config` only to share its skip when Docker is unavailable. Without
    the secret Login V2 would fall back to a key derived from its private key;
    the deployment is refused instead."""
    env = {k: v for k, v in _ENV.items() if k != "ZITADEL_SESSION_COOKIE_SECRET"}
    if value is not None:
        env["ZITADEL_SESSION_COOKIE_SECRET"] = value
    with pytest.raises(pytest.fail.Exception, match="ZITADEL_SESSION_COOKIE_SECRET"):
        _render(env, tmp_path_factory.mktemp("no-cookie-secret"))


def test_the_session_cookie_secret_is_documented_never_given_a_value() -> None:
    example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "\nZITADEL_SESSION_COOKIE_SECRET=\n" in example
    assert "openssl rand -base64 32" in example
    runbook = (REPO_ROOT / "docs" / "RUNBOOKS.md").read_text(encoding="utf-8")
    section = runbook.split("### 11. Login V2 session-cookie secret", 1)[1].split("\n## ", 1)[0]
    for required in ("openssl rand -base64 32", "32 characters", "comma-separated", "replica"):
        assert required in section, required


def test_local_development_needs_no_session_cookie_secret() -> None:
    """docker-compose.yml runs no Login V2 container (legacy login only), so
    a developer's stack starts without the production secret."""
    local = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "ZITADEL_SESSION_COOKIE_SECRET" not in local
    assert "zitadel-login:" not in local
    assert 'ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED: "false"' in local
