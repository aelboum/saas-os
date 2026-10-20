"""ADR-0023 Phase 4 -- automated restore drill for the ZITADEL PostgreSQL
backup path Phase 3 added (`saas_os/infra/db/backup/orchestrator.py::
resolve_admin_database_config`, exercised through the same
`--admin-database-url-var`/`ZITADEL_BACKUP_DATABASE_URL` mechanism
`deploy/saas-os-zitadel-backup.service` uses in production).

Proves, against a real disposable PostgreSQL container populated with
ZITADEL's own *real* schema and data (never a hand-fabricated fake
schema) -- via the exact pinned `ghcr.io/zitadel/zitadel:v4.19.5` image
docker-compose.yml/docker-compose.prod.yml already use, running only its
own `init` + `setup` subcommands (schema migration + FirstInstance
provisioning) and never `start`/`start-from-init`, so ZITADEL's HTTP
server/TLS/OIDC surface is never brought up:

    ZITADEL PostgreSQL backup -> checksum/integrity verification ->
    fresh-target restore -> ZITADEL-shaped schema/event/org round-trip

Reuses the exact same `saas_os.infra.db.backup` primitives (`create_backup`,
`restore_backup`, `verify_backup_checksum`, `drop_database_for_drill`) the
P1.3/P2.4 SaaS DB drill (`test_backup_restore_drill_integration.py`)
already uses -- never a second backup implementation -- and mirrors that
file's own disposable-container pattern; kept as a separate file because
ZITADEL's own Postgres role/schema shape (admin==user, no app-role split,
no `saas_os/infra/db/init/01-create-app-role.sh`) is genuinely different from the
SaaS DB's, not because the backup mechanism itself differs.

Marked `integration`; skips cleanly (never fails) if Docker itself, or
the pinned ZITADEL image's own `init`/`setup` steps, are unavailable --
identical convention to every other Docker-dependent fixture in this
repository.

**Explicit boundary (do not over-read this test):** it proves the
ZITADEL PostgreSQL backup/restore mechanism only. It does NOT prove
master-key recovery, DNS recovery, TLS recovery, Caddy recovery, full VPS
reconstruction, or browser login recovery -- those remain
docs/RUNBOOKS.md's "Self-hosted identity operations" runbook's own
concern (steps 5-9), and docs/BACKUP-RESTORE.md's own ZITADEL section.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest

from saas_os.infra.db.backup import (
    create_backup,
    drop_database_for_drill,
    restore_backup,
    verify_backup_checksum,
)
from saas_os.infra.db.backup.orchestrator import resolve_admin_database_config
from saas_os.infra.db.config import DatabaseConfig
from saas_os.infra.secrets.providers import EnvironmentSecretsProvider

pytestmark = pytest.mark.integration

# Pinned exact version -- matches docker-compose.yml/docker-compose.prod.yml
# exactly (never `latest`), so this drill exercises the same schema/setup
# behavior the real deployment does.
ZITADEL_IMAGE = "ghcr.io/zitadel/zitadel:v4.19.5"

_ADMIN_URL_VAR = "ZITADEL_BACKUP_DATABASE_URL"

# Drill-only, throwaway credentials -- never a real deployment's secret,
# same convention as the SaaS DB drill's own "drill-changeme".
_DB_USER = "zitadel_drill"
_DB_PASSWORD = "zitadel-drill-changeme"  # pragma: allowlist secret
_DB_NAME = "zitadel_drill"


def _docker_available() -> bool:
    try:
        probe = subprocess.run(["docker", "version"], capture_output=True, timeout=10, check=False)
        return probe.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _run(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


@pytest.fixture(scope="module")
def zitadel_drill_network() -> Iterator[str]:
    """A throwaway, module-scoped Docker network -- lets the one-shot
    `zitadel init`/`setup` containers below reach the disposable Postgres
    container by its container name, without relying on host networking
    (portable across the platforms this repository's Docker-based tests
    already run on)."""
    if not _docker_available():
        pytest.skip("Docker is not available -- this restore drill needs it.")
    name = f"zitadel-drill-net-{uuid.uuid4().hex[:10]}"
    created = _run(["docker", "network", "create", name], timeout=30)
    if created.returncode != 0:
        pytest.skip(f"Could not create a throwaway Docker network: {created.stderr.strip()}")
    try:
        yield name
    finally:
        _run(["docker", "network", "rm", name], timeout=30)


@pytest.fixture(scope="module")
def zitadel_drill_postgres(zitadel_drill_network: str) -> Iterator[tuple[str, int]]:
    """A throwaway PostgreSQL container shaped like ZITADEL's own
    dedicated `zitadel-db` (docker-compose.prod.yml): admin==user, no
    app-role split -- that split exists for SaaS-OS's own Row-Level
    Security enforcement, irrelevant to ZITADEL's schema (same reasoning
    docker-compose.yml's own `zitadel`/`zitadel-db` comments already give).
    On `zitadel_drill_network` (so the `zitadel init`/`setup` containers
    below can reach it by name) and published to a random host port (so
    this test's own verification queries and `saas_os.infra.db.backup`'s own
    `docker exec` calls can reach it, exactly like the SaaS DB drill's own
    disposable container)."""
    name = f"zitadel-drill-pg-{uuid.uuid4().hex[:10]}"
    run_cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--network",
        zitadel_drill_network,
        "-e",
        f"POSTGRES_USER={_DB_USER}",
        "-e",
        f"POSTGRES_PASSWORD={_DB_PASSWORD}",
        "-e",
        f"POSTGRES_DB={_DB_NAME}",
        "-p",
        "127.0.0.1::5432",
        "postgres:16-alpine",
    ]
    started = _run(run_cmd, timeout=60)
    if started.returncode != 0:
        pytest.skip(f"Could not start a throwaway PostgreSQL container: {started.stderr.strip()}")

    for _ in range(60):
        probe = subprocess.run(
            ["docker", "exec", name, "pg_isready", "-U", _DB_USER, "-d", _DB_NAME],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if probe.returncode == 0:
            break
        time.sleep(1)
    else:
        _run(["docker", "rm", "-f", name], timeout=30)
        pytest.skip("Throwaway PostgreSQL container did not become ready in time.")

    port_probe = _run(["docker", "port", name, "5432/tcp"], timeout=10)
    host_port = int(port_probe.stdout.strip().rsplit(":", 1)[-1])

    # Authoritative readiness: a real host-side connection, retried for up
    # to 60 seconds -- same rationale as the SaaS DB drill's own fixture
    # (a container-side pg_isready can precede the TCP listener briefly).
    deadline = time.monotonic() + 60
    while True:
        try:
            with psycopg.connect(_dsn(host_port, _DB_NAME), connect_timeout=2) as conn:
                conn.execute("SELECT 1")
            break
        except psycopg.OperationalError as exc:
            if time.monotonic() >= deadline:
                _run(["docker", "rm", "-f", name], timeout=30)
                pytest.skip(
                    "Throwaway PostgreSQL container never accepted a host TCP connection "
                    f"on port {host_port}: {exc}"
                )
            time.sleep(0.25)

    try:
        yield name, host_port
    finally:
        _run(["docker", "rm", "-f", name], timeout=30)


def _dsn(host_port: int, database: str) -> str:
    return f"postgresql://{_DB_USER}:{_DB_PASSWORD}@127.0.0.1:{host_port}/{database}"


def _zitadel_db_env(container_name: str) -> dict[str, str]:
    return {
        "ZITADEL_DATABASE_POSTGRES_HOST": container_name,
        "ZITADEL_DATABASE_POSTGRES_PORT": "5432",
        "ZITADEL_DATABASE_POSTGRES_DATABASE": _DB_NAME,
        "ZITADEL_DATABASE_POSTGRES_USER_USERNAME": _DB_USER,
        "ZITADEL_DATABASE_POSTGRES_USER_PASSWORD": _DB_PASSWORD,
        "ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE": "disable",
        "ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME": _DB_USER,
        "ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD": _DB_PASSWORD,
        "ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE": "disable",
    }


def _docker_run_zitadel(
    network: str, env: dict[str, str], *args: str, timeout: int
) -> subprocess.CompletedProcess[str]:
    cmd = ["docker", "run", "--rm", "--network", network]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    cmd += [ZITADEL_IMAGE, *args]
    return _run(cmd, timeout=timeout)


@pytest.fixture(scope="module")
def zitadel_seeded_schema(
    zitadel_drill_network: str, zitadel_drill_postgres: tuple[str, int]
) -> str:
    """Populates the disposable Postgres with ZITADEL's own real schema
    and a real FirstInstance org via the pinned image's own `init` +
    `setup` subcommands -- schema migration and FirstInstance
    provisioning -- never `start`/`start-from-init`: ZITADEL's HTTP
    server, TLS listener, and OIDC surface are never brought up here (see
    this module's own docstring boundary). Returns the org name seeded,
    for the post-restore assertion below."""
    container_name, _host_port = zitadel_drill_postgres
    db_env = _zitadel_db_env(container_name)

    init = _docker_run_zitadel(zitadel_drill_network, db_env, "init", timeout=120)
    if init.returncode != 0:
        pytest.skip(f"ZITADEL 'init' did not complete: {init.stderr.strip()[-2000:]}")

    org_name = f"zitadel-drill-{uuid.uuid4().hex[:8]}"
    setup_env = {
        **db_env,
        "ZITADEL_EXTERNALDOMAIN": "zitadel-drill.internal",
        "ZITADEL_EXTERNALPORT": "8080",
        "ZITADEL_EXTERNALSECURE": "false",
        "ZITADEL_TLS_ENABLED": "false",
        "ZITADEL_FIRSTINSTANCE_ORG_NAME": org_name,
        "ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME": "drill-admin",
        "ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_ADDRESS": "drill@example.com",
        "ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_VERIFIED": "true",
    }
    # Drill-only, throwaway values -- split out so the required inline
    # false-positive markers below don't push these dict lines past the
    # line-length limit.
    setup_env["ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD"] = (
        "Drill-Restore-Test-1!"  # pragma: allowlist secret
    )
    setup_env["ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED"] = (
        "false"  # pragma: allowlist secret
    )
    # Exactly 32 bytes (ZITADEL refuses any other length) -- a
    # drill-only, never-persisted masterkey. This drill never restarts a
    # container against this same value, so it need not be recoverable
    # (unlike ZITADEL_MASTERKEY in production, docs/BACKUP-RESTORE.md).
    drill_masterkey = uuid.uuid4().hex
    setup = _docker_run_zitadel(
        zitadel_drill_network,
        setup_env,
        "setup",
        "--masterkey",
        drill_masterkey,
        "--tlsMode",
        "disabled",
        timeout=180,
    )
    if setup.returncode != 0:
        pytest.skip(f"ZITADEL 'setup' did not complete: {setup.stderr.strip()[-2000:]}")

    return org_name


def _event_count(host_port: int, database: str) -> int:
    with psycopg.connect(_dsn(host_port, database), connect_timeout=5) as conn:
        row = conn.execute("SELECT count(*) FROM eventstore.events2").fetchone()
        assert row is not None
        return int(row[0])


def _org_row_exists(host_port: int, database: str, *, org_name: str) -> bool:
    with psycopg.connect(_dsn(host_port, database), connect_timeout=5) as conn:
        row = conn.execute(
            "SELECT 1 FROM projections.orgs1 WHERE name = %s", (org_name,)
        ).fetchone()
        return row is not None


@pytest.fixture
def backup_dir(tmp_path: Path) -> Path:
    return tmp_path / "backups"


def test_zitadel_postgresql_backup_restores_into_a_fresh_target(
    zitadel_drill_postgres: tuple[str, int],
    zitadel_seeded_schema: str,
    backup_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ZITADEL DB backup/restore round-trip this module's own
    docstring describes. Boundary: proves the database backup/restore
    mechanism only -- not master-key recovery, DNS/TLS/Caddy, full VPS
    reconstruction, or browser login (docs/RUNBOOKS.md's own runbook
    covers those)."""
    container, host_port = zitadel_drill_postgres
    org_name = zitadel_seeded_schema

    pre_backup_event_count = _event_count(host_port, _DB_NAME)
    assert pre_backup_event_count > 0
    assert _org_row_exists(host_port, _DB_NAME, org_name=org_name)

    # --- exercise the actual Phase 3 code path: `--admin-database-url-var`
    # resolves a *variable name* through SecretsProvider -- never a raw
    # connection string passed directly -- the same mechanism
    # `deploy/saas-os-zitadel-backup.service` uses in production. ---------
    monkeypatch.setenv(_ADMIN_URL_VAR, _dsn(host_port, _DB_NAME))
    admin_config: DatabaseConfig = resolve_admin_database_config(
        EnvironmentSecretsProvider(), admin_database_url_var=_ADMIN_URL_VAR
    )

    # --- backup -------------------------------------------------------------
    metadata = create_backup(
        container=container, admin_config=admin_config, output_dir=backup_dir, label="zitadel-drill"
    )
    assert metadata.artifact_path.is_file()
    assert metadata.size_bytes > 0
    assert metadata.database == _DB_NAME

    # --- integrity verification, and no stray plaintext artifact ------------
    verified = verify_backup_checksum(metadata.metadata_path)
    assert verified.sha256 == metadata.sha256
    assert sorted(backup_dir.glob("*.pgdump")) == [metadata.artifact_path]

    # --- simulate total loss -------------------------------------------------
    drop_database_for_drill(container=container, admin_config=admin_config, database=_DB_NAME)

    # --- restore into a completely fresh target, never the original name ----
    target_database = f"zitadel_drill_restored_{uuid.uuid4().hex[:8]}"
    result = restore_backup(
        container=container,
        admin_config=admin_config,
        metadata_path=metadata.metadata_path,
        target_database=target_database,
    )
    assert result.target_database == target_database

    # --- post-restore verification: real ZITADEL schema/data round-trip ----
    with psycopg.connect(_dsn(host_port, target_database), connect_timeout=5) as conn:
        schemas = {
            row[0]
            for row in conn.execute(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name IN ('eventstore', 'projections', 'system')"
            ).fetchall()
        }
    assert schemas == {"eventstore", "projections", "system"}

    restored_event_count = _event_count(host_port, target_database)
    assert restored_event_count == pre_backup_event_count

    assert _org_row_exists(host_port, target_database, org_name=org_name), (
        "the restored ZITADEL database must contain the exact FirstInstance org "
        "seeded before backup -- an empty or unusable restore must fail this test"
    )

    drop_database_for_drill(
        container=container, admin_config=admin_config, database=target_database
    )
