"""P1.3 -- the real PostgreSQL backup/restore disaster-recovery drill.

Creates its own throwaway, self-contained PostgreSQL container (a random
free host port, a random container name) -- it never touches the
developer's own `saas-os-db-1` (proven explicitly, at the end of the
drill, by confirming that container's own status is unaffected). Marked
`integration`; skips cleanly (not a failure) if Docker itself is not
available, exactly like every other Docker-dependent fixture in this
repository.

The drill (docs/IMPLEMENTATION-ROADMAP.md P1.3's own 13-step list):
throwaway DB -> migrate -> seed deterministic tenant data -> verify
pre-backup invariants -> backup -> verify checksum -> simulate total loss
(drop the database) -> restore -> verify structural/security invariants
-> re-run tenant isolation against the restored database -> verify the
application role/security properties -> verify migration state -> clean
up.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_user
from infra.db.backup import (
    BackupError,
    ChecksumMismatchError,
    InvalidIdentifierError,
    RestoreError,
    create_backup,
    drop_database_for_drill,
    restore_backup,
    verify_backup_checksum,
    verify_restored_database,
)
from infra.db.backup.config import BackupPipelineConfig
from infra.db.backup.destination import LocalBackupDestination
from infra.db.backup.orchestrator import run_production_backup, run_production_restore
from infra.db.config import DatabaseConfig, get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.role_guard import validate_application_role
from infra.db.session import (
    build_session_factory,
    get_session_factory,
    session_scope,
    tenant_session_scope,
)
from sqlalchemy import text

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
INIT_SCRIPT = REPO_ROOT / "infra" / "db" / "init" / "01-create-app-role.sh"
REAL_DEV_CONTAINER = "saas-os-db-1"


def _docker_available() -> bool:
    try:
        probe = subprocess.run(["docker", "version"], capture_output=True, timeout=10, check=False)
        return probe.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _docker_container_status(name: str) -> str | None:
    """Returns the container's `.State.Status` (e.g. "running"), or
    `None` if no such container exists. Used only to prove the drill
    never touched the developer's real `saas-os-db-1`."""
    probe = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Status}}", name],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if probe.returncode != 0:
        return None
    return probe.stdout.strip()


def _start_disposable_postgres_container(*, name_prefix: str) -> tuple[str, int]:
    """Starts one brand-new, throwaway PostgreSQL container and waits for
    it to become ready. Factored out of `drill_container` (P1.3) so the
    P2.4 extended pipeline drill below can start a second, genuinely
    clean disposable environment for its second pass -- not merely a
    second restore target inside the one long-lived container the
    original P1.3 fixture reuses, module-scoped, for speed. Skips the
    calling test (never fails it) if Docker or the init script is
    unavailable, or the container never becomes ready -- identical
    behavior to the original inline fixture body."""
    if not _docker_available():
        pytest.skip("Docker is not available -- this disaster-recovery drill needs it.")
    if not INIT_SCRIPT.is_file():
        pytest.skip(f"{INIT_SCRIPT} not found.")

    name = f"{name_prefix}-{uuid.uuid4().hex[:10]}"
    run_cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "-e",
        "POSTGRES_USER=saas_os",
        "-e",
        "POSTGRES_PASSWORD=drill-changeme",
        "-e",
        "POSTGRES_DB=saas_os",
        "-e",
        "APP_DB_USER=saas_os_app",
        "-e",
        "APP_DB_PASSWORD=drill-app-changeme",
        "-p",
        "127.0.0.1::5432",
        "-v",
        f"{INIT_SCRIPT}:/docker-entrypoint-initdb.d/01-create-app-role.sh:ro",
        "postgres:16-alpine",
    ]
    started = subprocess.run(run_cmd, capture_output=True, text=True, timeout=60, check=False)
    if started.returncode != 0:
        pytest.skip(f"Could not start a throwaway PostgreSQL container: {started.stderr.strip()}")

    for _ in range(60):
        probe = subprocess.run(
            ["docker", "exec", name, "pg_isready", "-U", "saas_os", "-d", "saas_os"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if probe.returncode == 0:
            break
        time.sleep(1)
    else:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30, check=False)
        pytest.skip("Throwaway PostgreSQL container did not become ready in time.")

    port_probe = subprocess.run(
        ["docker", "port", name, "5432/tcp"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    host_port = int(port_probe.stdout.strip().rsplit(":", 1)[-1])
    return name, host_port


def _stop_disposable_postgres_container(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30, check=False)


@pytest.fixture(scope="module")
def drill_container() -> Iterator[tuple[str, int]]:
    name, host_port = _start_disposable_postgres_container(name_prefix="p13-drill")
    try:
        yield name, host_port
    finally:
        _stop_disposable_postgres_container(name)


@pytest.fixture(scope="module")
def drill_configs(drill_container: tuple[str, int]) -> tuple[DatabaseConfig, DatabaseConfig]:
    _name, port = drill_container
    admin_config = DatabaseConfig(
        url=f"postgresql+psycopg://saas_os:drill-changeme@127.0.0.1:{port}/saas_os"
    )
    app_config = DatabaseConfig(
        url=f"postgresql+psycopg://saas_os_app:drill-app-changeme@127.0.0.1:{port}/saas_os"
    )
    return admin_config, app_config


@contextmanager
def _env_pointed_at(admin_config: DatabaseConfig, app_config: DatabaseConfig) -> Iterator[None]:
    """Temporarily repoints `infra.db`'s process-wide, cached
    configuration/engine at the drill database, so the *existing*
    application code paths (`core.tenancy.create_tenant`,
    `infra.db.session_scope`/`tenant_session_scope`, etc.) transparently
    operate against it -- exactly mirroring how every other integration
    test in this repository uses `monkeypatch.setenv` +
    `get_database_config.cache_clear()`, just without `monkeypatch`
    (module-scoped, not function-scoped) so it can wrap this module's
    larger, multi-step drill.
    """
    keys = ("DATABASE_URL", "MIGRATIONS_DATABASE_URL", "ENVIRONMENT")
    original = {k: os.environ.get(k) for k in keys}
    os.environ["DATABASE_URL"] = app_config.url
    os.environ["MIGRATIONS_DATABASE_URL"] = admin_config.url
    os.environ["ENVIRONMENT"] = "production"
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    try:
        yield
    finally:
        for k, v in original.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        get_database_config.cache_clear()
        get_migrations_database_config.cache_clear()
        get_engine.cache_clear()
        get_session_factory.cache_clear()


def _run_migrations(admin_config: DatabaseConfig) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "infra" / "db" / "migrations"))
    with _env_pointed_at(admin_config, admin_config):
        command.upgrade(cfg, "head")


def _engine_for(config: DatabaseConfig):
    return build_engine(config, connect_args={"connect_timeout": 5})


@pytest.fixture(scope="module")
def migrated_drill_db(
    drill_configs: tuple[DatabaseConfig, DatabaseConfig],
) -> tuple[DatabaseConfig, DatabaseConfig]:
    admin_config, app_config = drill_configs
    _run_migrations(admin_config)
    return admin_config, app_config


@pytest.fixture
def backup_dir(tmp_path: Path) -> Path:
    return tmp_path / "backups"


# --- The full end-to-end drill ----------------------------------------


def test_full_disaster_recovery_drill(
    drill_container: tuple[str, int],
    migrated_drill_db: tuple[DatabaseConfig, DatabaseConfig],
    backup_dir: Path,
) -> None:
    container, _port = drill_container
    admin_config, app_config = migrated_drill_db
    real_dev_status_before = _docker_container_status(REAL_DEV_CONTAINER)

    # --- 1-3: seed deterministic tenant data through the real application
    # code path (core.tenancy/core.identity/core.audit_log), pointed at
    # the throwaway drill database. -------------------------------------
    with _env_pointed_at(admin_config, app_config):
        tenant_a = create_tenant(f"drill-tenant-a-{uuid.uuid4().hex[:6]}")
        tenant_b = create_tenant(f"drill-tenant-b-{uuid.uuid4().hex[:6]}")
        user_a = create_user()
        user_b = create_user()
        add_tenant_membership(tenant_a.id, user_a.id)
        add_tenant_membership(tenant_b.id, user_b.id)

        record_audit_event(
            tenant_id=tenant_a.id,
            actor_type=ActorType.USER,
            actor_user_id=user_a.id,
            action="drill.seed",
            resource_type="drill_fixture",
            resource_id="a-1",
            outcome=AuditOutcome.SUCCESS,
        )
        record_audit_event(
            tenant_id=tenant_b.id,
            actor_type=ActorType.USER,
            actor_user_id=user_b.id,
            action="drill.seed",
            resource_type="drill_fixture",
            resource_id="b-1",
            outcome=AuditOutcome.SUCCESS,
        )

        # --- 4: pre-backup invariants ------------------------------------
        # `alembic_version` is owned by the privileged migration role with
        # no SELECT grant to the app role, exactly like a real migration's
        # own bookkeeping table -- verification here uses the admin engine,
        # matching the post-restore verification below.
        pre_backup_admin_engine = _engine_for(admin_config)
        pre_backup_verification = verify_restored_database(pre_backup_admin_engine)
        pre_backup_admin_engine.dispose()
        assert pre_backup_verification.rls_protected_table_count >= 14
        assert pre_backup_verification.every_rls_table_has_force_rls is True
        assert pre_backup_verification.every_rls_table_has_a_policy is True
        pre_backup_revision = pre_backup_verification.alembic_version
        assert pre_backup_revision

        with tenant_session_scope(tenant_a.id) as session:
            rows = session.execute(text("SELECT action FROM core.audit_log"))
            pre_a_actions = {row.action for row in rows}
        assert pre_a_actions == {"drill.seed"}

    # --- 5: create the backup -------------------------------------------
    metadata = create_backup(
        container=container, admin_config=admin_config, output_dir=backup_dir, label="drill"
    )
    assert metadata.artifact_path.is_file()
    assert metadata.size_bytes > 0

    # --- 6: verify the checksum independently ----------------------------
    verified = verify_backup_checksum(metadata.metadata_path)
    assert verified.sha256 == metadata.sha256

    # --- 7: simulate total database loss ---------------------------------
    drop_database_for_drill(container=container, admin_config=admin_config, database="saas_os")

    with pytest.raises(Exception):  # noqa: B017, PT011 -- the database genuinely no longer exists
        with _engine_for(admin_config).connect() as conn:
            conn.execute(text("SELECT 1"))

    # --- 8: restore -------------------------------------------------------
    result = restore_backup(
        container=container,
        admin_config=admin_config,
        metadata_path=metadata.metadata_path,
        target_database="saas_os",
    )
    assert result.target_database == "saas_os"

    # --- 9: structural + security verification of the restored database --
    restored_admin_engine = _engine_for(admin_config)
    post_restore = verify_restored_database(restored_admin_engine)
    assert post_restore.schemas_present == {"core", "control_plane", "self_learning"}
    pre_count = pre_backup_verification.rls_protected_table_count
    assert post_restore.rls_protected_table_count == pre_count
    assert post_restore.every_rls_table_has_force_rls is True
    assert post_restore.every_rls_table_has_a_policy is True

    # --- 12: migration state is exactly what it was pre-backup ------------
    assert post_restore.alembic_version == pre_backup_revision

    # --- 11: application role/security properties on the restored DB ------
    restored_app_engine = _engine_for(app_config)
    role_result = validate_application_role(restored_app_engine)
    assert role_result.role_name == "saas_os_app"

    # --- 10: tenant isolation re-run against the restored database --------
    restored_app_session_factory = build_session_factory(restored_app_engine)
    with tenant_session_scope(tenant_a.id, session_factory=restored_app_session_factory) as session:
        a_rows = list(session.execute(text("SELECT resource_id FROM core.audit_log")))
    assert [r[0] for r in a_rows] == ["a-1"]

    with tenant_session_scope(tenant_b.id, session_factory=restored_app_session_factory) as session:
        b_rows = list(session.execute(text("SELECT resource_id FROM core.audit_log")))
    assert [r[0] for r in b_rows] == ["b-1"]

    # Tenant A cannot see Tenant B's restored data, and vice versa.
    with tenant_session_scope(tenant_a.id, session_factory=restored_app_session_factory) as session:
        assert "b-1" not in [
            r[0] for r in session.execute(text("SELECT resource_id FROM core.audit_log"))
        ]

    # Missing tenant context -> zero rows, not every tenant's data.
    with session_scope(session_factory=restored_app_session_factory) as session:
        assert list(session.execute(text("SELECT resource_id FROM core.audit_log"))) == []

    with _env_pointed_at(admin_config, app_config):
        restored_a_entries = list_audit_entries(tenant_a.id)
    assert {e.action for e in restored_a_entries} == {"drill.seed"}

    restored_admin_engine.dispose()
    restored_app_engine.dispose()

    # --- 13 (partial): the drill container is cleaned up by the
    # drill_container fixture's own teardown; confirmed here that the
    # developer's real container was never touched. ------------------------
    real_dev_status_after = _docker_container_status(REAL_DEV_CONTAINER)
    assert real_dev_status_after == real_dev_status_before, (
        "the disaster-recovery drill must never affect the developer's own "
        f"{REAL_DEV_CONTAINER} container"
    )


# --- Failure-mode tests (real container, no mocks) ------------------------


def test_restoring_a_checksum_mismatched_backup_is_rejected(
    drill_container: tuple[str, int],
    migrated_drill_db: tuple[DatabaseConfig, DatabaseConfig],
    backup_dir: Path,
) -> None:
    container, _port = drill_container
    admin_config, _app_config = migrated_drill_db

    metadata = create_backup(
        container=container, admin_config=admin_config, output_dir=backup_dir, label="tamper"
    )
    original = metadata.artifact_path.read_bytes()
    metadata.artifact_path.write_bytes(original + b"\x00tampered")

    with pytest.raises(ChecksumMismatchError):
        restore_backup(
            container=container,
            admin_config=admin_config,
            metadata_path=metadata.metadata_path,
            target_database=f"p13_should_never_exist_{uuid.uuid4().hex[:8]}",
        )

    # Restoring into the corrupted-artifact's target must never actually
    # create the target database -- checksum verification runs before
    # any pg_restore/CREATE DATABASE call.
    engine = _engine_for(admin_config)
    with engine.connect() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname LIKE 'p13_should_never_exist_%'")
        ).first()
    engine.dispose()
    assert exists is None


def test_restoring_a_missing_backup_is_rejected(
    drill_container: tuple[str, int],
    migrated_drill_db: tuple[DatabaseConfig, DatabaseConfig],
    backup_dir: Path,
) -> None:
    container, _port = drill_container
    admin_config, _app_config = migrated_drill_db

    with pytest.raises(BackupError):
        restore_backup(
            container=container,
            admin_config=admin_config,
            metadata_path=backup_dir / "does-not-exist.pgdump.json",
            target_database=f"p13_missing_{uuid.uuid4().hex[:8]}",
        )


def test_restoring_into_an_invalid_target_identifier_is_rejected(
    drill_container: tuple[str, int],
    migrated_drill_db: tuple[DatabaseConfig, DatabaseConfig],
    backup_dir: Path,
) -> None:
    container, _port = drill_container
    admin_config, _app_config = migrated_drill_db

    metadata = create_backup(
        container=container, admin_config=admin_config, output_dir=backup_dir, label="badtarget"
    )
    with pytest.raises(InvalidIdentifierError):
        restore_backup(
            container=container,
            admin_config=admin_config,
            metadata_path=metadata.metadata_path,
            target_database="not a valid identifier; DROP TABLE core.tenants;--",
        )


def test_restoring_over_an_existing_database_is_rejected_not_the_default(
    drill_container: tuple[str, int],
    migrated_drill_db: tuple[DatabaseConfig, DatabaseConfig],
    backup_dir: Path,
) -> None:
    """restore_backup() never overwrites an existing database (module
    docstring: no destructive-replace default) -- CREATE DATABASE fails
    loudly when the target name is already taken."""
    container, _port = drill_container
    admin_config, _app_config = migrated_drill_db

    metadata = create_backup(
        container=container, admin_config=admin_config, output_dir=backup_dir, label="collide"
    )
    target = f"p13_collide_{uuid.uuid4().hex[:8]}"
    result = restore_backup(
        container=container,
        admin_config=admin_config,
        metadata_path=metadata.metadata_path,
        target_database=target,
    )
    assert result.target_database == target

    try:
        with pytest.raises(RestoreError):
            restore_backup(
                container=container,
                admin_config=admin_config,
                metadata_path=metadata.metadata_path,
                target_database=target,
            )
    finally:
        drop_database_for_drill(container=container, admin_config=admin_config, database=target)


def test_a_genuinely_corrupt_archive_is_rejected_by_pg_restore(
    drill_container: tuple[str, int],
    migrated_drill_db: tuple[DatabaseConfig, DatabaseConfig],
    backup_dir: Path,
) -> None:
    """Corrupt *after* recomputing a matching checksum for the corrupted
    bytes (so checksum verification alone doesn't catch it) -- proves
    `pg_restore` itself, not just the checksum gate, rejects a genuinely
    unreadable archive rather than reporting a false-positive success."""
    import hashlib
    import json

    container, _port = drill_container
    admin_config, _app_config = migrated_drill_db

    metadata = create_backup(
        container=container, admin_config=admin_config, output_dir=backup_dir, label="corrupt"
    )
    corrupt_bytes = b"not a real pgdump archive at all"
    metadata.artifact_path.write_bytes(corrupt_bytes)
    new_sha256 = hashlib.sha256(corrupt_bytes).hexdigest()
    raw = json.loads(metadata.metadata_path.read_text())
    raw["sha256"] = new_sha256
    raw["size_bytes"] = len(corrupt_bytes)
    metadata.metadata_path.write_text(json.dumps(raw))

    target = f"p13_corrupt_{uuid.uuid4().hex[:8]}"
    with pytest.raises(RestoreError, match="pg_restore failed"):
        restore_backup(
            container=container,
            admin_config=admin_config,
            metadata_path=metadata.metadata_path,
            target_database=target,
        )
    # The target database was created (CREATE DATABASE succeeded) but
    # pg_restore never populated it -- left present but empty, never
    # falsely reported as a healthy restore.
    drop_database_for_drill(container=container, admin_config=admin_config, database=target)


# --- P2.4 -- extended production pipeline drill: encryption, off-site
# upload, retention, and a fail-closed decrypt-then-restore, run twice
# against two independent, brand-new disposable environments. -------------

_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None
requires_age = pytest.mark.skipif(not _AGE_AVAILABLE, reason="age/age-keygen not installed on PATH")


def _generate_age_keypair() -> tuple[str, str]:
    result = subprocess.run(["age-keygen"], capture_output=True, text=True, timeout=30, check=True)
    identity = next(
        line.strip() for line in result.stdout.splitlines() if line.startswith("AGE-SECRET-KEY-1")
    )
    recipient = next(
        line.split(":", 1)[1].strip()
        for line in result.stderr.splitlines()
        if line.startswith("Public key:")
    )
    return recipient, identity


def _run_one_extended_pipeline_pass(
    *, name_prefix: str, tmp_root: Path, recipient: str, identity: str
) -> dict[str, object]:
    """One full pass of the P2.4 production pipeline against a brand-new,
    independently migrated, disposable PostgreSQL container: seed two
    tenants -> `run_production_backup()` (create_backup + checksum + age
    encryption + a real, non-fake `LocalBackupDestination` upload +
    keep-last-1 retention) -> simulate total loss of both the database
    and every local copy of the artifact -> download the off-site
    ciphertext back -> `run_production_restore()` (checksum + decrypt +
    pg_restore) -> verify schema/RLS -> re-run tenant isolation against
    the restored database. Returns the observations the caller compares
    across both passes to demonstrate deterministic repeatability, plus
    the measured restore duration."""
    container, port = _start_disposable_postgres_container(name_prefix=name_prefix)
    try:
        admin_config = DatabaseConfig(
            url=f"postgresql+psycopg://saas_os:drill-changeme@127.0.0.1:{port}/saas_os"
        )
        app_config = DatabaseConfig(
            url=f"postgresql+psycopg://saas_os_app:drill-app-changeme@127.0.0.1:{port}/saas_os"
        )
        _run_migrations(admin_config)

        with _env_pointed_at(admin_config, app_config):
            tenant_a = create_tenant(f"p24-tenant-a-{uuid.uuid4().hex[:6]}")
            tenant_b = create_tenant(f"p24-tenant-b-{uuid.uuid4().hex[:6]}")
            user_a = create_user()
            user_b = create_user()
            add_tenant_membership(tenant_a.id, user_a.id)
            add_tenant_membership(tenant_b.id, user_b.id)
            record_audit_event(
                tenant_id=tenant_a.id,
                actor_type=ActorType.USER,
                actor_user_id=user_a.id,
                action="p24.seed",
                resource_type="drill_fixture",
                resource_id="a-1",
                outcome=AuditOutcome.SUCCESS,
            )
            record_audit_event(
                tenant_id=tenant_b.id,
                actor_type=ActorType.USER,
                actor_user_id=user_b.id,
                action="p24.seed",
                resource_type="drill_fixture",
                resource_id="b-1",
                outcome=AuditOutcome.SUCCESS,
            )

        staging_dir = tmp_root / f"staging-{name_prefix}"
        off_site_root = tmp_root / f"off-site-{name_prefix}"
        destination = LocalBackupDestination(off_site_root)
        config = BackupPipelineConfig(staging_dir=staging_dir, retention_count=1)

        backup_result = run_production_backup(
            container=container,
            admin_config=admin_config,
            config=config,
            recipient=recipient,
            destination=destination,
        )
        assert backup_result.encrypted_path is not None
        assert backup_result.encrypted_path.is_file()
        assert backup_result.uploaded_key is not None

        # Simulate total loss of the primary database *and* every local
        # copy of the artifact -- the only surviving copy is the
        # off-site, encrypted object, exactly the scenario DR exists for.
        drop_database_for_drill(container=container, admin_config=admin_config, database="saas_os")
        backup_result.metadata.artifact_path.unlink()
        backup_result.encrypted_path.unlink()

        downloaded_encrypted = staging_dir / backup_result.encrypted_path.name
        destination.download(backup_result.uploaded_key, downloaded_encrypted)

        started = time.monotonic()
        restore_result = run_production_restore(
            container=container,
            admin_config=admin_config,
            metadata_path=backup_result.metadata.metadata_path,
            target_database="saas_os",
            identity=identity,
            encrypted_path=downloaded_encrypted,
        )
        restore_duration = time.monotonic() - started
        assert restore_result.result.target_database == "saas_os"

        restored_admin_engine = _engine_for(admin_config)
        verification = verify_restored_database(restored_admin_engine)
        restored_admin_engine.dispose()

        restored_app_engine = _engine_for(app_config)
        restored_session_factory = build_session_factory(restored_app_engine)
        with tenant_session_scope(tenant_a.id, session_factory=restored_session_factory) as session:
            a_rows = [r[0] for r in session.execute(text("SELECT resource_id FROM core.audit_log"))]
        with tenant_session_scope(tenant_b.id, session_factory=restored_session_factory) as session:
            b_rows = [r[0] for r in session.execute(text("SELECT resource_id FROM core.audit_log"))]
        restored_app_engine.dispose()

        return {
            "schemas_present": verification.schemas_present,
            "rls_protected_table_count": verification.rls_protected_table_count,
            "every_rls_table_has_force_rls": verification.every_rls_table_has_force_rls,
            "every_rls_table_has_a_policy": verification.every_rls_table_has_a_policy,
            "tenant_a_rows": a_rows,
            "tenant_b_rows": b_rows,
            "restore_duration_seconds": restore_duration,
        }
    finally:
        _stop_disposable_postgres_container(container)


@requires_age
def test_extended_production_pipeline_runs_twice_from_clean_disposable_environments(
    tmp_path: Path,
) -> None:
    """Extends the P1.3 drill above (does not merely rerun it) to cover
    the full P2.4 production pipeline this checkpoint requires: `age`
    encryption, off-site upload against a real (non-fake, real-disk)
    `LocalBackupDestination`, keep-last-N retention, and a fail-closed
    restore that decrypts a *downloaded* artifact (not one still sitting
    conveniently on local disk). Runs the entire pipeline twice, each
    pass against its own brand-new, independently migrated, disposable
    PostgreSQL container -- proving the pipeline carries no hidden state
    between runs (no stale lock, no reused ciphertext, no leftover target
    database) and is deterministically repeatable, per this checkpoint's
    own "run the drill at least twice, the second run starting from a
    clean disposable environment" requirement."""
    recipient, identity = _generate_age_keypair()

    first = _run_one_extended_pipeline_pass(
        name_prefix="p24-pass1", tmp_root=tmp_path, recipient=recipient, identity=identity
    )
    second = _run_one_extended_pipeline_pass(
        name_prefix="p24-pass2", tmp_root=tmp_path, recipient=recipient, identity=identity
    )

    for pass_name, result in (("first", first), ("second", second)):
        assert result["schemas_present"] == {"core", "control_plane", "self_learning"}, pass_name
        assert result["every_rls_table_has_force_rls"] is True, pass_name
        assert result["every_rls_table_has_a_policy"] is True, pass_name
        assert result["tenant_a_rows"] == ["a-1"], pass_name
        assert result["tenant_b_rows"] == ["b-1"], pass_name

    assert first["rls_protected_table_count"] == second["rls_protected_table_count"], (
        "both passes migrate the same codebase into a clean database and must produce "
        "an identical RLS-protected table count -- deterministic repeatability"
    )

    print(
        f"P2.4 extended pipeline drill: pass 1 restore took "
        f"{first['restore_duration_seconds']:.2f}s, "
        f"pass 2 restore took {second['restore_duration_seconds']:.2f}s"
    )
