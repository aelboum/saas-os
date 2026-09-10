"""End-to-end validation of the ADR-0018 reference consumer
(`examples/reference-consumer/`), against a real, disposable PostgreSQL
instance and a real, non-editable `saas-os` wheel.

Proves, in one real run, everything ADR-0018 requires the fixture prove:

1. `saas-os` is consumed as an installed package -- a real wheel is
   built, installed into an isolated venv, and `reference_consumer/` is
   copied to a scratch directory *outside* this repository before it is
   ever imported, so nothing here can resolve `core`/`infra`/`api`/
   `control_plane` via this repository's own source tree even by
   accident (module docstring of `reference_consumer/__init__.py`).
2. SaaS OS's own migrations and the reference consumer's own, separate
   migrations both apply, in order, against one shared database
   (ADR-0016) -- `alembic_version_saas_os` and `alembic_version` both
   exist, independently, along with `core`/`control_plane`/`self_learning`
   (SaaS OS) and `reference_consumer` (the project's own) schemas.
3. The reference consumer registers and invokes its own AI Control Plane
   tool against its own `core.rbac`-registered permission.
4. The reference consumer's own application entrypoint
   (`reference_consumer.app.create_app()`, built on
   `api.platform.build_platform_app()`) serves its own route.

Marked `integration` -- needs a real, reachable PostgreSQL instance (see
`tests/infra/db/test_migration_gate_integration.py`'s own docstring for
how to start one locally); also builds a real wheel and a real venv, so
this is one of the slower integration tests. Run via
`scripts/check-migrations.sh` (extended for this fixture, per
docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md §13) or
`pytest -m integration tests/test_reference_consumer_integration.py`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import venv
from pathlib import Path

import pytest
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_CONSUMER_SRC = REPO_ROOT / "examples" / "reference-consumer" / "reference_consumer"

_DRIVER_SCRIPT = textwrap.dedent(
    """
    import asyncio
    import os
    import uuid
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text as sqltext

    from control_plane.orchestration.service import invoke_tool
    from control_plane.orchestration.tools import ToolRegistry
    from core.identity.service import add_tenant_membership, create_user, get_membership
    from core.rbac.service import assign_role, create_role, grant_permission, register_permission
    from core.tenancy import create_tenant
    from infra.db import tenant_session_scope
    from infra.db.config import get_migrations_database_config
    from infra.db.migration_runner import run_core_migrations

    # 1. SaaS OS's own migrations (ADR-0016, step 1).
    run_core_migrations()

    # 2. The reference consumer's own, separate migrations (ADR-0016, step 2).
    ref_migrations_dir = Path(__file__).resolve().parent / "reference_consumer" / "migrations"
    project_cfg = Config()
    project_cfg.set_main_option("script_location", str(ref_migrations_dir))
    command.upgrade(project_cfg, "head")

    # 3. Both version tables + all four schemas exist independently.
    engine = create_engine(get_migrations_database_config().url)
    with engine.connect() as conn:
        saas_os_version = conn.execute(
            sqltext("SELECT version_num FROM alembic_version_saas_os")
        ).scalar_one()
        project_version = conn.execute(
            sqltext("SELECT version_num FROM alembic_version")
        ).scalar_one()
        schema_rows = conn.execute(
            sqltext("SELECT nspname FROM pg_namespace WHERE nspname = ANY(:names)"),
            {"names": ["core", "control_plane", "self_learning", "reference_consumer"]},
        ).all()
    engine.dispose()
    assert saas_os_version, "SaaS OS's own alembic_version_saas_os is empty"
    assert project_version, "the reference consumer's own alembic_version is empty"
    schemas_present = {row[0] for row in schema_rows}
    assert schemas_present == {"core", "control_plane", "self_learning", "reference_consumer"}, (
        schemas_present
    )

    # 4. Its own AI Control Plane tool, against its own RBAC permission.
    from reference_consumer.tools import ACTION, RESOURCE, build_check_widget_status_tool

    tenant = create_tenant(f"ref-consumer-{uuid.uuid4().hex[:8]}")
    agent = create_user()
    add_tenant_membership(tenant.id, agent.id)

    role = create_role(tenant.id, f"widget-role-{uuid.uuid4().hex[:8]}")
    permission = register_permission(RESOURCE, ACTION)
    grant_permission(tenant.id, role.id, permission.id)
    membership = get_membership(tenant.id, agent.id)
    assert membership is not None
    assign_role(tenant.id, membership.id, role.id)

    widget_id = uuid.uuid4()
    with tenant_session_scope(tenant.id) as session:
        session.execute(
            sqltext(
                "INSERT INTO reference_consumer.widgets (id, tenant_id, name, status) "
                "VALUES (:id, :t, :n, :s)"
            ),
            {"id": str(widget_id), "t": str(tenant.id), "n": "widget-1", "s": "active"},
        )
        session.commit()

    registry = ToolRegistry()
    registry.register(build_check_widget_status_tool())
    result = asyncio.run(
        invoke_tool(
            "reference_consumer.check_widget_status",
            agent_user_id=agent.id,
            tenant_id=tenant.id,
            payload={"widget_id": str(widget_id)},
            registry=registry,
        )
    )
    assert result.output["status"] == "active", result.output

    # 5. Its own application entrypoint, its own route.
    from reference_consumer.app import create_app

    app = create_app()
    with TestClient(app) as client:
        response = client.get(f"/widgets/{tenant.id}/{widget_id}")
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "active"

    print("REFERENCE_CONSUMER_OK")
    """
)


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL: {exc}")
    finally:
        probe_engine.dispose()

    try:
        get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")


def test_reference_consumer_end_to_end_against_installed_package(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    # --- build a real wheel, install it into an isolated venv ----------
    wheel_dir = tmp_path_factory.mktemp("ref-consumer-wheel")
    build_result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(REPO_ROOT), "-w", str(wheel_dir), "--no-deps"],
        capture_output=True,
        text=True,
    )
    assert build_result.returncode == 0, build_result.stdout + build_result.stderr
    (wheel,) = wheel_dir.glob("saas_os-*.whl")

    venv_dir = tmp_path_factory.mktemp("ref-consumer-venv")
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
    venv_python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

    install_result = subprocess.run(
        [str(venv_python), "-m", "pip", "install", str(wheel)],
        capture_output=True,
        text=True,
    )
    assert install_result.returncode == 0, install_result.stdout + install_result.stderr

    # --- copy reference_consumer/ to a scratch dir OUTSIDE this repo ---
    scratch_dir = tmp_path_factory.mktemp("ref-consumer-scratch")
    shutil.copytree(REFERENCE_CONSUMER_SRC, scratch_dir / "reference_consumer")
    driver_path = scratch_dir / "driver.py"
    driver_path.write_text(_DRIVER_SCRIPT, encoding="utf-8")

    # --- run the driver from the scratch dir, through the isolated venv
    run_result = subprocess.run(
        [str(venv_python), str(driver_path)],
        cwd=str(scratch_dir),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert run_result.returncode == 0, run_result.stdout + run_result.stderr
    assert "REFERENCE_CONSUMER_OK" in run_result.stdout
