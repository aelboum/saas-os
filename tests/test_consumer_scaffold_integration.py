"""End-to-end validation of the consumer scaffold
(`examples/consumer-scaffold/`, docs/CONSUMER-GUIDE.md, docs/P-ROADMAP.md P3)
against a real PostgreSQL, a real Redis and a real, non-editable `saas-os`
wheel.

The scaffold is what a new product copies, so this test treats it exactly
like one: a wheel is built and installed into an isolated venv, the
scaffold's `my_product/` package is copied to a scratch directory outside
this repository, and everything below runs from there. In one run it
proves each thing the guide tells a product to do:

1. migrations -- SaaS OS's history, then the product's own, through
   `python -m my_product.migrate`, twice (it must be re-runnable);
2. grants and RLS -- the restricted application role can use the product
   table, the table has forced Row-Level Security, and a query with no
   tenant predicate still returns only the bound tenant's rows;
3. permissions -- the product's permission is registered, and the route
   denies a member who has not been granted it;
4. the route -- 401 without a credential, 200 for a permitted member, and
   a 404 (never a 403) for a foreign tenant and for a foreign item;
5. background jobs -- the product's job runs on a real worker under the
   validated tenant context, cannot touch another tenant's row, and is
   accepted by the production worker next to the platform jobs;
6. tenant purge -- the product's participant removes the purged tenant's
   rows and no other tenant's.

It runs in its own database, created and dropped here, because the
scaffold and the ADR-0018 reference consumer both use Alembic's default
`alembic_version` table (as two real products each would, in their own
databases) and cannot share one.

Marked `integration`. A database or Redis that is configured but
unreachable skips, as in `tests/test_reference_consumer_integration.py`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import uuid
import venv
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import make_url, text
from sqlalchemy.exc import OperationalError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine
from saas_os.infra.ratelimit.config import get_ratelimit_config

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAFFOLD_SRC = REPO_ROOT / "examples" / "consumer-scaffold" / "my_product"

_DRIVER_SCRIPT = textwrap.dedent(
    """
    import asyncio
    import uuid

    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text as sqltext

    from saas_os.core.authority import SystemAuthority, SystemCaller
    from saas_os.core.identity.service import add_tenant_membership, create_user, get_membership
    from saas_os.core.identity.sessions import issue_session
    from saas_os.core.rbac import can, register_permission
    from saas_os.core.rbac.service import (
        assign_first_role_for_new_tenant,
        create_role,
        grant_permission,
    )
    from saas_os.core.tenancy import (
        TenantStatus,
        create_tenant,
        purge_tenant,
        transition_tenant_status,
    )
    from saas_os.infra.db import get_engine, tenant_session_scope, validate_application_role
    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.jobs import TenantJobPayload, build_worker, enqueue_job

    from my_product.migrate import migrate

    # Everything below runs against the installed package, not a source tree.
    import sys

    import saas_os.api as api
    import saas_os.core as core

    for module in (api, core):
        assert module.__file__.startswith(sys.prefix), module.__file__

    # --- 1. migrations: both histories, in order, and re-runnable -------
    migrate()
    migrate()

    admin = create_engine(get_migrations_database_config().url)

    def as_admin(statement, **params):
        with admin.connect() as conn:
            return conn.execute(sqltext(statement), params).all()

    assert as_admin("SELECT version_num FROM alembic_version_saas_os")
    assert as_admin("SELECT version_num FROM alembic_version") == [("0001_my_product_items",)]

    # --- 2. grants and RLS ----------------------------------------------
    # The application runs as a role that cannot bypass RLS ...
    role = validate_application_role(get_engine())
    # ... and the product table has RLS enabled and forced.
    assert as_admin(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'my_product' AND c.relname = 'items'"
    ) == [(True, True)]
    # The grant is exactly the four data privileges, to the application role.
    privileges = {
        row[0]
        for row in as_admin(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_schema = 'my_product' AND table_name = 'items' AND grantee = :r",
            r=role.role_name,
        )
    }
    assert privileges == {"SELECT", "INSERT", "UPDATE", "DELETE"}, privileges

    from my_product.items import NEW, PROCESSED, create_item, get_item
    from my_product.permissions import ITEMS_RESOURCE, READ

    provisioning = SystemCaller(SystemAuthority.PROVISIONING)

    def new_tenant(label):
        tenant = create_tenant(f"scaffold-{label}-{uuid.uuid4().hex[:8]}", caller=provisioning)
        user = create_user()
        add_tenant_membership(tenant.id, user.id, caller=provisioning)
        return tenant, user

    tenant_a, user_a = new_tenant("a")
    tenant_b, user_b = new_tenant("b")
    item_a = create_item(tenant_a.id, "a-1")
    item_b = create_item(tenant_b.id, "b-1")

    # Both rows exist (the privileged role sees them) ...
    assert len(as_admin("SELECT id FROM my_product.items")) == 2
    # ... but a query with NO tenant predicate, as the application role,
    # returns only the bound tenant's row. RLS is what isolates, not the
    # predicate in my_product/items.py.
    for tenant, own in ((tenant_a, item_a), (tenant_b, item_b)):
        with tenant_session_scope(tenant.id) as session:
            visible = session.execute(sqltext("SELECT id FROM my_product.items")).all()
        assert visible == [(own.id,)], visible
    # A foreign row cannot be written either: the INSERT is rejected.
    try:
        with tenant_session_scope(tenant_a.id) as session:
            session.execute(
                sqltext(
                    "INSERT INTO my_product.items (id, tenant_id, name, status) "
                    "VALUES (:i, :t, 'forged', 'new')"
                ),
                {"i": str(uuid.uuid4()), "t": str(tenant_b.id)},
            )
    except Exception as exc:  # noqa: BLE001
        assert "row-level security" in str(exc), exc
    else:
        raise AssertionError("an INSERT for another tenant was accepted")
    assert get_item(tenant_a.id, item_b.id) is None
    assert get_item(tenant_b.id, item_a.id) is None

    # --- 3. permissions ---------------------------------------------------
    # migrate() registered it -- checked directly, because the idempotent
    # call below would create the row if migrate() had not.
    assert as_admin(
        "SELECT 1 FROM core.permissions WHERE resource = :r AND action = :a",
        r=ITEMS_RESOURCE,
        a=READ,
    ), "my_product.migrate did not register the product's permission"
    permission = register_permission(ITEMS_RESOURCE, READ)
    assert not can(
        actor_id=user_a.id, tenant_id=tenant_a.id, action=READ, resource=ITEMS_RESOURCE
    )

    from my_product.app import create_app

    app = create_app()
    _, token_a = issue_session(user_a.id)
    _, token_b = issue_session(user_b.id)

    def get(client, tenant, item, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return client.get(f"/v1/tenants/{tenant.id}/items/{item.id}", headers=headers)

    with TestClient(app) as client:
        # A member without the permission is denied.
        assert get(client, tenant_a, item_a, token_a).status_code == 403

        role_row = create_role(tenant_a.id, "item-reader", caller=provisioning)
        grant_permission(tenant_a.id, role_row.id, permission.id, caller=provisioning)
        membership = get_membership(tenant_a.id, user_a.id)
        assign_first_role_for_new_tenant(
            tenant_a.id, membership.id, role_row.id, caller=provisioning
        )

        # --- 4. the route --------------------------------------------------
        assert get(client, tenant_a, item_a).status_code == 401
        allowed = get(client, tenant_a, item_a, token_a)
        assert allowed.status_code == 200, allowed.text
        assert allowed.json() == {"id": str(item_a.id), "name": "a-1", "status": NEW}
        # Another tenant's item under the caller's own tenant: not found.
        assert get(client, tenant_a, item_b, token_a).status_code == 404
        # Another tenant in the path: also a 404, never a 403.
        assert get(client, tenant_b, item_b, token_a).status_code == 404
        # The other tenant's member is not a member of tenant A: 404.
        assert get(client, tenant_a, item_a, token_b).status_code == 404

    # --- 5. background jobs -----------------------------------------------
    from saas_os.api.worker import build_production_worker

    from my_product.jobs import JOB_FUNCTIONS, MARK_ITEM_PROCESSED

    production = build_production_worker(extra_functions=JOB_FUNCTIONS)
    assert MARK_ITEM_PROCESSED in production.functions
    assert "_deliver_webhook" in production.functions

    async def run_job(tenant, item):
        queue = f"scaffold-test-{uuid.uuid4().hex}"
        await enqueue_job(
            MARK_ITEM_PROCESSED,
            TenantJobPayload(tenant_id=str(tenant.id), data={"item_id": str(item.id)}),
            queue_name=queue,
        )
        worker = build_worker(JOB_FUNCTIONS, burst=True, queue_name=queue)
        try:
            await worker.main()
        finally:
            await worker.close()

    # A job running as tenant B, naming tenant A's item, changes nothing.
    asyncio.run(run_job(tenant_b, item_a))
    assert get_item(tenant_a.id, item_a.id).status == NEW
    asyncio.run(run_job(tenant_a, item_a))
    assert get_item(tenant_a.id, item_a.id).status == PROCESSED
    asyncio.run(run_job(tenant_a, item_a))  # at-least-once: a second run is harmless
    assert get_item(tenant_a.id, item_a.id).status == PROCESSED

    # --- 6. tenant purge ----------------------------------------------------
    # ADR-0045: marking a tenant deleted needs a person -- an enrolled
    # platform operator holding `platform.tenant:delete`. A product's own
    # code cannot do it with the provisioning purpose.
    from saas_os.core.authority import UserCaller
    from saas_os.core.platform_authority import (
        PlatformNotAuthorizedError,
        PlatformPermission,
        enroll_operator,
        grant_platform_permission,
    )

    try:
        transition_tenant_status(tenant_a.id, TenantStatus.DELETED, caller=provisioning)
    except PlatformNotAuthorizedError:
        pass
    else:
        raise AssertionError("provisioning must not be able to delete a tenant")
    bootstrap = SystemCaller(SystemAuthority.PLATFORM_BOOTSTRAP)
    operator_user = create_user()
    operator = enroll_operator(operator_user.id, caller=bootstrap, reason="scaffold test")
    grant_platform_permission(
        operator.id, PlatformPermission.TENANT_DELETE, caller=bootstrap, reason="scaffold test"
    )
    transition_tenant_status(
        tenant_a.id, TenantStatus.DELETED, caller=UserCaller(operator_user.id)
    )
    purge_authority = SystemCaller(SystemAuthority.TENANT_PURGE)
    result = purge_tenant(tenant_a.id, caller=purge_authority, actor_user_id=operator_user.id)
    assert "my_product.items" in result.participant_names, result
    assert as_admin("SELECT id FROM my_product.items") == [(item_b.id,)]
    assert purge_tenant(tenant_a.id, caller=purge_authority).already_purged is True

    admin.dispose()
    print("CONSUMER_SCAFFOLD_OK")
    """
)


def _admin_statement(statement: str) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text(statement))
    finally:
        engine.dispose()


@pytest.fixture
def scaffold_database_env() -> Iterator[dict[str, str]]:
    """The environment for the scaffold's own process: the configured
    database server, a database of its own."""
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    try:
        admin_config = get_migrations_database_config()
        app_config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database not configured for the integration test: {exc}")

    probe = build_engine(admin_config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL: {exc}")
    finally:
        probe.dispose()

    try:
        ratelimit_config = get_ratelimit_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    import redis as redis_sync

    try:
        redis_sync.Redis.from_url(ratelimit_config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}")

    database = f"scaffold_{uuid.uuid4().hex[:12]}"
    _admin_statement(f'CREATE DATABASE "{database}"')

    def _in_scaffold_database(url: str) -> str:
        return make_url(url).set(database=database).render_as_string(hide_password=False)

    env = os.environ.copy()
    env["MIGRATIONS_DATABASE_URL"] = _in_scaffold_database(admin_config.url)
    env["DATABASE_URL"] = _in_scaffold_database(app_config.url)
    try:
        yield env
    finally:
        _admin_statement(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')


def test_consumer_scaffold_end_to_end_against_installed_package(
    tmp_path_factory: pytest.TempPathFactory, scaffold_database_env: dict[str, str]
) -> None:
    wheel_dir = tmp_path_factory.mktemp("scaffold-wheel")
    build_result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(REPO_ROOT), "-w", str(wheel_dir), "--no-deps"],
        capture_output=True,
        text=True,
    )
    assert build_result.returncode == 0, build_result.stdout + build_result.stderr
    (wheel,) = wheel_dir.glob("saas_os-*.whl")

    venv_dir = tmp_path_factory.mktemp("scaffold-venv")
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
    venv_python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    install_result = subprocess.run(
        [str(venv_python), "-m", "pip", "install", str(wheel)],
        capture_output=True,
        text=True,
    )
    assert install_result.returncode == 0, install_result.stdout + install_result.stderr

    # Outside this repository: nothing can resolve through its source tree.
    scratch_dir = tmp_path_factory.mktemp("scaffold-scratch")
    shutil.copytree(
        SCAFFOLD_SRC, scratch_dir / "my_product", ignore=shutil.ignore_patterns("__pycache__")
    )
    driver_path = scratch_dir / "driver.py"
    driver_path.write_text(_DRIVER_SCRIPT, encoding="utf-8")

    run_result = subprocess.run(
        [str(venv_python), str(driver_path)],
        cwd=str(scratch_dir),
        env=scaffold_database_env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert run_result.returncode == 0, run_result.stdout[-4000:] + run_result.stderr[-4000:]
    assert "CONSUMER_SCAFFOLD_OK" in run_result.stdout
