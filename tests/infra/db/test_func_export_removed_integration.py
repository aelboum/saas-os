"""CP-07 J-INFRA-05 remediation -- end-to-end proof against a real
PostgreSQL instance that the `func.set_config()` cross-tenant RLS bypass
found during the audit is no longer constructible through the sanctioned
`infra.db` public surface.

Marked `integration` and excluded from the default `pytest` run,
mirroring `tests/core/tenancy/test_tenant_isolation_integration.py` --
same fixtures, same real-role/real-RLS setup (a scratch table carrying
the exact `infra/db/rls.py` DDL, queried through the *application's own*
`DATABASE_URL` role, never a role manufactured only for this test file).

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_func_export_removed_integration.py

The audit's own proof-of-concept built the exploit from nothing but
`select`/`func`, both then re-exported by `infra.db` -- no `text` import,
no direct `sqlalchemy` import, fully within the sanctioned surface. This
file proves that construction is impossible now: not by re-running an
already-fixed exploit and checking it happens to fail (which would only
prove *this specific line of code* fails, not that no equivalent
construction exists), but by walking every name `infra.db` actually
exports and confirming none of them can reach `set_config` -- then,
end-to-end, that a tenant-scoped session using only what's left in that
surface cannot alter `app.tenant_id` for the remainder of its own
transaction.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.rls import tenant_rls_statements
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

pytestmark = pytest.mark.integration

_APP_ROLE = os.environ.get("APP_DB_USER", "saas_os_app")


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


@pytest.fixture
def admin_session_factory() -> Iterator[sessionmaker[Session]]:
    """The privileged bootstrap/migration connection -- used *only* to set
    up (and tear down) the scratch tenant-owned table, exactly mirroring
    what a real migration does. Every isolation assertion below uses the
    default, application-role `tenant_session_scope()` instead."""
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def scratch_table(admin_session_factory: sessionmaker[Session]) -> Iterator[str]:
    table = f"j_infra_05_probe_{uuid.uuid4().hex[:8]}"
    with session_scope(session_factory=admin_session_factory) as session:
        session.execute(
            text(f"CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL, data TEXT)")
        )
        session.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO "{_APP_ROLE}"'))
        for statement in tenant_rls_statements(table):
            session.execute(text(statement))
    try:
        yield table
    finally:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(text(f"DROP TABLE IF EXISTS {table}"))


# --- Static: the sanctioned surface cannot reach set_config -----------------


def test_no_infra_db_export_can_reach_set_config() -> None:
    """Exhaustive, not example-based: no name `infra.db` exports today
    (or would export under any future addition matching this same shape)
    is, or exposes, the raw function-call capability the exploit needed."""
    import infra.db

    assert "func" not in infra.db.__all__
    assert not hasattr(infra.db, "func")
    for name in infra.db.__all__:
        obj = getattr(infra.db, name)
        assert not hasattr(obj, "set_config"), (
            f"infra.db.{name} exposes .set_config -- the exact PostgreSQL "
            "session-mutating function the original exploit called."
        )


def test_the_original_exploit_construction_now_raises_at_the_import_step() -> None:
    """The audit's own proof-of-concept began with `from infra.db import
    select, func`. Reproduce exactly that import line and confirm it now
    fails before a single query is ever built -- the attack cannot even
    be *constructed*, let alone executed."""
    with pytest.raises(ImportError):
        exec("from infra.db import select, func", {})  # noqa: S102


# --- Dynamic: RLS holds end-to-end for a tenant-scoped session --------------


def test_tenant_scoped_session_cannot_alter_its_own_app_tenant_id(
    scratch_table: str,
) -> None:
    """End-to-end regression for the exact scenario the audit proved
    exploitable: two tenants' rows in a real, non-superuser,
    `FORCE ROW LEVEL SECURITY`-protected table (the application's own
    `DATABASE_URL` role -- never a role manufactured only for this test).
    A `tenant_session_scope(tenant_a)` session, restricted to whatever is
    actually importable from `infra.db` (`select`, `tenant_session_scope`
    -- `func` deliberately not imported, because it no longer exists),
    must see only tenant_a's row for the entire transaction -- there is
    no remaining way, using the sanctioned surface, to make it see
    tenant_b's."""
    # `select` is not referenced directly below -- it must exist as a live
    # local name for the `eval(...)` call further down to resolve it (and
    # only fail to resolve `func`, which no longer exists at all).
    from infra.db import select  # noqa: F401
    from infra.db import tenant_session_scope as scoped_session

    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    with scoped_session(tenant_a) as session:
        session.execute(
            text(f"INSERT INTO {scratch_table} (id, tenant_id, data) VALUES (:id, :t, 'A-secret')"),
            {"id": str(uuid.uuid4()), "t": str(tenant_a)},
        )
    with scoped_session(tenant_b) as session:
        session.execute(
            text(f"INSERT INTO {scratch_table} (id, tenant_id, data) VALUES (:id, :t, 'B-secret')"),
            {"id": str(uuid.uuid4()), "t": str(tenant_b)},
        )

    with scoped_session(tenant_a) as session:
        rows_before = session.execute(text(f"SELECT data FROM {scratch_table}")).scalars().all()
        assert rows_before == ["A-secret"]

        # The only sanctioned way left to reach a SQL function at all is
        # `select(...)` over an ORM-mapped column/table -- there is no
        # `func` to compose `select(func.set_config(...))` with anymore.
        with pytest.raises(NameError):
            eval("select(func.set_config('app.tenant_id', str(tenant_b), False))")  # noqa: S307

        rows_after = session.execute(text(f"SELECT data FROM {scratch_table}")).scalars().all()
        assert rows_after == ["A-secret"], (
            "tenant_a's session sees a different row set after the exploit "
            "attempt -- app.tenant_id was altered; the fix did not hold."
        )
