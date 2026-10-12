"""Foundation Enforcement FE-3 -- the complete RLS coverage proof, against a
real PostgreSQL database migrated to head.

For every table in the isolation registry (`saas_os/core/tenancy/isolation.py`):

- TENANT_OWNED: RLS enabled and FORCED, and exactly one policy, whose
  name, command, roles and expression are exactly what
  `saas_os.infra.db.rls.tenant_rls_statements()` creates;
- GLOBAL / SYSTEM: RLS not enabled.

And, schema-wide:

- the live set of SaaS OS tables equals the registry (no unclassified live
  table, no registry entry missing from the database);
- no `SECURITY DEFINER` function exists in any SaaS OS schema;
- no view, materialized view or foreign table exists in any SaaS OS schema
  (a view runs with its owner's privileges and would read past RLS; a
  materialized view cannot carry RLS at all) -- one would need an explicit
  isolation decision first;
- the runtime application role (`DATABASE_URL`) passes
  `saas_os.infra.db.validate_application_role()` -- not a superuser, no BYPASSRLS.

This is the one schema-wide assertion; the per-module isolation tests
still prove the behavior (cross-tenant reads/writes return nothing). It
covers every tenant-owned table, including `core.webhook_replay_records`,
which previously had no RLS assertion of its own. Consumer-owned schemas
(e.g. `reference_consumer`) are deliberately outside SaaS OS's registry.

SaaS OS schemas are *discovered*, not listed: every non-system schema in
the database except the declared consumer-owned ones, so a table, view or
function in a schema added later is still swept (review finding F-2).

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import re

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from saas_os.core.tenancy.isolation import ISOLATION_CLASSIFICATION, IsolationClass
from saas_os.infra.db import tenant_rls_statements, validate_application_role
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine

pytestmark = pytest.mark.integration

# Schemas a consuming project owns in the shared database (ADR-0016) --
# here the reference consumer the integration harness migrates. Everything
# else that is not a PostgreSQL system schema is SaaS OS's.
_CONSUMER_OWNED_SCHEMAS = frozenset({"reference_consumer"})
# A consuming project's own Alembic history uses Alembic's *default*
# version table in `public` (ADR-0016: two independent migration histories
# in one database). It is consumer-owned -- e.g. the reference consumer's,
# applied by the integration harness -- and outside SaaS OS's registry.
_CONSUMER_OWNED_TABLES = frozenset({"public.alembic_version"})


@pytest.fixture(scope="module")
def admin_engine():  # type: ignore[no-untyped-def]
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM public.alembic_version_saas_os"))
    except OperationalError as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    yield engine
    engine.dispose()


def _saas_os_schemas(conn) -> list[str]:  # type: ignore[no-untyped-def]
    rows = conn.execute(
        text(
            "SELECT nspname FROM pg_namespace "
            "WHERE nspname <> 'information_schema' AND left(nspname, 3) <> 'pg_'"
        )
    ).scalars()
    return sorted(set(rows) - _CONSUMER_OWNED_SCHEMAS)


def _relations(conn, kinds: tuple[str, ...]) -> dict[str, tuple[bool, bool]]:  # type: ignore[no-untyped-def]
    rows = conn.execute(
        text(
            "SELECT n.nspname || '.' || c.relname, c.relrowsecurity, c.relforcerowsecurity "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind = ANY(:kinds) AND n.nspname = ANY(:schemas)"
        ),
        {"kinds": list(kinds), "schemas": _saas_os_schemas(conn)},
    ).all()
    return {row[0]: (row[1], row[2]) for row in rows if row[0] not in _CONSUMER_OWNED_TABLES}


def _live_tables(engine) -> dict[str, tuple[bool, bool]]:  # type: ignore[no-untyped-def]
    with engine.connect() as conn:
        return _relations(conn, ("r", "p"))


def _policies(engine) -> dict[str, list[tuple]]:  # type: ignore[no-untyped-def]
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT schemaname || '.' || tablename, policyname, permissive, roles, cmd, "
                "qual, with_check FROM pg_policies WHERE schemaname = ANY(:schemas)"
            ),
            {"schemas": _saas_os_schemas(conn)},
        ).all()
    policies: dict[str, list[tuple]] = {}
    for row in rows:
        policies.setdefault(row[0], []).append(tuple(row[1:]))
    return policies


def _canonical_expression(engine, table: str) -> str:  # type: ignore[no-untyped-def]
    """The policy expression PostgreSQL stores for `tenant_rls_statements()`'s
    own `USING (...)` clause -- obtained by having PostgreSQL deparse that
    exact clause on a scratch table, so the comparison is against the
    canonical statement itself, not a hand-written copy of it."""
    schema, name = table.split(".", 1)
    statements = tenant_rls_statements(name, schema=schema)
    using = re.search(r"USING \((.*)\)$", statements[-1])
    assert using is not None, statements[-1]
    with engine.connect() as conn, conn.begin() as tx:
        conn.execute(text("CREATE TEMP TABLE _rls_probe (tenant_id uuid)"))
        conn.execute(text("ALTER TABLE _rls_probe ENABLE ROW LEVEL SECURITY"))
        conn.execute(text(f"CREATE POLICY _probe ON _rls_probe USING ({using.group(1)})"))
        expression = conn.execute(
            text("SELECT qual FROM pg_policies WHERE tablename = '_rls_probe'")
        ).scalar_one()
        tx.rollback()
    return expression


def test_live_tables_equal_the_isolation_registry(admin_engine) -> None:  # type: ignore[no-untyped-def]
    assert set(_live_tables(admin_engine)) == set(ISOLATION_CLASSIFICATION)


def test_every_tenant_owned_table_has_forced_rls_and_exactly_the_canonical_policy(
    admin_engine,  # type: ignore[no-untyped-def]
) -> None:
    live = _live_tables(admin_engine)
    policies = _policies(admin_engine)
    tenant_owned = sorted(
        table
        for table, entry in ISOLATION_CLASSIFICATION.items()
        if entry.isolation is IsolationClass.TENANT_OWNED
    )
    assert "core.webhook_replay_records" in tenant_owned
    expected_expression = _canonical_expression(admin_engine, tenant_owned[0])
    problems = []
    for table in tenant_owned:
        enabled, forced = live[table]
        if not (enabled and forced):
            problems.append(f"{table}: RLS enabled={enabled} forced={forced}")
        name = table.split(".", 1)[1]
        expected = [
            (f"{name}_tenant_isolation", "PERMISSIVE", ["public"], "ALL", expected_expression, None)
        ]
        actual = [(p[0], p[1], list(p[2]), p[3], p[4], p[5]) for p in policies.get(table, [])]
        if actual != expected:
            problems.append(f"{table}: policies {actual!r} != canonical {expected!r}")
    assert problems == []


def test_global_and_system_tables_have_no_rls(admin_engine) -> None:  # type: ignore[no-untyped-def]
    live = _live_tables(admin_engine)
    policies = _policies(admin_engine)
    offenders = [
        table
        for table, entry in ISOLATION_CLASSIFICATION.items()
        if entry.isolation is not IsolationClass.TENANT_OWNED
        and (live[table][0] or live[table][1] or policies.get(table))
    ]
    assert offenders == []


def test_no_security_definer_function_exists_in_saas_os_schemas(admin_engine) -> None:  # type: ignore[no-untyped-def]
    with admin_engine.connect() as conn:
        definers = conn.execute(
            text(
                "SELECT n.nspname || '.' || p.proname FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE p.prosecdef AND n.nspname = ANY(:schemas)"
            ),
            {"schemas": _saas_os_schemas(conn)},
        ).all()
    assert definers == []


def test_no_view_or_foreign_table_exists_in_saas_os_schemas(admin_engine) -> None:  # type: ignore[no-untyped-def]
    with admin_engine.connect() as conn:
        assert _relations(conn, ("v", "m", "f")) == {}


def test_schema_discovery_sweeps_a_schema_added_later(admin_engine) -> None:  # type: ignore[no-untyped-def]
    """Non-vacuousness of discovery: a table, view and function in a brand-new
    schema are all seen by the same queries the sweep uses."""
    with admin_engine.connect() as conn, conn.begin() as tx:
        conn.execute(text("CREATE SCHEMA _sweep_new_schema"))
        conn.execute(text("CREATE TABLE _sweep_new_schema.t (tenant_id uuid)"))
        conn.execute(text("CREATE VIEW _sweep_new_schema.v AS SELECT * FROM _sweep_new_schema.t"))
        assert "_sweep_new_schema" in _saas_os_schemas(conn)
        assert "_sweep_new_schema.t" in _relations(conn, ("r", "p"))
        assert "_sweep_new_schema.v" in _relations(conn, ("v", "m", "f"))
        assert not set(_saas_os_schemas(conn)) & _CONSUMER_OWNED_SCHEMAS
        tx.rollback()


def test_runtime_application_role_cannot_bypass_rls() -> None:
    get_database_config.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        validation = validate_application_role(engine)
        with engine.connect() as conn:
            superuser, bypass = conn.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            ).one()
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    finally:
        engine.dispose()
    assert validation is not None
    assert (superuser, bypass) == (False, False)


def test_the_sweep_detects_a_tenant_table_missing_its_policy(admin_engine) -> None:  # type: ignore[no-untyped-def]
    """Non-vacuousness: a scratch tenant-keyed table without the canonical
    statements is seen by the same catalog queries as un-protected."""
    with admin_engine.connect() as conn, conn.begin() as tx:
        conn.execute(text("CREATE TABLE core._sweep_probe (tenant_id uuid)"))
        row = conn.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity, "
                "(SELECT count(*) FROM pg_policies WHERE tablename = '_sweep_probe') "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'core' AND c.relname = '_sweep_probe'"
            )
        ).one()
        tx.rollback()
    assert tuple(row) == (False, False, 0)
