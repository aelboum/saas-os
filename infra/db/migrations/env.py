"""Alembic environment (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1;
switched to the privileged migrations connection in Phase 3.1's security
correction; `version_table` pinned in the SaaS OS packaging/consumer
implementation phase, docs/ADR/0016-independent-database-migration-histories.md).

This is SaaS OS's own migration environment -- it tracks only
`core.*`/`control_plane.*`/`self_learning.*` revisions
(`infra/db/migrations/versions/`), in `alembic_version_saas_os`, never the
default `alembic_version` table a consuming project's own, separate
Alembic environment uses for its own schema (ADR-0016's two-independent-
-environments model). A consuming project invokes this environment only
through `infra.db.migration_runner.run_core_migrations()` (or the
`saas-os-migrate` console script) -- never by pointing its own `alembic`
CLI at this directory directly, and never by editing this file.

The database URL comes from `infra.db.config.get_migrations_database_config()`
(`MIGRATIONS_DATABASE_URL`) -- the separate, privileged bootstrap role,
*not* `get_database_config()`'s `DATABASE_URL` (the restricted application
runtime role). Migrations create schemas/tables/roles-worth of DDL that
the restricted runtime role must not be able to do; PostgreSQL never
applies Row-Level Security to a superuser or BYPASSRLS role regardless, so
these two must be different roles in any environment where RLS is
expected to actually protect data. Neither is a hardcoded value in
`alembic.ini` (docs/ADR/0012-secrets-management.md: no credential
committed to the repo) -- `alembic.ini` intentionally has no
`sqlalchemy.url` set.

`target_metadata` is `None`: intentionally not wired to `infra.db.orm.Base.metadata`
even though `core/tenancy` now defines a real table on it -- `infra/db`
must not import `core` (docs/ARCHITECTURE.md section 2), so this module
has no way to *import* `core.tenancy.models` to register its table on
that metadata without violating that rule. Autogenerate diffing against
Core's tables is a separate concern this phase does not solve; every
migration so far is hand-written.
"""

from logging.config import fileConfig

from alembic import context
from infra.db.config import get_migrations_database_config
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# See module docstring: no models exist yet.
target_metadata = None

# ADR-0016: SaaS OS's own version-tracking table, independent of the
# consuming project's own (default-named) `alembic_version` table.
VERSION_TABLE = "alembic_version_saas_os"


def _get_url() -> str:
    return get_migrations_database_config().url


def run_migrations_offline() -> None:
    """Emit migration SQL without a live DB connection (`alembic upgrade
    head --sql`), using just the configured URL."""
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table=VERSION_TABLE,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live DB connection. `NullPool`: a
    one-shot migration run doesn't need connection pooling."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table=VERSION_TABLE,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
