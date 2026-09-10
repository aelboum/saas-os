"""The reference consumer's own Alembic environment (ADR-0016) --
independent of SaaS OS's own (`infra/db/migrations/env.py`): its own
script directory, its own default-named `alembic_version` table (no
override, unlike SaaS OS's own `alembic_version_saas_os`), invoked
separately, after SaaS OS's migrations (ADR-0016's fixed ordering).

Reuses `infra.db.config.get_migrations_database_config()` from the
installed `saas-os` package for the connection -- both environments
target the same one physical database per project (ADR-0016), so reusing
SaaS OS's own config/secrets plumbing here is the correct, intended
pattern (`Independent SaaS Project -> saas-os`, ADR-0015's one permitted
dependency direction), not a boundary violation.
"""

from logging.config import fileConfig

from alembic import context
from infra.db.config import get_migrations_database_config
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def _get_url() -> str:
    return get_migrations_database_config().url


def run_migrations_offline() -> None:
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
