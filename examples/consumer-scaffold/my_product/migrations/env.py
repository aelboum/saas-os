"""This project's own Alembic environment (ADR-0016): its own script
directory and its own default-named `alembic_version` table, applied
after SaaS OS's own history (`alembic_version_saas_os`) against the same
physical database. `my_product/migrate.py` runs both in the fixed order.

The connection comes from the installed `saas-os` package
(`saas_os.infra.db.config.get_migrations_database_config()`, i.e.
`MIGRATIONS_DATABASE_URL` through the secrets provider), so a migration
runs as the privileged migration role and the application never does.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from saas_os.infra.db.config import get_migrations_database_config

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

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
