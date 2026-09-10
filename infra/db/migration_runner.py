"""Importable interface to SaaS OS's own migration history
(docs/ADR/0016-independent-database-migration-histories.md).

`infra/db/migrations/` ships two independent things a consuming project
must never confuse: the migration *environment* (`env.py`,
`script.py.mako`, `versions/*.py` -- shipped as package data,
`pyproject.toml`'s `[tool.setuptools.package-data]`) and this module, the
*only* supported way to invoke it. A consuming project must never point
its own `alembic` CLI, or a hand-built `alembic.config.Config`, at
`site-packages/infra/db/migrations` directly -- that would require it to
know an installed package's internal filesystem layout, exactly what
ADR-0016's "What Is Deliberately Not Decided Here" flags as an
implementation detail this module now resolves: the script directory is
located relative to this module's own file location
(`Path(__file__).resolve().parent / "migrations"`), which is correct both
in an editable/source-tree install and inside an installed wheel, because
`package-data` ships `migrations/` at that same relative path either way.

No shell subprocess is used -- `alembic.command` (the same library Alembic's
own `alembic` CLI itself calls into) is invoked in-process, using a
programmatically-built `alembic.config.Config` exactly like
`scripts/check-docker.sh`'s own ad hoc worker-migration step already does.
This module's `alembic.config.Config` intentionally never sets
`sqlalchemy.url` -- `infra/db/migrations/env.py`'s `_get_url()` always
sources the connection from `infra.db.config.get_migrations_database_config()`
(`MIGRATIONS_DATABASE_URL`, the privileged bootstrap/migration role) itself,
the same existing secrets/configuration path every other database
connection in this codebase uses (docs/ADR/0012-secrets-management.md) --
this module does not read, cache, or override that URL, so there is no
second database-configuration mechanism to keep in sync with `infra/db`'s
own.

`env.py` pins `version_table="alembic_version_saas_os"` -- every function
here therefore only ever touches SaaS OS's own version-tracking table.
Nothing here upgrades, downgrades, or inspects a consuming project's own
migrations (its own, separately-invoked Alembic environment, tracked in
the ordinary, default-named `alembic_version` table).
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

_MIGRATIONS_DIRECTORY = Path(__file__).resolve().parent / "migrations"


def _build_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIRECTORY))
    return cfg


def run_core_migrations(revision: str = "head") -> None:
    """Apply SaaS OS's own `core.*`/`control_plane.*`/`self_learning.*`
    migration history up to `revision` (default: the latest -- `"head"`,
    Alembic's own convention). This is the SaaS-OS-owned half of
    ADR-0016's two-environment model -- a consuming project runs this
    first, then applies its own, separate migrations through its own
    Alembic environment (ADR-0016's fixed ordering).

    Raises whatever `alembic.command.upgrade()` raises on failure (a real
    migration error, a database connectivity error, etc.) -- never
    swallowed here, matching the existing convention
    (`tests/infra/db/test_migration_gate_integration.py`'s own gate).
    """
    command.upgrade(_build_config(), revision)


def downgrade_core_migrations(revision: str) -> None:
    """Roll back SaaS OS's own migration history to `revision` (e.g.
    `"-1"` for one step). Mirrors `run_core_migrations()` exactly --
    same environment, same version table, same in-process invocation.
    """
    command.downgrade(_build_config(), revision)


def current_core_revision() -> str | None:
    """The revision `alembic_version_saas_os` currently records, or
    `None` if SaaS OS's migrations have never been applied against this
    database. Thin wrapper around `alembic.command.current`'s own
    resolution logic (via `ScriptDirectory`/`MigrationContext`), not a
    hand-rolled query against the version table.
    """
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    from infra.db.config import get_migrations_database_config

    engine = create_engine(get_migrations_database_config().url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"version_table": "alembic_version_saas_os"}
            )
            return context.get_current_revision()
    finally:
        engine.dispose()


def core_head_revision() -> str:
    """The latest revision in SaaS OS's own shipped migration history --
    what `run_core_migrations()`'s default `revision="head"` resolves to.
    Useful for a caller (e.g. the reference consumer, or a test) that
    wants to assert a database is fully up to date without hardcoding a
    revision id.
    """
    (head,) = ScriptDirectory.from_config(_build_config()).get_heads()
    return head
