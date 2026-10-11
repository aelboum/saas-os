"""RA-11-F3 regression: loading either Alembic migration environment with an
`alembic.ini` must not disable loggers that already exist in the process.

`saas_os/infra/db/migrations/env.py` (and the reference consumer's own copy) call
`logging.config.fileConfig()` at module load whenever the Alembic `Config`
carries an ini path -- which every in-process migration test that builds
`Config(".../alembic.ini")` does. `fileConfig()`'s default
`disable_existing_loggers=True` set `disabled = True` on every logger already
registered at that moment; pytest imports every test module at collection,
so the backup, jobs, rate-limit and observability loggers all exist by then,
and every log-capture test that ran afterwards in the same process saw an
empty `caplog`. `disable_existing_loggers=False` is the fix; this test pins
it for both environments.

No database is needed: `fileConfig()` runs before env.py ever asks for a
connection URL, so `saas_os.infra.db.config.get_migrations_database_config` is
replaced with a function that raises a sentinel, stopping env.py right after
its logging configuration has been applied.
"""

from __future__ import annotations

import logging
import logging.config
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NoReturn

import pytest
from alembic import command
from alembic.config import Config

import saas_os.infra.db.config as db_config

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ALEMBIC_INI = _REPO_ROOT / "alembic.ini"
_MIGRATION_ENVIRONMENTS = {
    "saas-os": _REPO_ROOT / "saas_os" / "infra" / "db" / "migrations",
    "reference-consumer": _REPO_ROOT
    / "examples"
    / "reference-consumer"
    / "reference_consumer"
    / "migrations",
}


class _StopBeforeDatabaseAccess(RuntimeError):
    """Raised in place of the migration database config: env.py reaches it
    only after its module-level `fileConfig()` call has already run."""


@pytest.fixture
def _restore_logging_state() -> Iterator[None]:
    """`fileConfig()` also replaces the root logger's handlers and sets the
    levels of the loggers the ini names; put them back afterwards so this
    test leaves no global logging state behind for the rest of the suite."""
    root = logging.getLogger()
    named = [logging.getLogger(name) for name in ("sqlalchemy.engine", "alembic")]
    saved_root = (root.level, root.handlers[:])
    saved_named = [(lg, lg.level, lg.handlers[:], lg.propagate) for lg in named]
    yield
    root.setLevel(saved_root[0])
    root.handlers[:] = saved_root[1]
    for lg, level, handlers, propagate in saved_named:
        lg.setLevel(level)
        lg.handlers[:] = handlers
        lg.propagate = propagate


def _load_env_with_ini_until_database_access(
    monkeypatch: pytest.MonkeyPatch, script_location: Path
) -> list[dict[str, Any]]:
    """Run `alembic upgrade head` against `script_location` with the
    repository `alembic.ini` loaded -- exactly what the in-process migration
    tests do -- but stop at the first database-config lookup. Returns the
    keyword arguments of every `fileConfig()` call env.py made, so the test
    can prove the code path under test actually executed."""
    real_file_config = logging.config.fileConfig
    calls: list[dict[str, Any]] = []

    def _recording_file_config(fname: Any, *args: Any, **kwargs: Any) -> None:
        calls.append(dict(kwargs))
        real_file_config(fname, *args, **kwargs)

    def _stop_before_database_access() -> NoReturn:
        raise _StopBeforeDatabaseAccess("env.py asked for a database URL")

    monkeypatch.setattr(logging.config, "fileConfig", _recording_file_config)
    monkeypatch.setattr(db_config, "get_migrations_database_config", _stop_before_database_access)

    cfg = Config(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(script_location))
    assert cfg.config_file_name is not None  # what makes env.py call fileConfig() at all
    with pytest.raises(_StopBeforeDatabaseAccess):
        command.upgrade(cfg, "head")
    return calls


@pytest.mark.usefixtures("_restore_logging_state")
@pytest.mark.parametrize("environment", sorted(_MIGRATION_ENVIRONMENTS))
def test_loading_the_migration_env_does_not_disable_pre_existing_loggers(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    # A logger that exists *before* env.py runs -- the position every
    # application logger is in once pytest has collected the suite.
    probe = logging.getLogger(f"ra11f3.probe.{uuid.uuid4().hex}")
    assert probe.disabled is False

    calls = _load_env_with_ini_until_database_access(
        monkeypatch, _MIGRATION_ENVIRONMENTS[environment]
    )

    assert len(calls) == 1, "env.py never reached its fileConfig() call -- vacuous run"
    assert probe.disabled is False, (
        "fileConfig() disabled a pre-existing logger: disable_existing_loggers must be False"
    )
    assert probe.isEnabledFor(logging.WARNING)
