"""Static, database-free inventory of the schema Alembic's migrations
produce at head -- table -> column-name set, per schema-qualified table --
derived by walking the migration scripts themselves in revision order and
parsing each one's own `upgrade()` function with Python's `ast` module.
Migration code is never executed and no database is ever contacted.

This is the authoritative "what does the real schema look like" answer for
this repository: `saas_os/infra/db/migrations/env.py`'s own `target_metadata = None`
means nothing here ever derives the schema from SQLAlchemy ORM metadata --
every migration is hand-written, and the migration history is the sole
source of truth for what a real database ends up containing (that module's
own docstring). Deriving an inventory from SQLAlchemy `Base.metadata`
instead would require importing every model module across `core`,
`control_plane`, and `self_learning` by hand -- exactly the kind of
second, independently maintained list this module exists to avoid -- and
would still miss any column a migration adds via `op.add_column()` without
a paired model-attribute change on the same commit. Walking the migration
scripts is complete by construction: no table or column can ever reach a
real database in this codebase without a migration that creates it.

Used by `saas_os.core.tenancy.retention.audit_retention_classification()` (RA-12-1)
to prove every tenant-scoped table this schema will ever produce is
accounted for in `RETENTION_CLASSIFICATION`, without a disposable
PostgreSQL instance and without a hand-maintained list of model modules.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import MappingProxyType

from alembic.config import Config
from alembic.script import ScriptDirectory

_DEFAULT_SCHEMA = "core"
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _alembic_config() -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "infra" / "db" / "migrations"))
    return cfg


def _string_const(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _schema_kwarg(call: ast.Call) -> str:
    for kw in call.keywords:
        if kw.arg == "schema":
            value = _string_const(kw.value)
            if value is not None:
                return value
    return _DEFAULT_SCHEMA


def _column_name(arg: ast.expr) -> str | None:
    """The column name, if `arg` (one of `create_table`'s positional
    arguments after the table name) is an `sa.Column(...)` call --
    `None` for anything else a table definition can carry positionally
    (`sa.CheckConstraint(...)`, `sa.ForeignKeyConstraint(...)`,
    `sa.UniqueConstraint(...)`, `sa.Index(...)`)."""
    if (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "Column"
        and arg.args
    ):
        return _string_const(arg.args[0])
    return None


def _is_op_call(node: ast.AST, attr: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == attr
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "op"
    )


def _apply_upgrade(tree: ast.Module, schema: dict[str, set[str]]) -> None:
    """Mutate `schema` (schema-qualified table name -> mutable column-name
    set) according to every `op.create_table()` / `op.add_column()` /
    `op.drop_column()` / `op.drop_table()` call found anywhere inside this
    module's own `upgrade()` function -- never `downgrade()`, which is the
    reverse operation and irrelevant to "what does head look like"."""
    upgrade_fn = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "upgrade"),
        None,
    )
    if upgrade_fn is None:
        return
    for node in ast.walk(upgrade_fn):
        if not isinstance(node, ast.Call):
            continue
        if _is_op_call(node, "create_table"):
            if not node.args:
                continue
            table = _string_const(node.args[0])
            if table is None:
                continue
            key = f"{_schema_kwarg(node)}.{table}"
            columns = {c for arg in node.args[1:] if (c := _column_name(arg)) is not None}
            schema[key] = columns
        elif _is_op_call(node, "add_column"):
            if len(node.args) < 2:
                continue
            table = _string_const(node.args[0])
            column = _column_name(node.args[1])
            if table is None or column is None:
                continue
            key = f"{_schema_kwarg(node)}.{table}"
            schema.setdefault(key, set()).add(column)
        elif _is_op_call(node, "drop_column"):
            if len(node.args) < 2:
                continue
            table = _string_const(node.args[0])
            column = _string_const(node.args[1])
            if table is None or column is None:
                continue
            key = f"{_schema_kwarg(node)}.{table}"
            schema.get(key, set()).discard(column)
        elif _is_op_call(node, "drop_table"):
            if not node.args:
                continue
            table = _string_const(node.args[0])
            if table is None:
                continue
            key = f"{_schema_kwarg(node)}.{table}"
            schema.pop(key, None)


def schema_at_head() -> MappingProxyType[str, frozenset[str]]:
    """Replay every migration's own `upgrade()` in revision order (oldest
    first -- `ScriptDirectory.walk_revisions()` yields head-first, so this
    reverses it) and return the resulting table -> column-name-set
    inventory, read-only. Pure AST parsing: no migration code is ever
    executed, no database is ever contacted."""
    script_dir = ScriptDirectory.from_config(_alembic_config())
    revisions = list(script_dir.walk_revisions())
    revisions.reverse()
    schema: dict[str, set[str]] = {}
    for revision in revisions:
        source = Path(revision.path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=revision.path)
        _apply_upgrade(tree, schema)
    return MappingProxyType({table: frozenset(cols) for table, cols in schema.items()})
