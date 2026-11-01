"""Static guardrails against raw SQL built at run time (finding F6, owner
decision of 2026-11-01: test-only checks; threat model in
`docs/architecture/RAW-SQL-RLS-THREAT-MODEL.md`, pull request #188).

Tenant isolation is row-level security keyed on the session setting
`app.tenant_id`, which any SQL the application role runs can change
(`set_config`). The import fence (no `func`, no `text` in
`saas_os.infra.db`; no `sqlalchemy` import in products outside migrations)
removes the obvious constructors, but `Column.op("<raw SQL>")` and
`Session.connection().exec_driver_sql("<sql>")` need no forbidden import.
These checks are **guardrails, not a security boundary**: code running in
the process can always reach the database another way. They catch the
realistic mistake, SQL text or an operator built from data, and keep the
property the assessment recorded: no shipped code builds SQL text at run
time.

Rules, applied by AST to the shipped code and the examples products copy:

1. `.op(x)` / `.bool_op(x)`: `x` must be a string literal made of operator
   symbols only (`@@`, `->>`, `||`, ...). A name, an f-string, a
   concatenation or a literal containing letters, spaces, quotes or
   parentheses is refused: it is SQL text, not an operator.
2. `exec_driver_sql(...)` and `literal_column(...)`: refused everywhere
   scanned.
3. `text(x)`: refused outside `saas_os/infra/` (the infrastructure layer,
   the only one the import contracts let use SQLAlchemy directly) and
   Alembic migrations. Inside them, `x` must be static: a string literal,
   an implicit concatenation of literals, a module-level constant
   (`_UPPER_CASE` name), or an f-string whose every placeholder is such a
   constant.
4. `.execute(x)` with an f-string, a `%`/`+` string expression or a
   `.format()` call as `x`: refused everywhere scanned (a driver-level
   cursor would run it as raw SQL), except in Alembic migrations, which
   format DDL with a role name (an identifier cannot be a bound parameter).
   They run once, as the migration role, never at request time; rule 5
   holds them to it.
5. A migration that formats anything but module constants into SQL must
   validate what it formats: it must contain the plain-identifier pattern
   its role helpers use (`r"[A-Za-z_][A-Za-z0-9_]*"`, with `re.fullmatch`
   or a compiled pattern's `fullmatch`).

Not scanned, with the reason: `tests/` (fixtures and clean-up run as the
migration role on disposable databases and are not shipped; they use
`text(f"...")` over fixed table names), and documentation. Exceptions are
listed in `_ALLOWED` with a reason; the list is empty because nothing in
the scanned code needs one.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNED_ROOTS = ("saas_os", "examples", "products", "scripts")
# Where raw SQL text is allowed at all (rule 3), as long as it is static.
RAW_SQL_ZONES = ("saas_os/infra/",)
MIGRATION_MARKER = "/migrations/versions/"
# `path:line` -> reason. Every entry needs a reason a reviewer can check.
_ALLOWED: dict[str, str] = {}

_OPERATOR_SYMBOLS = re.compile(r"^[@#&|<>=!~*+\-/%^?]{1,4}$")
_CONSTANT_NAME = re.compile(r"^_?[A-Z][A-Z0-9_]*$")


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}"


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _is_static_sql(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.Name):
        return bool(_CONSTANT_NAME.match(node.id))
    if isinstance(node, ast.JoinedStr):
        return all(
            isinstance(part, ast.Constant)
            or (
                isinstance(part, ast.FormattedValue)
                and isinstance(part.value, ast.Name)
                and bool(_CONSTANT_NAME.match(part.value.id))
            )
            for part in node.values
        )
    return False


def _is_built_string(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def check_source(source: str, relative_path: str) -> list[Violation]:
    """The violations in one file's source. `relative_path` uses `/`."""
    in_raw_zone = relative_path.startswith(RAW_SQL_ZONES) or MIGRATION_MARKER in relative_path
    violations: list[Violation] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        first = node.args[0] if node.args else None
        if name in {"op", "bool_op"} and isinstance(node.func, ast.Attribute):
            literal = (
                first.value
                if isinstance(first, ast.Constant) and isinstance(first.value, str)
                else None
            )
            if literal is None or not _OPERATOR_SYMBOLS.match(literal):
                violations.append(
                    Violation(
                        relative_path, node.lineno, f"{name}() with SQL text, not an operator"
                    )
                )
        elif name in {"exec_driver_sql", "literal_column"}:
            violations.append(Violation(relative_path, node.lineno, f"{name}() is raw SQL"))
        elif name == "text" and first is not None:
            if not in_raw_zone:
                violations.append(
                    Violation(relative_path, node.lineno, "text() outside saas_os/infra")
                )
            elif not _is_static_sql(first):
                violations.append(
                    Violation(relative_path, node.lineno, "text() with SQL built at run time")
                )
        elif (
            name == "execute"
            and first is not None
            and _is_built_string(first)
            and MIGRATION_MARKER not in relative_path
        ):
            violations.append(
                Violation(relative_path, node.lineno, "execute() with SQL built at run time")
            )
    return violations


def _scanned_files() -> Iterator[Path]:
    for root in SCANNED_ROOTS:
        base = REPO_ROOT / root
        if base.is_dir():
            yield from (p for p in sorted(base.rglob("*.py")) if "__pycache__" not in p.parts)


def test_no_shipped_or_example_code_builds_raw_sql_at_run_time() -> None:
    found = []
    for path in _scanned_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        for violation in check_source(path.read_text(encoding="utf-8"), relative):
            if f"{violation.path}:{violation.line}" not in _ALLOWED:
                found.append(str(violation))
    assert not found, "\n".join(found)


_IDENTIFIER_PATTERN = 'r"[A-Za-z_][A-Za-z0-9_]*"'


def test_a_migration_that_formats_sql_validates_the_identifier_it_formats() -> None:
    """Rule 5. Every migration whose `execute()` takes a formatted string
    also carries the plain-identifier check, so nothing but a validated
    identifier is ever formatted into its DDL."""
    unchecked = []
    for path in _scanned_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        if MIGRATION_MARKER not in relative:
            continue
        source = path.read_text(encoding="utf-8")
        formats = any(
            isinstance(node, ast.Call)
            and _call_name(node) == "execute"
            and node.args
            and _is_built_string(node.args[0])
            and not _is_static_sql(node.args[0])
            for node in ast.walk(ast.parse(source))
        )
        if formats and (_IDENTIFIER_PATTERN not in source or "fullmatch" not in source):
            unchecked.append(relative)
    assert not unchecked, unchecked


def test_every_allowlist_entry_still_matches_a_violation() -> None:
    """An exception that no longer matches anything is removed, so the list
    cannot silently grow stale."""
    live = set()
    for path in _scanned_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        live |= {f"{v.path}:{v.line}" for v in check_source(path.read_text("utf-8"), relative)}
    assert set(_ALLOWED) <= live


def test_the_scan_covers_the_package_and_the_examples() -> None:
    """Not vacuous: the files that hold the database layer and the example
    consumers are actually read."""
    scanned = {p.relative_to(REPO_ROOT).as_posix() for p in _scanned_files()}
    assert "saas_os/infra/db/session.py" in scanned
    assert "saas_os/infra/db/role_guard.py" in scanned
    assert any(p.startswith("examples/reference-consumer/") for p in scanned)
    assert any(p.startswith("examples/consumer-scaffold/") for p in scanned)


# --- The checker itself: what it refuses and what it accepts -----------------

_PRODUCT = "examples/some_product/repository.py"
_DB = "saas_os/infra/db/session.py"


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        # The F6 demonstration: SQL text smuggled in as an operator.
        (
            "Role.name.op(\"|| (SELECT set_config('app.tenant_id', 't', false)) ||\")(x)",
            "op() with SQL text",
        ),
        ("Model.col.op(user_supplied)(value)", "op() with SQL text"),
        ("Model.col.op(f'{op}')(value)", "op() with SQL text"),
        ("Model.col.bool_op('@@ ' + extra)(value)", "bool_op() with SQL text"),
        ("Model.col.op('LIKE')(value)", "op() with SQL text"),  # a word is SQL text
        ("session.connection().exec_driver_sql('SELECT 1')", "exec_driver_sql() is raw SQL"),
        ("select(literal_column('tenant_id'))", "literal_column() is raw SQL"),
        ("session.execute(text('SELECT 1'))", "text() outside saas_os/infra"),
        ("cursor.execute(f'SELECT * FROM t WHERE id = {value}')", "execute() with SQL built"),
        ("cursor.execute('SELECT %s' % value)", "execute() with SQL built"),
        ("cursor.execute('SELECT {}'.format(value))", "execute() with SQL built"),
    ],
)
def test_the_checker_refuses_raw_sql_in_product_code(source: str, rule: str) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule.startswith(rule)


@pytest.mark.parametrize(
    "source",
    [
        "Document.search.bool_op('@@')(query)",  # full-text match operator
        "Model.data.op('->>')('key')",  # JSON operator
        "Model.a.op('||')(Model.b)",  # concatenation
        "session.execute(select(Model).where(Model.id == value))",
        "session.execute(update(Model).values(x=1))",
        "logger.info('text(%s)', value)",  # not SQL at all
        "'SELECT 1'.format()",  # a format call that is not executed
    ],
)
def test_the_checker_accepts_ordinary_queries_and_symbolic_operators(source: str) -> None:
    assert check_source(source, _PRODUCT) == []


@pytest.mark.parametrize(
    "source",
    [
        "session.execute(text(\"SELECT set_config('app.tenant_id', :t, true)\"), {'t': t})",
        "session.execute(text('SELECT 1 ' 'FROM x'))",
        "session.execute(text(_PROTECTED_WRITES_QUERY))",
        "conn.execute(sa.text(f'SELECT count(*) FROM t WHERE status IN {_LIVE}'))",
    ],
)
def test_static_raw_sql_is_accepted_where_raw_statements_live(source: str) -> None:
    assert check_source(source, _DB) == []
    assert check_source(source, "saas_os/infra/health/readiness.py") == []
    assert check_source(source, "saas_os/infra/db/migrations/versions/abc_x.py") == []


@pytest.mark.parametrize(
    "path", ["saas_os/core/billing/service.py", "saas_os/api/v1/members.py", _PRODUCT]
)
def test_static_raw_sql_is_still_refused_above_the_infrastructure_layer(path: str) -> None:
    (violation,) = check_source("session.execute(text('SELECT 1'))", path)
    assert violation.rule == "text() outside saas_os/infra"


def test_a_migration_may_format_ddl_but_a_product_may_not() -> None:
    ddl = "op.execute(f'GRANT USAGE ON SCHEMA s TO \"{role}\"')"
    assert check_source(ddl, "saas_os/infra/db/migrations/versions/abc_x.py") == []
    (violation,) = check_source(ddl, _PRODUCT)
    assert violation.rule == "execute() with SQL built at run time"


@pytest.mark.parametrize(
    "source",
    [
        "session.execute(text(query))",
        "session.execute(text(f'SELECT * FROM {table}'))",
        "session.execute(text('SELECT ' + column))",
    ],
)
def test_raw_sql_built_at_run_time_is_refused_even_in_the_database_layer(source: str) -> None:
    (violation,) = check_source(source, _DB)
    assert violation.rule == "text() with SQL built at run time"
