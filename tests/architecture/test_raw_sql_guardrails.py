"""Static guardrails against raw SQL built at run time (finding F6, owner
decisions of 2026-11-01 and 2026-11-02: test-only checks; the raw-SQL and
RLS threat model is in pull request #188).

Tenant isolation is row-level security keyed on the session setting
`app.tenant_id`, which any SQL the application role runs can change
(`set_config`). The import fence (no `func`, no `text` in
`saas_os.infra.db`; no `sqlalchemy` import in products outside migrations)
removes the obvious constructors, but `Column.op("<raw SQL>")` and
`Session.connection().exec_driver_sql("<sql>")` need no forbidden import.
These checks are **guardrails, not a complete security boundary**: they
read source patterns, not data, and code running in the process can
always reach the database another way. They catch the realistic mistake,
SQL text or an operator built from data, and keep the property the
assessment recorded: no shipped code builds SQL text at run time.

Rules, applied by AST to the shipped code and the examples products copy:

1. `.op(x)` / `.bool_op(x)`: `x` must be a string literal made of operator
   symbols only (`@@`, `->>`, `||`, ...) and must not contain a SQL comment
   token (`--`, `/*`, `*/`). A name, an f-string, a concatenation or a
   literal containing letters, spaces, quotes or parentheses is refused:
   it is SQL text, not an operator.
2. `exec_driver_sql(...)`, `literal_column(...)` and
   `column(..., is_literal=<anything but False>)`: refused everywhere
   scanned.
3. `text(x)`, `TextClause(x)` and `DDL(x)` (`sqlalchemy.schema.DDL`):
   refused outside `saas_os/infra/` (the infrastructure layer, the only one
   the import contracts let use SQLAlchemy directly) and Alembic
   migrations. Inside them, `x` must be static: a string literal, an
   implicit or `+` concatenation of static parts, a module-level constant
   (`_UPPER_CASE` name not itself built at run time), or an f-string whose
   every placeholder is such a constant.
4. `.execute(x)` with an f-string, a `%`/`+` string expression or a
   `.format()` call as `x`, or with a variable assigned such a string (see
   "Data flow" below): refused everywhere scanned (a driver-level cursor
   would run it as raw SQL), except in Alembic migrations, which format DDL
   with a role name (an identifier cannot be a bound parameter). They run
   once, as the migration role, never at request time; rule 5 holds them
   to it.
5. A migration that formats anything but module constants into SQL must
   validate what it formats: it must contain the plain-identifier pattern
   its role helpers use (`r"[A-Za-z_][A-Za-z0-9_]*"`, with `re.fullmatch`
   or a compiled pattern's `fullmatch`).

Import aliases: `from sqlalchemy[.sql[.expression]] import text as T`
makes `T(...)` a `text()` call, as does a re-binding `T = sa.text` or
`T = text`. Attribute calls (`sa.text`, `sql.text`, `expression.text`,
`sa.column`, `schema.DDL`) are matched by the attribute name whatever the
module alias; an unaliased bare name (`text(...)`) is matched by name.

Data flow, deliberately simple: within one scope (the module, or one
function or lambda body; nested functions are their own scope), a name is
"built at run time" when any assignment to it (`=`, annotated `=`, `:=`,
`+=`, `%=`) takes a string built from anything but literals and module
constants, or another such name. The analysis is flow-insensitive (an
assignment anywhere in the scope counts; a later static reassignment does
not clear it), and a function inherits the names built in the scopes that
enclose it. Not tracked: function parameters, return values, attributes,
container elements, `getattr(sa, "text")`, other modules. A miss is
possible; code review remains necessary.

Not scanned, with the reason: `tests/` (fixtures and clean-up run as the
migration role on disposable databases and are not shipped; they use
`text(f"...")` over fixed table names), and documentation. Exceptions are
listed in `_ALLOWED` with a reason; the list is empty because nothing in
the scanned code needs one.

A product copying this file must adapt `SCANNED_ROOTS`, `RAW_SQL_ZONES`,
`MIGRATION_MARKER` and `test_the_scan_covers_the_package_and_the_examples`
to its own layout: it checks nothing it is not pointed at.
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
_SQL_COMMENT_TOKENS = ("--", "/*", "*/")
_CONSTANT_NAME = re.compile(r"^_?[A-Z][A-Z0-9_]*$")
# Constructors whose first argument is SQL text (rule 3).
_TEXT_CONSTRUCTORS = frozenset({"text", "TextClause", "DDL"})
# Raw SQL wherever they appear (rule 2); `column` only with `is_literal`.
_ALWAYS_RAW = frozenset({"exec_driver_sql", "literal_column"})
_ALIASABLE = _TEXT_CONSTRUCTORS | _ALWAYS_RAW | {"column"}
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}"


def _call_name(node: ast.Call, aliases: dict[str, str] | None = None) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return (aliases or {}).get(node.func.id, node.func.id)
    return None


def _is_sqlalchemy_module(module: str | None) -> bool:
    return module is not None and (module == "sqlalchemy" or module.startswith("sqlalchemy."))


def _sqlalchemy_aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> SQLAlchemy name, for `from sqlalchemy... import X as Y`
    and for re-bindings `Y = sa.text` / `Y = text` of a guarded name."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and _is_sqlalchemy_module(node.module):
            for alias in node.names:
                if alias.asname and alias.name in _ALIASABLE:
                    aliases[alias.asname] = alias.name
    rebindings = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    changed = True
    while changed:
        changed = False
        for node in rebindings:
            value = node.value
            if isinstance(value, ast.Attribute):
                resolved = value.attr
            elif isinstance(value, ast.Name):
                resolved = aliases.get(value.id, value.id)
            else:
                continue
            if resolved not in _ALIASABLE:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and aliases.get(target.id) != resolved:
                    aliases[target.id] = resolved
                    changed = True
    return aliases


def _is_static_sql(node: ast.expr, built: frozenset[str] = frozenset()) -> bool:
    """A literal, a module constant not built at run time, or an f-string or
    `+` concatenation of those. `built` holds names built at run time."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.Name):
        return bool(_CONSTANT_NAME.match(node.id)) and node.id not in built
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_static_sql(node.left, built) and _is_static_sql(node.right, built)
    if isinstance(node, ast.JoinedStr):
        return all(
            isinstance(part, ast.Constant)
            or (
                isinstance(part, ast.FormattedValue)
                and isinstance(part.value, ast.Name)
                and _is_static_sql(part.value, built)
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


def _scope_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """The nodes of one scope. A nested function or lambda is yielded but
    not entered: it is a scope of its own."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _built_names(scope: ast.AST, inherited: frozenset[str]) -> frozenset[str]:
    """The names some assignment in `scope` gives a string built at run
    time (flow-insensitive), plus those inherited from enclosing scopes."""
    assignments: list[tuple[str, ast.expr | None]] = []
    for node in _scope_nodes(scope):
        if isinstance(node, ast.Assign):
            assignments += [(t.id, node.value) for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign | ast.NamedExpr):
            if isinstance(node.target, ast.Name) and node.value is not None:
                assignments.append((node.target.id, node.value))
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add | ast.Mod):
            if isinstance(node.target, ast.Name):
                assignments.append((node.target.id, None))  # `+=` / `%=` builds
    built = set(inherited)
    changed = True
    while changed:
        changed = False
        known = frozenset(built)
        for name, value in assignments:
            if name in built:
                continue
            if (
                value is None
                or (isinstance(value, ast.Name) and value.id in known)
                or (_is_built_string(value) and not _is_static_sql(value, known))
            ):
                built.add(name)
                changed = True
    return frozenset(built)


def _calls(tree: ast.Module) -> Iterator[tuple[ast.Call, frozenset[str]]]:
    """Every call in the module, with the names built at run time in the
    scope the call is in."""
    pending: list[tuple[ast.AST, frozenset[str]]] = [(tree, frozenset())]
    while pending:
        scope, inherited = pending.pop()
        built = _built_names(scope, inherited)
        for node in _scope_nodes(scope):
            if isinstance(node, _SCOPES):
                pending.append((node, built))
            elif isinstance(node, ast.Call):
                yield node, built


def _executes_built_sql(call: ast.Call, built: frozenset[str]) -> bool:
    if not call.args:
        return False
    first = call.args[0]
    if isinstance(first, ast.Name):
        return first.id in built
    return _is_built_string(first)


def _is_literal_column(call: ast.Call) -> bool:
    return any(
        keyword.arg == "is_literal"
        and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False)
        for keyword in call.keywords
    )


def check_source(source: str, relative_path: str) -> list[Violation]:
    """The violations in one file's source. `relative_path` uses `/`."""
    in_raw_zone = relative_path.startswith(RAW_SQL_ZONES) or MIGRATION_MARKER in relative_path
    tree = ast.parse(source)
    aliases = _sqlalchemy_aliases(tree)
    violations: list[Violation] = []
    for node, built in _calls(tree):
        name = _call_name(node, aliases)
        first = node.args[0] if node.args else None
        rule: str | None = None
        if name in {"op", "bool_op"} and isinstance(node.func, ast.Attribute):
            literal = (
                first.value
                if isinstance(first, ast.Constant) and isinstance(first.value, str)
                else None
            )
            if literal is None or not _OPERATOR_SYMBOLS.match(literal):
                rule = f"{name}() with SQL text, not an operator"
            elif any(token in literal for token in _SQL_COMMENT_TOKENS):
                rule = f"{name}() with a SQL comment token, not an operator"
        elif name in _ALWAYS_RAW:
            rule = f"{name}() is raw SQL"
        elif name == "column" and _is_literal_column(node):
            rule = "column(is_literal=True) is raw SQL"
        elif name in _TEXT_CONSTRUCTORS and first is not None:
            if not in_raw_zone:
                rule = f"{name}() outside saas_os/infra"
            elif not _is_static_sql(first, built):
                rule = f"{name}() with SQL built at run time"
        elif (
            name == "execute"
            and _executes_built_sql(node, built)
            and MIGRATION_MARKER not in relative_path
        ):
            rule = "execute() with SQL built at run time"
        if rule is not None:
            violations.append(Violation(relative_path, node.lineno, rule))
    return sorted(violations, key=lambda v: (v.line, v.rule))


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
        if _formats_unvalidated_sql(path.read_text(encoding="utf-8")):
            unchecked.append(relative)
    assert not unchecked, unchecked


def _formats_unvalidated_sql(source: str) -> bool:
    """Rule 5 for one migration: it executes SQL built from something other
    than constants (directly or through a variable) without carrying the
    plain-identifier check."""
    formats = any(
        _call_name(call) == "execute"
        and _executes_built_sql(call, built)
        and not _is_static_sql(call.args[0], built)
        for call, built in _calls(ast.parse(source))
    )
    return formats and (_IDENTIFIER_PATTERN not in source or "fullmatch" not in source)


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


# --- Owner decision of 2026-11-02: comment tokens, aliases, variables --------


@pytest.mark.parametrize("operator", ["--", "/*", "*/", "->--", "|/*", "@*/"])
def test_an_operator_holding_a_sql_comment_token_is_refused(operator: str) -> None:
    (violation,) = check_source(f"Model.col.op('{operator}')(value)", _PRODUCT)
    assert violation.rule == "op() with a SQL comment token, not an operator"
    (violation,) = check_source(f"Model.col.bool_op('{operator}')(value)", _DB)
    assert violation.rule == "bool_op() with a SQL comment token, not an operator"


@pytest.mark.parametrize("operator", ["-", "/", "*", "#-", "#>>", "-|-", "@-@", "->"])
def test_single_minus_slash_and_star_operators_are_still_accepted(operator: str) -> None:
    assert check_source(f"Model.col.op('{operator}')(value)", _PRODUCT) == []


@pytest.mark.parametrize(
    "source",
    [
        "from sqlalchemy import text as T\nsession.execute(T('SELECT 1'))",
        "from sqlalchemy.sql import text as raw\nsession.execute(raw('SELECT 1'))",
        "from sqlalchemy.sql.expression import text as t\nsession.execute(t('SELECT 1'))",
        "import sqlalchemy as sa\nsession.execute(sa.text('SELECT 1'))",
        "from sqlalchemy import sql\nsession.execute(sql.text('SELECT 1'))",
        "from sqlalchemy.sql import expression\nsession.execute(expression.text('SELECT 1'))",
        "import sqlalchemy as sa\nT = sa.text\nsession.execute(T('SELECT 1'))",
        "from sqlalchemy import text\nT = text\nU = T\nsession.execute(U('SELECT 1'))",
    ],
)
def test_text_is_found_through_import_aliases(source: str) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule == "text() outside saas_os/infra"


def test_an_aliased_text_with_run_time_sql_is_refused_in_the_database_layer() -> None:
    source = "from sqlalchemy import text as T\nsession.execute(T(f'SELECT {column}'))"
    (violation,) = check_source(source, _DB)
    assert violation.rule == "text() with SQL built at run time"


def test_an_alias_of_something_that_is_not_sqlalchemy_is_not_text() -> None:
    assert check_source("from string import Template as T\nT('x')", _PRODUCT) == []


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("select(column('x', is_literal=True))", "column(is_literal=True) is raw SQL"),
        ("select(sa.column('x', is_literal=True))", "column(is_literal=True) is raw SQL"),
        ("select(sa.sql.column(name, is_literal=flag))", "column(is_literal=True) is raw SQL"),
        (
            "from sqlalchemy import column as c\nselect(c('x', is_literal=True))",
            "column(is_literal=True) is raw SQL",
        ),
        ("select(sa.literal_column('x'))", "literal_column() is raw SQL"),
        (
            "from sqlalchemy import literal_column as lc\nselect(lc('x'))",
            "literal_column() is raw SQL",
        ),
    ],
)
def test_literal_columns_are_refused_in_every_spelling(source: str, rule: str) -> None:
    for path in (_PRODUCT, _DB):
        (violation,) = check_source(source, path)
        assert violation.rule == rule


@pytest.mark.parametrize(
    "source",
    ["select(column('x'))", "select(sa.column('x', is_literal=False))", "select(Model.x)"],
)
def test_a_quoted_column_is_accepted(source: str) -> None:
    assert check_source(source, _PRODUCT) == []


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("op.execute(DDL('DROP TABLE t'))", "DDL() outside saas_os/infra"),
        ("event.listen(t, 'after_create', sa.schema.DDL('SELECT 1'))", "DDL() outside"),
        ("from sqlalchemy.schema import DDL as D\nD('SELECT 1')", "DDL() outside"),
        ("session.execute(TextClause('SELECT 1'))", "TextClause() outside saas_os/infra"),
        (
            "from sqlalchemy.sql.elements import TextClause as TC\nTC('SELECT 1')",
            "TextClause() outside",
        ),
    ],
)
def test_ddl_and_text_clause_are_refused_above_the_infrastructure_layer(
    source: str, rule: str
) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule.startswith(rule)


@pytest.mark.parametrize("path", [_DB, "saas_os/infra/db/migrations/versions/abc_x.py"])
@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("DDL(f'GRANT USAGE ON SCHEMA s TO {role}')", "DDL() with SQL built at run time"),
        ("TextClause('SELECT ' + column)", "TextClause() with SQL built at run time"),
    ],
)
def test_ddl_and_text_clause_must_be_static_where_raw_sql_lives(
    path: str, source: str, rule: str
) -> None:
    (violation,) = check_source(source, path)
    assert violation.rule == rule


def test_static_ddl_is_accepted_where_raw_sql_lives() -> None:
    source = "event.listen(t, 'after_create', DDL('ALTER TABLE t ENABLE ROW LEVEL SECURITY'))"
    assert check_source(source, _DB) == []


@pytest.mark.parametrize(
    "source",
    [
        "sql = f'SELECT * FROM t WHERE id = {value}'\nconn.execute(sql)",
        "sql = 'SELECT %s' % value\ncursor.execute(sql)",
        "sql = 'SELECT {}'.format(value)\ncursor.execute(sql)",
        "sql = 'SELECT * FROM ' + table\ncursor.execute(sql)",
        "sql = 'SELECT 1'\nsql += where\ncursor.execute(sql)",
        "sql: str = f'SELECT {value}'\ncursor.execute(sql)",
        "if (sql := f'SELECT {value}'):\n    cursor.execute(sql)",
        "base = f'SELECT {value}'\nsql = base\ncursor.execute(sql)",  # one hop
        "def run(conn, value):\n    sql = f'SELECT {value}'\n    return conn.execute(sql)",
        "sql = f'SELECT {value}'\ndef run(conn):\n    return conn.execute(sql)",  # enclosing
        "sql = f'SELECT {value}'\nsql = 'SELECT 1'\ncursor.execute(sql)",  # flow-insensitive
        "_QUERY = f'SELECT {value}'\ncursor.execute(_QUERY)",  # constant-looking name
    ],
)
def test_execute_of_a_variable_holding_run_time_sql_is_refused(source: str) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule == "execute() with SQL built at run time"


@pytest.mark.parametrize(
    "source",
    [
        "query = f'SELECT * FROM {table}'\nsession.execute(text(query))",
        "_QUERY = 'SELECT * FROM ' + table\nsession.execute(text(_QUERY))",
        "_QUERY = f'SELECT {value}'\ndef f():\n    session.execute(text(f'{_QUERY} x'))",
    ],
)
def test_a_constant_built_at_run_time_is_not_static(source: str) -> None:
    (violation,) = check_source(source, _DB)
    assert violation.rule == "text() with SQL built at run time"


@pytest.mark.parametrize(
    "source",
    [
        "sql = 'SELECT 1'\ncursor.execute(sql)",  # a static string in a variable
        "stmt = select(Model).where(Model.id == value)\nsession.execute(stmt)",
        "_LIVE = f'({_A}, {_B})'\nsession.execute(text(f'SELECT 1 WHERE s IN {_LIVE}'))",
        "_QUERY = 'SELECT 1 ' + _WHERE\nsession.execute(text(_QUERY))",
        # A name built in another function is a different variable.
        "def a(v):\n    sql = f'{v}'\n    return sql\ndef b(sql):\n    conn.execute(sql)",
    ],
)
def test_variables_holding_static_sql_or_statements_are_accepted(source: str) -> None:
    assert check_source(source, _DB) == []


def test_function_parameters_are_not_tracked_a_documented_limit() -> None:
    """The data flow is local: SQL built by a caller and passed in is not
    seen. This pins the limit the docstring states, so changing it is a
    deliberate decision."""
    source = "def run(conn, sql):\n    conn.execute(sql)\nrun(conn, f'SELECT {value}')"
    assert check_source(source, _PRODUCT) == []


_VALIDATES_ROLE = (
    'import re\n_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")\nassert _ID.fullmatch(role)\n'
)


@pytest.mark.parametrize(
    ("source", "unvalidated"),
    [
        ("sql = f'GRANT USAGE ON SCHEMA s TO {role}'\nop.execute(sql)", True),
        ("op.execute(f'GRANT USAGE ON SCHEMA s TO {role}')", True),
        (_VALIDATES_ROLE + "sql = f'GRANT USAGE ON SCHEMA s TO {role}'\nop.execute(sql)", False),
        ("op.execute(f'GRANT USAGE ON SCHEMA s TO {_ROLE}')", False),
        ("sql = 'GRANT USAGE ON SCHEMA s TO r'\nop.execute(sql)", False),
    ],
)
def test_rule_5_follows_variables_into_migrations(source: str, unvalidated: bool) -> None:
    assert _formats_unvalidated_sql(source) is unvalidated
