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

The SQL argument of a call is its first positional argument or, when it
has none, the keyword that callee uses for it (`text=`, `statement=`,
`query=`, `sql=`, `operation=`, `opstring=`).

Rules, applied by AST to the shipped code and the examples products copy:

1. `.op(x)` / `.bool_op(x)`: `x` must be a string literal made only of
   operator symbols (`@@`, `->>`, `||`, ...; matched in full) and must not
   contain a SQL comment token (`--`, `/*`, `*/`). A name, an f-string, a
   concatenation or a literal containing letters, spaces, quotes or
   parentheses is refused: it is SQL text, not an operator.
2. `exec_driver_sql(...)`, `literal_column(...)` and `column(...)` with
   `is_literal` (keyword, or third positional argument) other than a
   literal `False`: refused everywhere scanned.
3. `text(x)`, `TextClause(x)` and `DDL(x)` (`sqlalchemy.schema.DDL`):
   refused outside `saas_os/infra/` (the infrastructure layer, the only one
   the import contracts let use SQLAlchemy directly) and Alembic
   migrations. Inside them, `x` must be static: a string literal, an
   implicit or `+` concatenation of static parts, a static constant, or an
   f-string whose every placeholder is a static constant. A static
   constant is an `_UPPER_CASE` name that every module-level assignment
   gives a static value, and that is not a parameter or a local name of an
   enclosing function (an imported or environment-read name is not one).
4. `.execute(x)` with an f-string, a `%`/`+` string expression, a string
   method call (`.format()`, `.join()`, `.strip()`, `.replace()`, ...), a
   conditional expression with such a branch, or a variable assigned one
   (see "Data flow" below): refused everywhere scanned (a driver-level
   cursor would run it as raw SQL), except in Alembic migrations, which
   format DDL with a role name (an identifier cannot be a bound
   parameter). They run once, as the migration role, never at request
   time; rule 5 holds them to it.
5. A migration that formats anything but static constants into SQL must
   validate identifiers: its code (the AST, so a comment does not count)
   must hold the plain-identifier pattern `[A-Za-z_][A-Za-z0-9_]*` as a
   string constant and call `fullmatch` (`re.fullmatch` or a compiled
   pattern's). Limit: it does not prove that the value checked is the
   value formatted (the role helpers validate inside a function whose
   result the upgrade formats); review covers that link.

Import aliases: `from sqlalchemy[.sql[.expression]] import text as T`
makes `T(...)` a `text()` call, as do re-bindings `T = sa.text`,
`T: Any = text` and `T, U = sa.text, sa.column`. Attribute calls
(`sa.text`, `sql.text`, `expression.text`, `sa.column`, `schema.DDL`) are
matched by the attribute name whatever the module alias; an unaliased bare
name (`text(...)`) is matched by name.

Data flow, deliberately simple: within one scope (the module, one class
body, or one function or lambda body; each is its own scope), a name is
"built at run time" when any assignment to it takes a string built from
anything but literals and static constants, or another such name.
Assignments followed: `=` (including element-wise tuple/list unpacking of a
tuple/list value), annotated `=`, `:=`, `+=`, `%=`, and `for` or
comprehension targets over a literal list/tuple/set holding such a string.
The analysis is flow-insensitive (an assignment anywhere in the scope
counts; a later static reassignment does not clear it), and a scope
inherits the names built in the scopes that enclose it.

For `execute()`, the SQL arguments (the first positional one, starred or
not, the SQL keywords and any `**mapping`) are searched in their whole
subtree: a non-static f-string, a non-static `+`/`%` with a string operand
or a `.format()` call anywhere inside (in `dedent(...)`, `str(...)`,
`None or ...`, `*[...]`, `**{...}`) makes the call refused; a nested
`text()`-like call is left to its own rule. A built name counts only as the
whole argument (a bound value such as `M.host == host.lower()` is not SQL
text). A name declared `global` anywhere is never a static constant, and an
f-string placeholder's format spec must itself be static.

Known misses, the complete list as of the 2026-11-02 reviews (review covers
them; later gaps are added here, not necessarily fixed):

- values the scope does not show: function parameters, return values,
  attributes (including class-body names read through `self`), container
  elements, other modules;
- bindings not followed: unpacking of a non-literal value, iteration over
  a non-literal iterable, `except ... as e`, `match` captures, `with ... as`
  (bound as unknown, so never built), `del`;
- aliases not followed: re-bindings through `:=`, a conditional
  (`T = sa.text if c else f`), a `for` target, `getattr(sa, "text")`,
  `functools.partial(text)`, `import sqlalchemy.sql.expression` followed by
  a call through a variable holding the module;
- constructors not checked: `column(*args)` (a starred `is_literal`),
  `custom_op(...)`, `quoted_name(..., quote=False)`,
  `Index(..., postgresql_where=...)`.

A miss is possible; code review remains necessary. The opposite error is
accepted by design: a run-time string anywhere inside `execute()`'s SQL
argument, even a bound value in a statement builder
(`execute(select(M).where(M.x == f"{y}"))`), is refused; build the value
before the call.

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

_OPERATOR_SYMBOLS = re.compile(r"[@#&|<>=!~*+\-/%^?]{1,4}")  # used with fullmatch
_SQL_COMMENT_TOKENS = ("--", "/*", "*/")
_CONSTANT_NAME = re.compile(r"_?[A-Z][A-Z0-9_]*")  # used with fullmatch
# Constructors whose SQL argument is SQL text (rule 3).
_TEXT_CONSTRUCTORS = frozenset({"text", "TextClause", "DDL"})
# Raw SQL wherever they appear (rule 2); `column` only with `is_literal`.
_ALWAYS_RAW = frozenset({"exec_driver_sql", "literal_column"})
_ALIASABLE = _TEXT_CONSTRUCTORS | _ALWAYS_RAW | {"column"}
# The keyword a callee takes its SQL argument by, when it has no positional
# one: text(text=), TextClause(text=), DDL(statement=), Session.execute
# (statement=), DB-API cursor.execute(operation= / query= / sql=), op(opstring=).
_SQL_KEYWORDS = frozenset({"text", "statement", "query", "sql", "operation", "opstring"})
# String methods whose result is a string built at run time.
_STRING_METHODS = frozenset(
    {
        "format",
        "format_map",
        "join",
        "strip",
        "lstrip",
        "rstrip",
        "replace",
        "lower",
        "upper",
        "removeprefix",
        "removesuffix",
    }
)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_SCOPES = (*_FUNCTIONS, ast.ClassDef)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}"


@dataclass(frozen=True)
class _Binding:
    """A name bound in a scope: to `value`, or (value None) to a string
    built at run time when `built`, else to something unknown."""

    name: str
    value: ast.expr | None
    built: bool = False


def _call_name(node: ast.Call, aliases: dict[str, str] | None = None) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return (aliases or {}).get(node.func.id, node.func.id)
    return None


def _sql_argument(call: ast.Call) -> ast.expr | None:
    """The first positional argument, else the SQL keyword argument."""
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg in _SQL_KEYWORDS:
            return keyword.value
    return None


def _bind(target: ast.expr, value: ast.expr | None) -> list[_Binding]:
    """The bindings of one assignment target; a tuple or list target takes
    a tuple or list value element-wise, anything else binds unknowns."""
    if isinstance(target, ast.Name):
        return [_Binding(target.id, value)]
    if isinstance(target, ast.Tuple | ast.List):
        if (
            isinstance(value, ast.Tuple | ast.List)
            and len(value.elts) == len(target.elts)
            and not any(isinstance(e, ast.Starred) for e in (*value.elts, *target.elts))
        ):
            return [b for t, v in zip(target.elts, value.elts, strict=True) for b in _bind(t, v)]
        return [b for t in target.elts for b in _bind(t, None)]
    if isinstance(target, ast.Starred):
        return _bind(target.value, None)
    return []


def _bind_iteration(target: ast.expr, iterable: ast.expr) -> list[_Binding]:
    """A `for`/comprehension target: each element of a literal iterable is
    a possible value; any other iterable binds unknowns."""
    if isinstance(iterable, ast.List | ast.Tuple | ast.Set) and iterable.elts:
        return [b for element in iterable.elts for b in _bind(target, element)]
    return _bind(target, None)


def _bindings_of(node: ast.AST) -> list[_Binding]:
    if isinstance(node, ast.Assign):
        return [b for target in node.targets for b in _bind(target, node.value)]
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return _bind(node.target, node.value)
    if isinstance(node, ast.NamedExpr):
        return _bind(node.target, node.value)
    if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        built = isinstance(node.op, ast.Add | ast.Mod)  # `+=` / `%=` builds a string
        return [_Binding(node.target.id, None, built)]
    if isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
        return _bind_iteration(node.target, node.iter)
    if isinstance(node, ast.Import | ast.ImportFrom):
        return [_Binding((a.asname or a.name).split(".")[0], None) for a in node.names]
    if isinstance(node, ast.withitem) and node.optional_vars is not None:
        return _bind(node.optional_vars, None)
    return []


def _scope_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """The nodes of one scope. A nested function, lambda or class is
    yielded but not entered: it is a scope of its own."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _scope_bindings(scope: ast.AST) -> list[_Binding]:
    return [b for node in _scope_nodes(scope) for b in _bindings_of(node)]


def _parameters(scope: ast.AST) -> set[str]:
    if not isinstance(scope, _FUNCTIONS):
        return set()
    arguments = scope.args
    names = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    names += [a for a in (arguments.vararg, arguments.kwarg) if a is not None]
    return {a.arg for a in names}


def _sqlalchemy_aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> SQLAlchemy name, for `from sqlalchemy... import X as Y`
    and for re-bindings (`Y = sa.text`, `Y: Any = text`, `Y, Z = ...`) of a
    guarded name."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module == "sqlalchemy" or node.module.startswith("sqlalchemy."):
                for alias in node.names:
                    if alias.asname and alias.name in _ALIASABLE:
                        aliases[alias.asname] = alias.name
    rebindings = [
        b
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign | ast.AnnAssign)
        for b in _bindings_of(node)
    ]
    changed = True
    while changed:
        changed = False
        for binding in rebindings:
            value = binding.value
            if isinstance(value, ast.Attribute):
                resolved = value.attr
            elif isinstance(value, ast.Name):
                resolved = aliases.get(value.id, value.id)
            else:
                continue
            if resolved in _ALIASABLE and aliases.get(binding.name) != resolved:
                aliases[binding.name] = resolved
                changed = True
    return aliases


def _is_static_sql(node: ast.expr, static: frozenset[str] = frozenset()) -> bool:
    """A literal, a static constant (a name in `static`), or an f-string or
    `+` concatenation of those."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.Name):
        return node.id in static
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_static_sql(node.left, static) and _is_static_sql(node.right, static)
    if isinstance(node, ast.JoinedStr):
        return all(
            isinstance(part, ast.Constant)
            or (
                isinstance(part, ast.FormattedValue)
                and isinstance(part.value, ast.Name)
                and part.value.id in static
                and (part.format_spec is None or _is_static_sql(part.format_spec, static))
            )
            for part in node.values
        )
    return False


def _is_built_string(node: ast.expr, built: frozenset[str] = frozenset()) -> bool:
    """A string expression assembled at run time: an f-string, `+`/`%`, a
    string method call, a conditional with such a branch, or a name some
    assignment in scope builds."""
    if isinstance(node, ast.Name):
        return node.id in built
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return True
    if isinstance(node, ast.IfExp):
        return _is_built_string(node.body, built) or _is_built_string(node.orelse, built)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _STRING_METHODS
    )


def _static_constants(tree: ast.Module) -> frozenset[str]:
    """`_UPPER_CASE` names every module-level binding gives a static value
    (least fixed point, so constants built from constants count)."""
    bindings = _scope_bindings(tree)
    # A name declared `global` anywhere can be rebound from any function.
    rebound = {
        name for node in ast.walk(tree) if isinstance(node, ast.Global) for name in node.names
    }
    candidates = {b.name for b in bindings if _CONSTANT_NAME.fullmatch(b.name)} - rebound
    static: set[str] = set()
    changed = True
    while changed:
        changed = False
        known = frozenset(static)
        for name in candidates - static:
            if all(
                b.value is not None and _is_static_sql(b.value, known)
                for b in bindings
                if b.name == name
            ):
                static.add(name)
                changed = True
    return frozenset(static)


def _built_names(
    bindings: list[_Binding], inherited: frozenset[str], static: frozenset[str]
) -> frozenset[str]:
    """The names some binding gives a string built at run time
    (flow-insensitive), plus those inherited from enclosing scopes."""
    built = set(inherited)
    changed = True
    while changed:
        changed = False
        known = frozenset(built)
        for binding in bindings:
            if binding.name in built:
                continue
            value = binding.value
            if binding.built or (
                value is not None
                and _is_built_string(value, known)
                and not _is_static_sql(value, static)
            ):
                built.add(binding.name)
                changed = True
    return frozenset(built)


@dataclass(frozen=True)
class _Scope:
    built: frozenset[str]  # names holding a string built at run time
    static: frozenset[str]  # static constants visible here


def _calls(tree: ast.Module) -> Iterator[tuple[ast.Call, _Scope]]:
    """Every call in the module, with what its scope knows."""
    pending: list[tuple[ast.AST, frozenset[str], frozenset[str] | None]] = [
        (tree, frozenset(), None)
    ]
    while pending:
        node, inherited, outer_static = pending.pop()
        bindings = _scope_bindings(node)
        if outer_static is None:
            static = _static_constants(tree)
        else:  # a parameter or local name shadows the module constant
            static = outer_static - {b.name for b in bindings} - _parameters(node)
        scope = _Scope(_built_names(bindings, inherited, static), static)
        for child in _scope_nodes(node):
            if isinstance(child, _SCOPES):
                pending.append((child, scope.built, scope.static))
            elif isinstance(child, ast.Call):
                yield child, scope


def _sql_candidates(call: ast.Call) -> list[ast.expr]:
    """Every expression that can supply a call's SQL: the first positional
    argument (the value of `*x` when starred), the SQL keywords, and any
    `**mapping`."""
    candidates: list[ast.expr] = []
    if call.args:
        first = call.args[0]
        candidates.append(first.value if isinstance(first, ast.Starred) else first)
    candidates += [k.value for k in call.keywords if k.arg is None or k.arg in _SQL_KEYWORDS]
    return candidates


def _is_string_operand(node: ast.expr) -> bool:
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.Constant) and isinstance(node.value, str)
    )


def _holds_built_string(
    node: ast.expr, scope: _Scope, aliases: dict[str, str] | None = None
) -> bool:
    """Whether a run-time string appears anywhere in `node`'s subtree (inside
    calls such as `dedent(...)`/`str(...)`, `or`, starred and `**` values):
    a non-static f-string, a non-static `+` or `%` with a string operand, or
    a `.format()` call. A nested `text()`/`DDL()`/... call is not entered:
    its own rule reports it."""
    stack: list[ast.AST] = [node]
    while stack:
        sub = stack.pop()
        if isinstance(sub, ast.Call):
            name = _call_name(sub, aliases)
            if name in _TEXT_CONSTRUCTORS or name in _ALWAYS_RAW:
                continue
            if isinstance(sub.func, ast.Attribute) and sub.func.attr in {"format", "format_map"}:
                return True
        if isinstance(sub, ast.JoinedStr) and not _is_static_sql(sub, scope.static):
            return True
        if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Add | ast.Mod):
            stringy = _is_string_operand(sub.left) or (
                isinstance(sub.op, ast.Add) and _is_string_operand(sub.right)
            )
            if stringy and not _is_static_sql(sub, scope.static):
                return True
        stack.extend(ast.iter_child_nodes(sub))
    return False


def _executes_built_sql(
    call: ast.Call, scope: _Scope, aliases: dict[str, str] | None = None
) -> bool:
    return any(
        _is_built_string(sql, scope.built) or _holds_built_string(sql, scope, aliases)
        for sql in _sql_candidates(call)
    )


def _is_literal_column(call: ast.Call) -> bool:
    flags = [k.value for k in call.keywords if k.arg == "is_literal"]
    if len(call.args) >= 3:  # column(text, type_, is_literal, ...)
        flags.append(call.args[2])
    return any(not (isinstance(f, ast.Constant) and f.value is False) for f in flags)


def check_source(source: str, relative_path: str) -> list[Violation]:
    """The violations in one file's source. `relative_path` uses `/`."""
    in_raw_zone = relative_path.startswith(RAW_SQL_ZONES) or MIGRATION_MARKER in relative_path
    tree = ast.parse(source)
    aliases = _sqlalchemy_aliases(tree)
    violations: list[Violation] = []
    for node, scope in _calls(tree):
        name = _call_name(node, aliases)
        sql = _sql_argument(node)
        rule: str | None = None
        if name in {"op", "bool_op"} and isinstance(node.func, ast.Attribute):
            literal = (
                sql.value if isinstance(sql, ast.Constant) and isinstance(sql.value, str) else None
            )
            if literal is None or not _OPERATOR_SYMBOLS.fullmatch(literal):
                rule = f"{name}() with SQL text, not an operator"
            elif any(token in literal for token in _SQL_COMMENT_TOKENS):
                rule = f"{name}() with a SQL comment token, not an operator"
        elif name in _ALWAYS_RAW:
            rule = f"{name}() is raw SQL"
        elif name == "column" and _is_literal_column(node):
            rule = "column(is_literal=True) is raw SQL"
        elif name in _TEXT_CONSTRUCTORS and sql is not None:
            if not in_raw_zone:
                rule = f"{name}() outside saas_os/infra"
            elif not _is_static_sql(sql, scope.static):
                rule = f"{name}() with SQL built at run time"
        elif (
            name == "execute"
            and _executes_built_sql(node, scope, aliases)
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


_IDENTIFIER_PATTERN = "[A-Za-z_][A-Za-z0-9_]*"


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
    plain-identifier check in its code: the pattern as a string constant and
    a `fullmatch` call, both found in the AST (a comment does not count)."""
    tree = ast.parse(source)
    formats = False
    for call, scope in _calls(tree):
        if _call_name(call) == "execute" and any(
            (_is_built_string(sql, scope.built) and not _is_static_sql(sql, scope.static))
            or _holds_built_string(sql, scope)
            for sql in _sql_candidates(call)
        ):
            formats = True
    if not formats:
        return False
    nodes = list(ast.walk(tree))
    has_pattern = any(
        isinstance(node, ast.Constant) and node.value == _IDENTIFIER_PATTERN for node in nodes
    )
    calls_fullmatch = any(
        isinstance(node, ast.Call) and _call_name(node) == "fullmatch" for node in nodes
    )
    return not (has_pattern and calls_fullmatch)


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
        "_PROTECTED_WRITES_QUERY = 'SELECT 1'\nsession.execute(text(_PROTECTED_WRITES_QUERY))",
        "_LIVE = \"('a', 'b')\"\n"
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
        "_A, _B = 'a', 'b'\n_LIVE = f'({_A}, {_B})'\n"
        "session.execute(text(f'SELECT 1 WHERE s IN {_LIVE}'))",
        "_WHERE: str = 'WHERE x'\n_QUERY = 'SELECT 1 ' + _WHERE\nsession.execute(text(_QUERY))",
        "_Q = 'SELECT 1'\ndef f():\n    session.execute(text(_Q))",  # module constant in a function
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
        ("_ROLE = 'r'\nop.execute(f'GRANT USAGE ON SCHEMA s TO {_ROLE}')", False),
        # The check must be code: a comment naming the pattern and fullmatch does not count.
        (
            '# r"[A-Za-z_][A-Za-z0-9_]*" fullmatch\n'
            "op.execute(f'GRANT USAGE ON SCHEMA s TO {role}')",
            True,
        ),
        ("x = 'fullmatch [A-Za-z_][A-Za-z0-9_]*'\nop.execute(f'GRANT TO {role}')", True),
        ("import re\nre.fullmatch(r'[a-z]+', role)\nop.execute(f'GRANT TO {role}')", True),
        ("sql = 'GRANT USAGE ON SCHEMA s TO r'\nop.execute(sql)", False),
    ],
)
def test_rule_5_follows_variables_into_migrations(source: str, unvalidated: bool) -> None:
    assert _formats_unvalidated_sql(source) is unvalidated


# --- Second review (2026-11-02): keywords, constants, more data flow ---------


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("session.execute(text(text=f'SELECT {x}'))", "text() with SQL built at run time"),
        ("session.execute(sa.text(text=query))", "text() with SQL built at run time"),
        ("TextClause(text=user)", "TextClause() with SQL built at run time"),
        ("DDL(statement=f'GRANT ALL TO {role}')", "DDL() with SQL built at run time"),
    ],
)
def test_sql_passed_by_keyword_is_checked_in_the_database_layer(source: str, rule: str) -> None:
    (violation,) = check_source(source, _DB)
    assert violation.rule == rule


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("session.execute(text(text='SELECT 1'))", "text() outside saas_os/infra"),
        ("cursor.execute(query=f'SELECT {x}')", "execute() with SQL built at run time"),
        ("session.execute(statement=f'SELECT {x}')", "execute() with SQL built at run time"),
        ("cursor.execute(operation='SELECT %s' % x)", "execute() with SQL built at run time"),
        ("conn.execute(sql='SELECT ' + x)", "execute() with SQL built at run time"),
        ("Model.col.op(opstring=user)(value)", "op() with SQL text, not an operator"),
        ("Model.col.op(opstring='--')(value)", "op() with a SQL comment token, not an operator"),
    ],
)
def test_sql_passed_by_keyword_is_checked_in_product_code(source: str, rule: str) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule == rule


def test_a_keyword_that_is_not_the_sql_argument_is_ignored() -> None:
    source = "session.execute(statement=select(Model), params=f'{x}')"
    assert check_source(source, _PRODUCT) == []


@pytest.mark.parametrize(
    "source",
    [
        "import os\n_Q = os.environ['Q']\nsession.execute(text(_Q))",  # read at run time
        "_Q = ' '.join(parts)\nsession.execute(text(_Q))",  # a string method
        "QUERY = request.args['q']\nsession.execute(text(QUERY))",
        "from settings import QUERY\nsession.execute(text(QUERY))",  # imported, unknown
        "def run(SQL):\n    session.execute(text(SQL))",  # a parameter
        "_Q = 'SELECT 1'\ndef run(_Q):\n    session.execute(text(_Q))",  # shadowed
        "_Q = 'SELECT 1'\ndef run():\n    _Q = load()\n    session.execute(text(_Q))",
        "_Q = 'SELECT 1'\n_Q += where\nsession.execute(text(_Q))",
        "session.execute(text(_UNDEFINED))",
    ],
)
def test_an_upper_case_name_is_static_only_when_the_module_gives_it_a_static_value(
    source: str,
) -> None:
    (violation,) = check_source(source, _DB)
    assert violation.rule == "text() with SQL built at run time"


@pytest.mark.parametrize(
    "source",
    [
        "sql, params = f'SELECT {x}', {}\ncursor.execute(sql, params)",  # tuple unpacking
        "[sql, params] = [f'SELECT {x}', {}]\ncursor.execute(sql, params)",
        "sql: str = ' '.join(parts)\ncursor.execute(sql)",  # annotated
        "for sql in ['SELECT 1', f'SELECT {x}']:\n    cursor.execute(sql)",  # for target
        "[cursor.execute(sql) for sql in (f'SELECT {x}',)]",  # comprehension target
        "cursor.execute(' '.join(parts))",
        "cursor.execute(query.strip())",
        "cursor.execute(base.replace('x', column))",
        "cursor.execute(f'SELECT {x}' if flag else 'SELECT 1')",  # conditional
        "sql = 'SELECT 1' if flag else f'SELECT {x}'\ncursor.execute(sql)",
    ],
)
def test_more_run_time_strings_reaching_execute_are_refused(source: str) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule == "execute() with SQL built at run time"


@pytest.mark.parametrize(
    "source",
    [
        "sql, params = 'SELECT 1', {'x': x}\ncursor.execute(sql, params)",
        "for stmt in [select(A), select(B)]:\n    session.execute(stmt)",
        "cursor.execute(stmt if flag else other)",
        "stmt, _ = build()\nsession.execute(stmt)",  # unpacking a call: not tracked
    ],
)
def test_static_unpacking_iteration_and_conditionals_are_accepted(source: str) -> None:
    assert check_source(source, _PRODUCT) == []


@pytest.mark.parametrize(
    "source",
    [
        "T, U = sa.text, sa.column\nsession.execute(T('SELECT 1'))",  # tuple rebind
        "from typing import Any\nT: Any = sa.text\nsession.execute(T('SELECT 1'))",  # annotated
    ],
)
def test_text_is_found_through_tuple_and_annotated_rebindings(source: str) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule == "text() outside saas_os/infra"


@pytest.mark.parametrize(
    "source",
    ["select(column('x', None, True))", "select(sa.column('x', None, flag))"],
)
def test_a_positional_is_literal_is_refused(source: str) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule == "column(is_literal=True) is raw SQL"


def test_a_positional_false_is_literal_is_accepted() -> None:
    assert check_source("select(column('x', None, False))", _PRODUCT) == []


@pytest.mark.parametrize("operator", ["@@\n", "->>\n", "||\n"])
def test_an_operator_with_a_trailing_newline_is_refused(operator: str) -> None:
    (violation,) = check_source(f"Model.col.op({operator!r})(value)", _PRODUCT)
    assert violation.rule == "op() with SQL text, not an operator"


def test_known_misses_are_pinned_so_closing_one_is_deliberate() -> None:
    """The docstring's known misses; each returns no violation today."""
    for source in (
        "T = functools.partial(sa.text)\nstmt = T(f'SELECT {x}')\nsession.execute(stmt)",
        "session.execute(getattr(sa, 'text')('SELECT 1'))",
        "try:\n    pass\nexcept E as sql:\n    cursor.execute(sql)",  # except capture
        "select(column(*('x', None, True)))",  # a starred is_literal
        "T = sa.text if flag else other\nsession.execute(T('SELECT 1'))",  # conditional alias
        "class R:\n    Q = f'SELECT {x}'\n    def run(self):\n        cursor.execute(self.Q)",
        "Model.col.operate(custom_op(user), value)",
    ):
        assert check_source(source, _PRODUCT) == [], source


# --- Final review (2026-11-02): format specs, globals, nested run-time SQL ---


@pytest.mark.parametrize(
    "source",
    [
        "_T = 't'\nsession.execute(text(f'SELECT * FROM {_T:{x}}'))",  # dynamic format spec
        "_T = 't'\nsession.execute(text(f'{_T:>{width}}'))",
    ],
)
def test_a_dynamic_format_spec_is_not_static(source: str) -> None:
    (violation,) = check_source(source, _DB)
    assert violation.rule == "text() with SQL built at run time"


def test_a_static_format_spec_is_still_static() -> None:
    assert check_source("_T = 't'\nsession.execute(text(f'{_T:>10}'))", _DB) == []


@pytest.mark.parametrize(
    "source",
    [
        "_Q = 'SELECT 1'\ndef load(x):\n    global _Q\n    _Q = x\nsession.execute(text(_Q))",
        "_Q = 'SELECT 1'\ndef load(x):\n    global _Q\n    _Q = x\n"
        "def run():\n    session.execute(text(_Q))",
        "_Q = 'SELECT 1'\ndef touch():\n    global _Q\nsession.execute(text(_Q))",
    ],
)
def test_a_name_declared_global_is_never_a_static_constant(source: str) -> None:
    (violation,) = check_source(source, _DB)
    assert violation.rule == "text() with SQL built at run time"


@pytest.mark.parametrize(
    "source",
    [
        "cursor.execute(textwrap.dedent(f'SELECT {x}'))",
        "cursor.execute(None or f'SELECT {x}')",
        "cursor.execute(str(f'SELECT {x}'))",
        "cursor.execute(*[f'SELECT {x}'])",
        "cursor.execute(**{'statement': f'SELECT {x}'})",
        "cursor.execute(clean('SELECT ' + x))",
        "cursor.execute(clean('SELECT %s' % x))",
        "cursor.execute(clean('SELECT {}'.format(x)))",
        "cursor.execute(statement=dedent(f'SELECT {x}'))",
        "session.execute(select(M).where(M.x == f'{y}'))",  # by design, see the docstring
    ],
)
def test_a_run_time_string_anywhere_in_the_sql_argument_is_refused(source: str) -> None:
    (violation,) = check_source(source, _PRODUCT)
    assert violation.rule == "execute() with SQL built at run time"


@pytest.mark.parametrize(
    "source",
    [
        "session.execute(select(M).where(M.n == n + 1))",  # arithmetic, not a string
        "session.execute(select(M).where(M.host == host.lower()))",  # a bound value
        "session.execute(stmt, {'x': f'{y}'})",  # parameters are not the SQL argument
        "_T = 't'\ncursor.execute(dedent(f'SELECT * FROM {_T}' 'x'))",  # static parts only
    ],
)
def test_values_outside_the_sql_text_are_not_refused(source: str) -> None:
    assert check_source(source, _PRODUCT) == []


def test_run_time_sql_inside_text_is_reported_once_by_the_text_rule() -> None:
    (violation,) = check_source("session.execute(text(f'SELECT {x}'))", _DB)
    assert violation.rule == "text() with SQL built at run time"


def test_rule_5_sees_a_run_time_string_nested_in_a_migration_execute() -> None:
    assert _formats_unvalidated_sql("op.execute(dedent(f'GRANT USAGE ON SCHEMA s TO {role}'))")
