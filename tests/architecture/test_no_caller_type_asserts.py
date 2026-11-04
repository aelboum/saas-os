"""No module of `saas_os` states a caller-type requirement with an `assert`.

`python -O` strips `assert` statements, so a type check written as one is no
check at all in an optimized process: the code after it would run for a
caller type it was never written for. A requirement is stated with
`if not isinstance(caller, ...): raise CallerTypeError(operation, caller, (...,))`,
which type checkers narrow in the same way.

The scanner reads every `assert` in the package and flags one whose test
calls `isinstance(...)` or `type(...)` on an expression that names something
containing "caller" (`caller`, `core_caller`, `self.caller`, `authorized.caller`).
Its own tests feed it source text, to show that each way of writing such an
assert is caught and that the `raise` form is not."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "saas_os"
_CALLER_NAME = re.compile("caller", re.IGNORECASE)
_TYPE_PROBES = frozenset({"isinstance", "type"})


def _names_a_caller(expression: ast.AST) -> bool:
    for node in ast.walk(expression):
        if isinstance(node, ast.Name) and _CALLER_NAME.search(node.id):
            return True
        if isinstance(node, ast.Attribute) and _CALLER_NAME.search(node.attr):
            return True
    return False


def caller_type_asserts(source: str, filename: str = "<source>") -> list[int]:
    """The line numbers of the `assert` statements in `source` whose test probes
    the type of a caller with `isinstance(...)` or `type(...)`."""
    found: list[int] = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if not isinstance(node, ast.Assert):
            continue
        for call in ast.walk(node.test):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id in _TYPE_PROBES
                and call.args
                and _names_a_caller(call.args[0])
            ):
                found.append(node.lineno)
                break
    return sorted(found)


def test_the_package_is_found() -> None:
    assert len(list(PACKAGE.rglob("*.py"))) > 300


def test_no_module_checks_a_caller_type_with_an_assert() -> None:
    found = [
        f"{path.relative_to(PACKAGE.parent).as_posix()}:{line}"
        for path in sorted(PACKAGE.rglob("*.py"))
        for line in caller_type_asserts(path.read_text(encoding="utf-8"), str(path))
    ]
    assert not found, (
        "`assert isinstance(caller, ...)` is stripped under `python -O`; use "
        "`if not isinstance(caller, UserCaller): raise CallerTypeError(operation, caller, "
        f"(UserCaller,))` instead. Found: {found}"
    )


@pytest.mark.parametrize(
    "source",
    [
        "assert isinstance(caller, UserCaller)",
        "assert isinstance(core_caller, UserCaller)",
        "assert isinstance(caller, (UserCaller, SystemCaller))",
        "assert isinstance(caller, UserCaller | ServiceAccountCaller)",
        "assert isinstance(caller, UserCaller)  # authorized above",
        'assert isinstance(caller, UserCaller), "a user is required"',
        "assert isinstance(\n    caller,\n    (UserCaller, SystemCaller),\n)",
        "assert (isinstance(caller, UserCaller))",
        "assert not isinstance(caller, SystemCaller)",
        "assert not (isinstance(caller, SystemCaller))",
        "assert type(caller) is UserCaller",
        "assert type(caller) == UserCaller",
        "assert type(caller) in (UserCaller, SystemCaller)",
        "assert type(core_caller) is not SystemCaller",
        "assert isinstance(self.caller, UserCaller)",
        "assert isinstance(authorized.caller, UserCaller)",
        "assert isinstance(Caller, UserCaller)",
        "assert caller is not None and isinstance(caller, UserCaller)",
        "assert isinstance(caller, UserCaller) or isinstance(caller, SystemCaller)",
        "assert isinstance(actor_caller_id, UserCaller)",
        "def f(caller):\n    if x:\n        assert isinstance(caller, UserCaller)",
        "class C:\n    def f(self, caller):\n        with a:\n            assert type(caller) is X",
    ],
)
def test_the_scanner_catches_every_way_of_writing_the_assert(source: str) -> None:
    assert caller_type_asserts(source), source


@pytest.mark.parametrize(
    "source",
    [
        "if not isinstance(caller, UserCaller):\n    raise CallerTypeError(op, caller, ())",
        "assert isinstance(value, UserCaller)",
        "assert isinstance(tenant_id, uuid.UUID)",
        "assert type(row) is Row",
        "assert caller is not None",
        "assert caller.user_id == user_id",
        "assert len(callers) == 2",
        "x = isinstance(caller, UserCaller)",
        "raise AssertionError('caller')",
    ],
)
def test_the_scanner_does_not_flag_what_is_not_such_an_assert(source: str) -> None:
    assert caller_type_asserts(source) == [], source


def test_the_scanner_reports_the_line_of_each_assert() -> None:
    source = "a = 1\nassert isinstance(caller, X)\nb = 2\nassert type(caller) is Y\n"
    assert caller_type_asserts(source) == [2, 4]
