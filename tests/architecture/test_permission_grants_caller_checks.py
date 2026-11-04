"""The permission-grant package states a caller-type requirement with an
explicit `CallerTypeError`, never with an `assert` (which `python -O`
strips, turning the requirement into nothing)."""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2] / "saas_os" / "core" / "permission_grants"


def _caller_asserts(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Assert) and "isinstance(caller" in ast.unparse(node.test)
    ]


def test_the_package_is_found() -> None:
    assert len(list(PACKAGE.glob("*.py"))) > 5


def test_no_permission_grant_module_checks_the_caller_type_with_an_assert() -> None:
    found = [
        f"{path.name}:{line}"
        for path in sorted(PACKAGE.glob("*.py"))
        for line in _caller_asserts(path)
    ]
    assert not found, (
        "`assert isinstance(caller, ...)` is stripped under `python -O`; use "
        "`if not isinstance(caller, UserCaller): raise CallerTypeError(operation, caller, "
        f"(UserCaller,))` instead. Found: {found}"
    )
