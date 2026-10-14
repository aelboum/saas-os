"""Every platform refusal names a declared label
(docs/ADR/0045-installation-scoped-platform-authority.md section 5b).

A `PlatformRefusalError` says what was refused in its `operation`
attribute. That value is a key of the declared operation table
(`PLATFORM_OPERATIONS`) or a member of the closed set of refusal labels
that are deliberately not operations (`NON_OPERATION_REFUSALS`) -- and
nothing else. A handler can therefore rely on the two mappings being the
whole vocabulary, and a label that is not an operation (identity erasure,
above all) can never be mistaken for one.

Proved in two ways:

- by construction: the base class refuses to be built with any other
  label, and no subclass can be built without going through it;
- statically: every label written as a literal at a construction site is
  declared, the labels of the closed set are written in exactly one
  module, and no refusal class is defined outside the errors module.

Hermetic: no database.
"""

from __future__ import annotations

import ast
import inspect
import uuid
from pathlib import Path
from typing import Any

import pytest

import saas_os.core.platform_authority.errors as errors_module
from saas_os.core.platform_authority import (
    NON_OPERATION_REFUSALS,
    PLATFORM_OPERATIONS,
    PlatformRefusalError,
    UnknownPlatformOperationError,
    is_refusal_label,
)

_REPO = Path(__file__).resolve().parents[2]
_SAAS_OS = _REPO / "saas_os"
_ERRORS = "saas_os/core/platform_authority/errors.py"
_OPERATIONS = "saas_os/core/platform_authority/operations.py"


def _subclasses(cls: type) -> list[type]:
    found: list[type] = []
    for sub in cls.__subclasses__():
        found.append(sub)
        found.extend(_subclasses(sub))
    return found


_REFUSALS: list[type[PlatformRefusalError]] = sorted(
    {PlatformRefusalError, *_subclasses(PlatformRefusalError)}, key=lambda cls: cls.__name__
)
_REFUSAL_NAMES = {cls.__name__ for cls in _REFUSALS}


def _build(cls: type[PlatformRefusalError], label: object) -> PlatformRefusalError:
    """Construct `cls` with `label` as its operation and a plausible value
    for every other required argument."""
    arguments: list[Any] = []
    for name, parameter in list(inspect.signature(cls.__init__).parameters.items())[1:]:
        if name == "operation":
            arguments.append(label)
        elif "uuid" in str(parameter.annotation).lower():
            arguments.append(uuid.uuid4())
        elif "int" in str(parameter.annotation):
            arguments.append(1)
        else:
            arguments.append("x")
    return cls(*arguments)


def _sources() -> list[Path]:
    return sorted(path for path in _SAAS_OS.rglob("*.py") if "__pycache__" not in path.parts)


def _rel(path: Path) -> str:
    return path.relative_to(_REPO).as_posix()


# --- by construction -----------------------------------------------------------------


def test_the_inventory_of_refusal_classes_is_the_reviewed_one() -> None:
    """A new refusal class is a visible diff here."""
    assert _REFUSAL_NAMES == {
        "PlatformRefusalError",
        "PlatformNotAuthorizedError",
        "SelfAuthorityChangeError",
        "PlatformAmplificationError",
        "LastPlatformOwnerError",
        "EnrolledOperatorErasureError",
        "PlatformSelfTargetError",
        "PlatformSubjectNotLinkedError",
        "TenantParentRuleError",
        "MoveIntoCallerHierarchyError",
        "DeactivationScanLimitError",
    }
    assert all(cls.__module__ == errors_module.__name__ for cls in _REFUSALS)


@pytest.mark.parametrize("cls", _REFUSALS, ids=lambda cls: cls.__name__)
@pytest.mark.parametrize(
    "label",
    ["user.purge", "tenant.transition ", "TENANT.READ", "", "platform.tenant.read", None, 7],
)
def test_no_refusal_can_be_built_with_an_undeclared_label(
    cls: type[PlatformRefusalError], label: object
) -> None:
    """Not a refusal that happens to carry a strange name: a programming
    error, raised as one. The audit action `platform.tenant.read` is among
    the rejected values -- an action is not a label."""
    with pytest.raises(UnknownPlatformOperationError):
        _build(cls, label)


@pytest.mark.parametrize("cls", _REFUSALS, ids=lambda cls: cls.__name__)
@pytest.mark.parametrize("label", sorted({*PLATFORM_OPERATIONS, *NON_OPERATION_REFUSALS}))
def test_every_declared_label_builds_every_refusal(
    cls: type[PlatformRefusalError], label: str
) -> None:
    assert _build(cls, label).operation == label


def test_no_subclass_can_be_built_without_the_base_initializer() -> None:
    """Every refusal class either inherits `__init__` or defines one that
    calls `super().__init__`, and only the base class assigns
    `self.operation`."""
    tree = ast.parse((_REPO / _ERRORS).read_text(encoding="utf-8"))
    assigns_operation: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name not in _REFUSAL_NAMES:
            continue
        initializers = [
            item
            for item in node.body
            if isinstance(item, ast.FunctionDef) and item.name == "__init__"
        ]
        for initializer in initializers:
            calls_super = any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "__init__"
                and isinstance(call.func.value, ast.Call)
                and isinstance(call.func.value.func, ast.Name)
                and call.func.value.func.id == "super"
                for call in ast.walk(initializer)
            )
            assert calls_super or node.name == "PlatformRefusalError", node.name
            if any(
                isinstance(target, ast.Attribute) and target.attr == "operation"
                for assign in ast.walk(initializer)
                if isinstance(assign, ast.Assign)
                for target in assign.targets
            ):
                assigns_operation.append(node.name)
    assert assigns_operation == ["PlatformRefusalError"]


# --- statically ----------------------------------------------------------------------


def test_refusal_classes_are_defined_only_in_the_errors_module() -> None:
    """A subclass defined elsewhere would be outside the inventory above
    until something imported it."""
    offenders = []
    for path in _sources():
        if _rel(path) == _ERRORS:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ClassDef) and any(
                (isinstance(base, ast.Name) and base.id in _REFUSAL_NAMES)
                or (isinstance(base, ast.Attribute) and base.attr in _REFUSAL_NAMES)
                for base in node.bases
            ):
                offenders.append(f"{_rel(path)}:{node.name}")
    assert offenders == []


def _construction_sites() -> list[tuple[str, int, ast.expr | None]]:
    """`(file, line, first argument)` of every construction of a refusal
    class under `saas_os/`."""
    sites = []
    for path in _sources():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            if name not in _REFUSAL_NAMES:
                continue
            first = node.args[0] if node.args else None
            for keyword in node.keywords:
                if keyword.arg == "operation":
                    first = keyword.value
            sites.append((_rel(path), node.lineno, first))
    return sites


def test_the_scan_finds_the_construction_sites() -> None:
    """Guards the scan itself: an empty result would make the test below
    pass for the wrong reason."""
    files = {path for path, _, _ in _construction_sites()}
    assert {
        "saas_os/core/platform_authority/authorization.py",
        "saas_os/core/identity/user_authority.py",
        "saas_os/core/tenancy/service.py",
        "saas_os/core/billing/oversight.py",
    } <= files
    assert len(_construction_sites()) >= 20


def test_every_label_written_at_a_construction_site_is_declared() -> None:
    """A literal label, or none at all, at a construction site: the
    literal must be declared. (A label that arrives in a variable is
    covered by construction, above.)"""
    undeclared = [
        f"{path}:{line}"
        for path, line, first in _construction_sites()
        if first is None or (isinstance(first, ast.Constant) and not is_refusal_label(first.value))
    ]
    assert undeclared == []


def test_the_non_operation_labels_and_actions_are_written_in_one_module() -> None:
    """Centralized: the label and action strings of the closed set appear
    as literals in the operations module and nowhere else under
    `saas_os/`, so there is one place to read what they are."""
    strings = set(NON_OPERATION_REFUSALS) | {
        row.audit_action for row in NON_OPERATION_REFUSALS.values() if row.audit_action
    }
    elsewhere = []
    for path in _sources():
        if _rel(path) == _OPERATIONS:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and node.value in strings:
                elsewhere.append(f"{_rel(path)}:{node.lineno}:{node.value}")
    assert elsewhere == []
    declared = {
        node.value
        for node in ast.walk(ast.parse((_REPO / _OPERATIONS).read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert strings <= declared
