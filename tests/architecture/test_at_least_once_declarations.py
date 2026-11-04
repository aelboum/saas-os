"""Which code may declare `at_least_once` (retry-after-marker design,
decision D-6, option C).

After a started marker an `AmbiguousOutcomeError(at_least_once=True)` that a
consumer raised is retried within the attempt budget
(`docs/architecture/OUTBOX-RETRY-AFTER-MARKER-DESIGN.md`, branch B; #195
section 3.1). The raised exception is the declaration: there is no registry
and no flag, so this scan is the review gate. It reads every module of
`saas_os` and fails when a call passes `at_least_once=` anything but the
literal `False`, or when a class body or attribute assignment sets it, outside
the pinned places below. Adding a declaration is therefore a visible change to
this list, reviewed with the destination's de-duplication contract (a stable
identity on every attempt, a receiver that de-duplicates on it, the
possibility of a duplicate documented). A product's own class is governed by
that product's review.

The scanner's own tests feed it source text."""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2] / "saas_os"

# (module path under the repository, qualified class or function) -> why.
ALLOWED_DECLARATIONS: dict[tuple[str, str], str] = {
    (
        "saas_os/core/webhooks/errors.py",
        "WebhookAmbiguousDeliveryError.__init__",
    ): "webhooks: at-least-once on the stable event id, receivers de-duplicate (W1)",
    (
        "saas_os/api/outbox_dispatcher.py",
        "_ambiguous_outcome",
    ): "re-states a group whose every member declared it; declares nothing itself",
    (
        "saas_os/core/outbox/errors.py",
        "AmbiguousOutcomeError.__init__",
    ): "the class itself: stores and validates the constructor argument",
}

_NAME = "at_least_once"


def _scope_names(tree: ast.AST) -> dict[int, str]:
    """The dotted qualified name of the enclosing class or function of every
    node, by id (`Class.method`)."""
    scopes: dict[int, str] = {}

    def visit(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                inner = child.name if scope == "<module>" else f"{scope}.{child.name}"
            else:
                inner = scope
            scopes[id(child)] = inner
            visit(child, inner)

    visit(tree, "<module>")
    return scopes


def _is_false(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def declarations(source: str, filename: str = "<source>") -> list[tuple[str, int]]:
    """`(enclosing scope, line)` of every place `source` sets `at_least_once`
    to anything but the literal `False`: a keyword argument, a class-level
    or annotated assignment, or an attribute assignment."""
    tree = ast.parse(source, filename=filename)
    scopes = _scope_names(tree)
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == _NAME and not _is_false(keyword.value):
                    found.append((scopes.get(id(node), "<module>"), node.lineno))
        elif isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                name = (
                    target.id
                    if isinstance(target, ast.Name)
                    else target.attr
                    if isinstance(target, ast.Attribute)
                    else None
                )
                value = getattr(node, "value", None)
                if name != _NAME or (isinstance(node, ast.AnnAssign) and value is None):
                    continue  # an annotation alone declares nothing
                if value is None or not _is_false(value):
                    found.append((scopes.get(id(node), "<module>"), node.lineno))
    return found


def _package_declarations() -> list[tuple[str, str, int]]:
    root = PACKAGE.parent
    found: list[tuple[str, str, int]] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        for scope, line in declarations(path.read_text(encoding="utf-8"), relative):
            found.append((relative, scope, line))
    return found


def test_the_package_is_found() -> None:
    assert len(list(PACKAGE.rglob("*.py"))) > 300


def test_only_the_pinned_places_declare_at_least_once() -> None:
    unpinned = [
        f"{path}:{line} in {scope}"
        for path, scope, line in _package_declarations()
        if (path, scope) not in ALLOWED_DECLARATIONS
    ]
    assert unpinned == [], (
        "a class or call sets `at_least_once`; a destination's de-duplication contract must be "
        "reviewed and the place added to ALLOWED_DECLARATIONS "
        "(docs/architecture/OUTBOX-RETRY-AFTER-MARKER-DESIGN.md, D-6): " + ", ".join(unpinned)
    )


def test_every_pinned_place_still_declares_it() -> None:
    present = {(path, scope) for path, scope, _ in _package_declarations()}
    stale = sorted(set(ALLOWED_DECLARATIONS) - present)
    assert stale == [], f"pinned declarations that no longer exist: {stale}"


# --- The scanner's own tests -----------------------------------------------------------


def test_a_literal_true_argument_is_found() -> None:
    source = (
        "class Mine(AmbiguousOutcomeError):\n"
        "    def __init__(self):\n"
        "        super().__init__('r', phase='p', at_least_once=True)\n"
    )
    assert declarations(source) == [("Mine.__init__", 3)]


def test_a_computed_argument_is_found() -> None:
    assert declarations("f(at_least_once=flag)\n") == [("<module>", 1)]
    assert declarations("f(at_least_once=not other)\n") == [("<module>", 1)]


def test_the_literal_false_is_not_a_declaration() -> None:
    assert declarations("f(at_least_once=False)\n") == []


def test_a_class_level_or_attribute_assignment_is_found() -> None:
    assert declarations("class C:\n    at_least_once = True\n") == [("C", 2)]
    assert declarations("class C:\n    at_least_once: bool = True\n") == [("C", 2)]
    assert declarations("def f(e):\n    e.at_least_once = True\n") == [("f", 2)]
    assert declarations("def f(e):\n    e.at_least_once = x\n") == [("f", 2)]
    assert declarations("def f(e):\n    e.at_least_once = False\n") == []


def test_other_names_are_ignored() -> None:
    assert declarations("f(retry_within=1)\nclass C:\n    at_least = True\n") == []
