"""RA-12-2 -- pure unit tests for `saas_os.core.tenancy.purge_participants`: the
registry's own behavior, and the architecture-boundary property that the
new module never imports a Product (no database needed for either).
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

from saas_os.core.tenancy.purge_participants import (
    DuplicateTenantPurgeParticipantError,
    TenantPurgeParticipant,
    TenantPurgeParticipantRegistry,
    default_registry,
)


class _FakeParticipant:
    def __init__(self, name: str = "fake.participant") -> None:
        self._name = name
        self.calls: list[uuid.UUID] = []

    @property
    def name(self) -> str:
        return self._name

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None:
        self.calls.append(tenant_id)


def test_a_conforming_class_satisfies_the_protocol_structurally() -> None:
    assert isinstance(_FakeParticipant(), TenantPurgeParticipant)


def test_register_and_list_round_trip_in_registration_order() -> None:
    registry = TenantPurgeParticipantRegistry()
    first, second = _FakeParticipant("a"), _FakeParticipant("b")
    registry.register(first)
    registry.register(second)
    assert registry.list() == [first, second]


def test_duplicate_name_is_rejected() -> None:
    registry = TenantPurgeParticipantRegistry()
    registry.register(_FakeParticipant("dup"))
    with pytest.raises(DuplicateTenantPurgeParticipantError):
        registry.register(_FakeParticipant("dup"))
    assert len(registry.list()) == 1


def test_empty_name_is_rejected() -> None:
    registry = TenantPurgeParticipantRegistry()
    with pytest.raises(ValueError, match="non-empty"):
        registry.register(_FakeParticipant(""))


def test_a_fresh_registry_starts_empty() -> None:
    assert TenantPurgeParticipantRegistry().list() == []


def test_default_registry_is_a_process_wide_singleton() -> None:
    assert default_registry() is default_registry()


def test_isolated_registries_do_not_share_state() -> None:
    a, b = TenantPurgeParticipantRegistry(), TenantPurgeParticipantRegistry()
    a.register(_FakeParticipant("only-in-a"))
    assert b.list() == []


# --- Architecture boundary: Core never imports a Product --------------------


def test_purge_participants_module_never_imports_a_product() -> None:
    """`import-linter`'s own "Core does not depend on Products or the AI
    Control Plane" contract cannot see `reference_consumer` at all -- it
    lives outside every configured `root_packages` entry
    (`examples/reference-consumer/`, never a `products/` subpackage) -- so
    this is the one place that boundary is actually checked for the new
    module powering the Core-facing purge-participant contract. Static
    AST inspection, not an import attempt: importing this module must
    never have a side effect of pulling in a Product package either."""
    import saas_os.core.tenancy.purge_participants as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    forbidden_prefixes = ("reference_consumer", "products", "saas_os.control_plane")
    violations = [m for m in imported if m.startswith(forbidden_prefixes)]
    assert violations == []


def test_importing_purge_participants_pulls_in_no_product_module() -> None:
    """Empirical companion to the static check above: even transitively,
    importing this module must never cause a Product package to appear in
    `sys.modules` (mirrors this repository's own "confirmed empirically"
    convention for architecture contracts, e.g.
    tests/architecture/test_layer_boundaries.py)."""
    import subprocess
    import sys

    probe = (
        "import sys\n"
        "import saas_os.core.tenancy.purge_participants\n"
        "loaded = [m for m in sys.modules if m.startswith(('reference_consumer', 'products'))]\n"
        "print(loaded)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=30, check=True
    )
    assert result.stdout.strip() == "[]", result.stdout
