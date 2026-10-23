"""RA-12-2 -- pure unit tests for `saas_os.core.tenancy.purge_participants`: the
registry's own behavior, and the architecture-boundary property that the
new module never imports a Product (no database needed for either).
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

import saas_os.core.tenancy as tenancy
from saas_os.core.tenancy import purge_participants
from saas_os.core.tenancy.purge_participants import (
    DuplicateTenantPurgeParticipantError,
    InvalidTenantPurgeParticipantError,
    TenantPurgeParticipant,
    TenantPurgeParticipantRegistry,
    default_registry,
    register_purge_participant,
    registered_purge_participant_names,
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


def test_registering_the_same_object_again_is_a_no_op() -> None:
    registry = TenantPurgeParticipantRegistry()
    participant = _FakeParticipant("same")
    assert registry.register(participant) is participant
    assert registry.register(participant) is participant
    assert registry.list() == [participant]
    assert registry.names() == ("same",)


def test_a_different_object_under_a_registered_name_is_refused_and_the_first_kept() -> None:
    registry = TenantPurgeParticipantRegistry()
    first = _FakeParticipant("dup")
    registry.register(first)
    with pytest.raises(DuplicateTenantPurgeParticipantError) as raised:
        registry.register(_FakeParticipant("dup"))
    assert raised.value.name == "dup"
    assert isinstance(raised.value, ValueError)
    assert registry.entries() == (("dup", first),)


@pytest.mark.parametrize(
    "name",
    [
        "",
        " ",
        " leading-space",
        "trailing-space ",
        "Upper.case",
        "has space",
        ".leading-dot",
        "-leading-dash",
        "_leading-underscore",
        "tab\tinside",
        "new\nline",
        "naïve",
        "colon:inside",
        "a" * 101,
    ],
)
def test_a_name_outside_the_grammar_is_refused(name: str) -> None:
    registry = TenantPurgeParticipantRegistry()
    with pytest.raises(InvalidTenantPurgeParticipantError):
        registry.register(_FakeParticipant(name))
    assert registry.names() == ()


@pytest.mark.parametrize("name", [123, None, b"bytes.name"])
def test_a_name_that_is_not_a_string_is_refused(name: object) -> None:
    registry = TenantPurgeParticipantRegistry()
    with pytest.raises(InvalidTenantPurgeParticipantError):
        registry.register(_FakeParticipant(name))  # type: ignore[arg-type]
    assert registry.names() == ()


@pytest.mark.parametrize(
    "name", ["a", "0", "a" * 100, "my_product.items", "test.counting-participant"]
)
def test_a_name_inside_the_grammar_is_accepted(name: str) -> None:
    registry = TenantPurgeParticipantRegistry()
    registry.register(_FakeParticipant(name))
    assert registry.names() == (name,)


class _NoMethod:
    name = "no.method"


class _MethodNotCallable:
    name = "not.callable"
    purge_tenant_data = "not a function"


@pytest.mark.parametrize("candidate", [object(), _NoMethod(), _MethodNotCallable(), None])
def test_an_object_that_is_not_a_participant_is_refused(candidate: object) -> None:
    registry = TenantPurgeParticipantRegistry()
    with pytest.raises(InvalidTenantPurgeParticipantError):
        registry.register(candidate)  # type: ignore[arg-type]
    assert registry.names() == ()


class _ShiftingName:
    """A `name` that changes after registration: the registry must keep and
    report the value it validated."""

    def __init__(self) -> None:
        self.reads = 0

    @property
    def name(self) -> str:
        self.reads += 1
        return "stable.name" if self.reads == 1 else "Changed Name"

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None:
        pass


def test_the_name_is_read_once_and_stored_at_registration() -> None:
    registry = TenantPurgeParticipantRegistry()
    participant = _ShiftingName()
    registry.register(participant)
    assert registry.names() == ("stable.name",)
    assert registry.entries() == (("stable.name", participant),)


def test_entries_is_a_snapshot_in_registration_order() -> None:
    registry = TenantPurgeParticipantRegistry()
    first, second, third = (_FakeParticipant(n) for n in ("zeta", "alpha", "mid"))
    registry.register(first)
    registry.register(second)
    snapshot = registry.entries()
    registry.register(third)
    assert snapshot == (("zeta", first), ("alpha", second))
    assert registry.names() == ("zeta", "alpha", "mid")
    assert registry.list() == [first, second, third]


# --- The public, process-wide functions -------------------------------------


@pytest.fixture
def isolated_default_registry(monkeypatch: pytest.MonkeyPatch) -> TenantPurgeParticipantRegistry:
    """Swap the process-wide registry for an empty one for this test only, so
    nothing registered here leaks into any other test."""
    fresh = TenantPurgeParticipantRegistry()
    monkeypatch.setattr(purge_participants, "_default_registry", fresh)
    return fresh


def test_the_public_api_is_exported_from_saas_os_core_tenancy() -> None:
    for name in (
        "TenantPurgeParticipant",
        "register_purge_participant",
        "registered_purge_participant_names",
        "DuplicateTenantPurgeParticipantError",
        "InvalidTenantPurgeParticipantError",
    ):
        assert name in tenancy.__all__, name
        assert getattr(tenancy, name) is getattr(purge_participants, name), name


def test_register_purge_participant_registers_in_the_process_wide_registry(
    isolated_default_registry: TenantPurgeParticipantRegistry,
) -> None:
    first, second = _FakeParticipant("product.first"), _FakeParticipant("product.second")
    assert registered_purge_participant_names() == ()
    assert register_purge_participant(first) is first
    register_purge_participant(second)
    register_purge_participant(first)  # the same object again: no-op
    assert registered_purge_participant_names() == ("product.first", "product.second")
    assert default_registry() is isolated_default_registry
    assert isolated_default_registry.list() == [first, second]


def test_register_purge_participant_refuses_a_collision_and_an_invalid_participant(
    isolated_default_registry: TenantPurgeParticipantRegistry,
) -> None:
    register_purge_participant(_FakeParticipant("product.items"))
    with pytest.raises(DuplicateTenantPurgeParticipantError):
        register_purge_participant(_FakeParticipant("product.items"))
    with pytest.raises(InvalidTenantPurgeParticipantError):
        register_purge_participant(_FakeParticipant("Product Items"))
    assert registered_purge_participant_names() == ("product.items",)


def test_the_isolation_fixture_leaves_the_real_registry_untouched(
    isolated_default_registry: TenantPurgeParticipantRegistry,
) -> None:
    """Non-vacuity for the fixture above: what a test registers lands in the
    swapped registry, never in the module's original one."""
    original = purge_participants.__dict__["_default_registry"]
    assert original is isolated_default_registry
    register_purge_participant(_FakeParticipant("only.here"))
    assert "only.here" in isolated_default_registry.names()


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
