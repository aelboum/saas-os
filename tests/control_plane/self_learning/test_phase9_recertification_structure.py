"""Phase 9 re-certification (2026-10-21, docs/architecture/PHASE-9-RECERTIFICATION.md):
structural checks for three recovered requirements that the code met but no
test asserted.

- 9.3 Evaluation: no table and no access to tenant data beyond what the caller
  supplies -- the package defines no ORM model and never imports the database
  layer.
- 9.7 Policy Gate: decides, never activates, applies or promotes -- it imports
  no service that changes an adaptation, experiment or canary.
- 9.9 Continuous loop: produces seeds with zero mutations of the learning
  pipeline -- it imports no such service and never calls the Policy Gate.

Imports are read from the source with `ast`, recursively over each package,
so a module added later is covered too.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SELF_LEARNING = REPO_ROOT / "saas_os" / "control_plane" / "self_learning"
_PREFIX = "saas_os.control_plane.self_learning"

# The services that change persisted learning state (9.4 activation and
# rollback, 9.6 experiment runs, 9.8 canaries) and the 9.7 gate itself.
_MUTATING_SERVICES = (
    f"{_PREFIX}.adaptive.service",
    f"{_PREFIX}.experiments.service",
    f"{_PREFIX}.autonomous_improvement.service",
)
_POLICY_GATE_SERVICE = f"{_PREFIX}.policy_gate.service"
_DATABASE = ("sqlalchemy", "saas_os.infra.db")


def _imports(package: str) -> set[str]:
    modules: set[str] = set()
    files = sorted((SELF_LEARNING / package).rglob("*.py"))
    assert files, f"no source found for {package}"
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                modules.add(node.module)
                modules.update(f"{node.module}.{alias.name}" for alias in node.names)
    return modules


def _hits(imports: set[str], forbidden: tuple[str, ...]) -> list[str]:
    return sorted(m for m in imports if any(m == f or m.startswith(f + ".") for f in forbidden))


def test_evaluation_defines_no_table_and_never_reads_the_database() -> None:
    assert not _hits(_imports("evaluation"), _DATABASE)
    for path in (SELF_LEARNING / "evaluation").rglob("*.py"):
        assert "__tablename__" not in path.read_text(encoding="utf-8"), path


def test_policy_gate_never_imports_a_service_that_changes_learning_state() -> None:
    assert not _hits(_imports("policy_gate"), _MUTATING_SERVICES)


@pytest.mark.parametrize("forbidden", [*_MUTATING_SERVICES, _POLICY_GATE_SERVICE])
def test_continuous_loop_never_imports_a_mutating_service_or_the_gate(forbidden: str) -> None:
    assert not _hits(_imports("continuous_loop"), (forbidden,))


def test_the_checks_see_real_imports() -> None:
    """Guard against a vacuous pass: the parser finds imports these packages
    are known to have, in the same forms the checks above look for."""
    assert f"{_PREFIX}.service" in _imports("policy_gate")
    assert _hits(_imports("continuous_loop"), _DATABASE)
    assert f"{_PREFIX}.adaptive.models" in _imports("continuous_loop")
