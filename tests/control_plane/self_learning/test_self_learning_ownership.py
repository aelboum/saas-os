"""Ownership/schema-consistency tests for docs/IMPLEMENTATION-ROADMAP.md
Phase 9.1 (`control_plane.self_learning` -- Learning Foundation).

Mirrors Phase 1.1's "every top-level module directory declares its
owner/layer" check, extended per Phase 9.1's own Tests bullet: confirm
`control_plane.self_learning` declares a schema/table-prefix distinct
from `core.*`. Phase 9.2 added real Learning Authorization code
(`models.py`, `service.py`) to this package -- see
`test_learning_authorization_unit.py` for its own tests -- but the
no-persistence guarantee these tests prove still holds and is now
checked across every file in the package, not just `__init__.py`.
"""

from __future__ import annotations

import ast
from pathlib import Path

import control_plane.self_learning as self_learning

REPO_ROOT = Path(__file__).resolve().parents[3]
SELF_LEARNING_INIT = REPO_ROOT / "control-plane" / "control_plane" / "self_learning" / "__init__.py"


def test_self_learning_package_importable() -> None:
    assert self_learning.SELF_LEARNING_MARKER == "self_learning"


def test_self_learning_declares_schema_distinct_from_core() -> None:
    """Phase 9.1's own Tests bullet, verbatim: the package must declare a
    schema/table-prefix distinct from `core.*`."""
    schema = self_learning.SCHEMA_NAME
    assert isinstance(schema, str) and schema
    assert schema != "core"
    assert not schema.startswith("core.")


def test_self_learning_schema_distinct_from_control_plane_approvals_schema() -> None:
    """docs/DATA-ARCHITECTURE.md section 1: each module owns a distinct
    namespace. `control_plane.approvals`'s `ApprovalRequest` table uses
    the `control_plane` schema (docs/IMPLEMENTATION-ROADMAP.md Phase 7.2)
    -- self-learning's future Learning Ledger must not silently collide
    with it."""
    assert self_learning.SCHEMA_NAME != "control_plane"


def test_self_learning_declares_ai_control_plane_layer_ownership() -> None:
    """Documentation/ownership-consistency check, mirroring Phase 1.1's
    "every top-level module directory declares its owner/layer" -- the
    package docstring must identify its layer as AI Control Plane, never
    SaaS Core (docs/ARCHITECTURE.md sections 1-2)."""
    doc = self_learning.__doc__ or ""
    assert "AI Control Plane" in doc
    assert "never SaaS Core" in doc or "never `core`" in doc.lower()


def test_self_learning_package_defines_no_orm_table_or_migration_yet() -> None:
    """Non-vacuous proof of Phase 9.1/9.2's Non-Goals ("no database
    migration, no table, no runtime Learning Ledger implementation"):
    statically parse *every* module in the package (not just
    `__init__.py` -- Phase 9.2 added `models.py`/`service.py`) and confirm
    none defines `__tablename__` or imports ORM/SQLAlchemy machinery --
    unlike `control_plane.approvals.models`, which does both for its real
    table."""
    package_dir = SELF_LEARNING_INIT.parent
    py_files = sorted(package_dir.glob("*.py"))
    assert (
        len(py_files) >= 3
    )  # __init__.py, models.py, service.py -- fails loudly if this list drifts

    for py_file in py_files:
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source)

        assigned_names: set[str] = set()
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned_names.add(target.id)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])

        assert "__tablename__" not in assigned_names, py_file.name
        assert "sqlalchemy" not in imported_modules, py_file.name

    migrations_dir = REPO_ROOT / "control-plane" / "control_plane" / "self_learning" / "migrations"
    assert not migrations_dir.exists()


def test_self_learning_package_defines_no_secrets_access() -> None:
    """Phase 9.2's own rule: "No new secret-consuming call site may be
    introduced outside the existing SecretsProvider boundary" -- and this
    package needs none, since it makes no external-provider call. Statically
    confirm no module imports `infra.secrets` or reads `os.environ`."""
    package_dir = SELF_LEARNING_INIT.parent
    for py_file in sorted(package_dir.glob("*.py")):
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)
        assert not any(
            m == "infra.secrets" or m.startswith("infra.secrets.") for m in imported_modules
        ), py_file.name
        assert "os" not in imported_modules, py_file.name


def test_self_learning_directory_has_only_the_authorized_phase_9_2_modules() -> None:
    """Phase 9.2's exact, authorized addition to the Phase 9.1 scaffold:
    `models.py` (typed request/decision/policy/evidence shapes) and
    `service.py` (the Learning Authorization evaluator + audited
    entrypoint) -- nothing else (docs/IMPLEMENTATION-ROADMAP.md Phase 9.2's
    own Non-Goals: no evaluation framework, no L1/L2/L3, no
    experimentation, no policy gate)."""
    package_dir = SELF_LEARNING_INIT.parent
    files = sorted(
        p.name
        for p in package_dir.iterdir()
        if p.is_file() and not p.name.startswith("__pycache__")
    )
    assert files == ["__init__.py", "models.py", "service.py"]
