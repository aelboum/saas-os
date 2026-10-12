"""The `saas_os` import root (docs/ADR/0038-package-namespace-and-public-import-contract.md).

The distribution installs exactly one top-level import name. Before
ADR-0038 it installed five generic ones -- `api`, `contracts`,
`control_plane`, `core`, `infra` -- which a consuming project's own `api/`
or `core/` directory silently shadowed. These tests keep that from coming
back: no such directory, no such import, no packaging entry and no
boundary contract may name the old roots.

`tests/test_wheel_contents.py` proves the same thing on a built wheel
(`packaging` marker); this module is the hermetic half.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ROOT = "saas_os"
_FORMER_ROOTS = ("api", "contracts", "control_plane", "core", "infra")
_FORMER_DIRECTORIES = ("api", "contracts", "control-plane", "control_plane", "core", "infra")
_PYPROJECT = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

_SCANNED = ("saas_os", "products", "tests", "examples", "scripts", "local-dev", "deploy")


def _python_files() -> list[Path]:
    files = [_REPO_ROOT / "conftest.py"]
    for top in _SCANNED:
        files += [p for p in (_REPO_ROOT / top).rglob("*.py") if "__pycache__" not in p.parts]
    return sorted(files)


def _former_root_imports(tree: ast.AST) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [
                (node.lineno, alias.name)
                for alias in node.names
                if alias.name.split(".")[0] in _FORMER_ROOTS
            ]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module.split(".")[0] in _FORMER_ROOTS:
                found.append((node.lineno, node.module))
    return found


# --- Layout ----------------------------------------------------------------------------


def test_no_former_top_level_package_directory_exists() -> None:
    present = [name for name in _FORMER_DIRECTORIES if (_REPO_ROOT / name).exists()]
    assert present == [], f"pre-ADR-0038 top-level directories are back: {present}"


def test_every_shipped_package_lives_under_the_one_root() -> None:
    packages = _PYPROJECT["tool"]["setuptools"]["packages"]
    assert _ROOT in packages
    assert [p for p in packages if p != _ROOT and not p.startswith(f"{_ROOT}.")] == []
    # No directory remapping: with one, the repository root could expose a
    # second import name for the same code.
    assert "package-dir" not in _PYPROJECT["tool"]["setuptools"]


def test_the_shipped_package_list_matches_the_packages_on_disk() -> None:
    on_disk = {
        ".".join(init.parent.relative_to(_REPO_ROOT).parts)
        for init in (_REPO_ROOT / _ROOT).rglob("__init__.py")
    }
    assert set(_PYPROJECT["tool"]["setuptools"]["packages"]) == on_disk


def test_console_scripts_and_package_data_use_the_one_root() -> None:
    for target in _PYPROJECT["project"]["scripts"].values():
        assert target.startswith(f"{_ROOT}."), target
    for package in _PYPROJECT["tool"]["setuptools"]["package-data"]:
        assert package.startswith(f"{_ROOT}."), package


# --- Imports ---------------------------------------------------------------------------


def test_nothing_imports_a_former_top_level_package() -> None:
    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        offenders += [
            f"{path.relative_to(_REPO_ROOT).as_posix()}:{lineno}: {module}"
            for lineno, module in _former_root_imports(tree)
        ]
    assert offenders == []


@pytest.mark.parametrize("root", _FORMER_ROOTS)
def test_the_import_scan_would_catch_a_former_root(root: str) -> None:
    """Not vacuous: each former root is reported in every import form."""
    source = f"import {root}\nimport {root}.x as y\nfrom {root} import z\nfrom {root}.x import z\n"
    assert [module for _, module in _former_root_imports(ast.parse(source))] == [
        root,
        f"{root}.x",
        root,
        f"{root}.x",
    ]


def test_a_relative_or_unrelated_import_is_not_reported() -> None:
    source = "from . import core\nfrom .api import x\nimport core_utils\nfrom apiary import y\n"
    assert _former_root_imports(ast.parse(source)) == []


# --- Boundary contracts stay non-vacuous -------------------------------------------------


def _module_exists(dotted: str) -> bool:
    path = _REPO_ROOT.joinpath(*dotted.split("."))
    return (path / "__init__.py").exists() or path.with_suffix(".py").exists()


def test_import_linter_roots_are_the_one_root_and_the_products_fixture() -> None:
    assert _PYPROJECT["tool"]["importlinter"]["root_packages"] == [_ROOT, "products"]


def test_every_first_party_module_named_by_a_boundary_contract_exists() -> None:
    """A `forbidden` contract whose `source_modules` names a module that does
    not exist checks nothing and still reports KEPT. After a rename that is
    the silent failure mode, so every first-party name must resolve."""
    missing = []
    for contract in _PYPROJECT["tool"]["importlinter"]["contracts"]:
        names = list(contract["source_modules"])
        names += [
            m for m in contract["forbidden_modules"] if m.split(".")[0] in (_ROOT, "products")
        ]
        for edge in contract.get("ignore_imports", []):
            names += [end.strip() for end in edge.split("->") if end.strip().startswith(_ROOT)]
        missing += [f"{contract['name']}: {name}" for name in names if not _module_exists(name)]
    assert missing == []


def test_no_boundary_contract_names_a_former_root() -> None:
    stale = []
    for contract in _PYPROJECT["tool"]["importlinter"]["contracts"]:
        for name in [*contract["source_modules"], *contract["forbidden_modules"]]:
            if name.split(".")[0] in _FORMER_ROOTS:
                stale.append(f"{contract['name']}: {name}")
    assert stale == []
