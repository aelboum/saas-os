"""Packaging regression test (SaaS OS packaging implementation phase):
proves a real, non-editable wheel actually ships every SaaS OS
subpackage and the migration environment -- the exact defect class the
original flat `packages = [...]` list silently produced (see
`pyproject.toml`'s own `[tool.setuptools]` comment: naming only six
top-level packages, with no nested entries, built wheels that silently
excluded every subpackage; `pip install -e .` never surfaced this because
an editable install exposes the whole source tree regardless of what
`packages` lists).

Marked `packaging`; excluded from the default `pytest` run (builds a real
wheel and creates a real venv via subprocesses -- slow, matching
`integration`/the `docker` job's own precedent of being kept out of the
fast default suite, docs/IMPLEMENTATION-ROADMAP.md). Run via
`scripts/check-packaging.sh` or `pytest -m packaging`.
"""

from __future__ import annotations

import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.packaging

REPO_ROOT = Path(__file__).resolve().parents[1]

# One representative path per SaaS OS subpackage/migration asset -- not
# exhaustive, but enough to catch a regression to the "top-level package
# name only, no nested subpackages" bug.
_EXPECTED_PATHS = [
    "core/__init__.py",
    "core/tenancy/__init__.py",
    "core/billing/__init__.py",
    "core/rbac/__init__.py",
    "core/identity/__init__.py",
    "infra/__init__.py",
    "infra/db/__init__.py",
    "infra/db/backup/__init__.py",
    "infra/jobs/__init__.py",
    "infra/secrets/__init__.py",
    "control_plane/__init__.py",
    "control_plane/orchestration/__init__.py",
    "control_plane/approvals/__init__.py",
    "control_plane/self_learning/__init__.py",
    "control_plane/self_learning/adaptive/__init__.py",
    "control_plane/tools/__init__.py",
    "contracts/__init__.py",
    "api/__init__.py",
    "api/platform.py",
    "api/auth/__init__.py",
    "api/v1/__init__.py",
    "infra/db/migrations/env.py",
    "infra/db/migrations/script.py.mako",
]

# ADR-0015 rule 11/12: `products/` must never be shipped as part of the
# `saas-os` package.
_FORBIDDEN_PATHS = ["products/__init__.py"]


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out_dir = tmp_path_factory.mktemp("wheel")
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(REPO_ROOT), "-w", str(out_dir), "--no-deps"],
        check=True,
        capture_output=True,
        text=True,
    )
    (wheel,) = out_dir.glob("saas_os-*.whl")
    return wheel


def test_wheel_contains_every_nested_subpackage(built_wheel: Path) -> None:
    with zipfile.ZipFile(built_wheel) as zf:
        names = set(zf.namelist())
    missing = [p for p in _EXPECTED_PATHS if p not in names]
    assert not missing, f"wheel is missing expected paths: {missing}"


def test_wheel_excludes_products(built_wheel: Path) -> None:
    with zipfile.ZipFile(built_wheel) as zf:
        names = set(zf.namelist())
    present = [p for p in _FORBIDDEN_PATHS if p in names]
    assert not present, f"wheel unexpectedly ships excluded paths: {present}"


def test_wheel_contains_every_migration_revision(built_wheel: Path) -> None:
    with zipfile.ZipFile(built_wheel) as zf:
        names = zf.namelist()
    real_source_versions = {
        p.name for p in (REPO_ROOT / "infra" / "db" / "migrations" / "versions").glob("*.py")
    }
    shipped_versions = {
        Path(n).name
        for n in names
        if n.startswith("infra/db/migrations/versions/") and n.endswith(".py")
    }
    assert shipped_versions == real_source_versions


def test_installed_wheel_is_importable_in_an_isolated_non_editable_environment(
    built_wheel: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """The critical, non-editable-install proof: a fresh venv, a real
    `pip install` of the wheel FILE (never `pip install -e .`, and never
    run from this repository's own working directory), then a real
    import of a representative set of nested modules -- proves the
    installed package's on-disk layout (not just the wheel's own zip
    listing) is actually importable, with dependencies resolved from the
    wheel's own declared metadata."""
    venv_dir = tmp_path_factory.mktemp("venv")
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
    venv_python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

    install_result = subprocess.run(
        [str(venv_python), "-m", "pip", "install", str(built_wheel)],
        capture_output=True,
        text=True,
    )
    assert install_result.returncode == 0, install_result.stdout + install_result.stderr

    probe = (
        "import core.tenancy, core.billing, core.rbac, infra.db, infra.db.backup, "
        "infra.jobs, infra.secrets, control_plane.orchestration, "
        "control_plane.self_learning.adaptive, contracts, api.platform, api.auth; "
        "from infra.db.migration_runner import core_head_revision; "
        "print(core_head_revision())"
    )
    result = subprocess.run(
        [str(venv_python), "-c", probe],
        cwd=str(venv_dir),  # never the repository root -- proves no source-tree fallback
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip()  # a real head revision id was printed
