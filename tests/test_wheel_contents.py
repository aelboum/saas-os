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

import os
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
    "saas_os/core/__init__.py",
    "saas_os/core/tenancy/__init__.py",
    "saas_os/core/billing/__init__.py",
    "saas_os/core/crypto/__init__.py",
    "saas_os/core/rbac/__init__.py",
    "saas_os/core/identity/__init__.py",
    "saas_os/infra/__init__.py",
    "saas_os/infra/db/__init__.py",
    "saas_os/infra/db/backup/__init__.py",
    "saas_os/infra/jobs/__init__.py",
    # docs/LOCAL-IDENTITY.md: the `saas-os-local-identity` console script a
    # consuming project runs from its installed dependency.
    "saas_os/infra/local_identity/zitadel_bootstrap.py",
    # docs/ADR/0024-single-origin-application-runtime.md: the reusable
    # single-origin edge configuration `saas-os-edge-config` emits for a
    # consuming project -- package DATA, so it is exactly the kind of file a
    # `packages`-only list silently drops from a real wheel.
    "saas_os/infra/edge/cli.py",
    "saas_os/infra/edge/assets/Caddyfile.local-edge",
    # docs/AUTO-UPDATE-CLI.md: the `saas-os-update` console script.
    "saas_os/infra/update/cli.py",
    "saas_os/infra/update/policy.py",
    "saas_os/infra/secrets/__init__.py",
    "saas_os/control_plane/__init__.py",
    "saas_os/control_plane/orchestration/__init__.py",
    "saas_os/control_plane/approvals/__init__.py",
    "saas_os/control_plane/self_learning/__init__.py",
    "saas_os/control_plane/self_learning/adaptive/__init__.py",
    "saas_os/control_plane/tools/__init__.py",
    "saas_os/contracts/__init__.py",
    "saas_os/api/__init__.py",
    "saas_os/api/platform.py",
    "saas_os/api/auth/__init__.py",
    "saas_os/api/v1/__init__.py",
    "saas_os/infra/db/migrations/env.py",
    "saas_os/infra/db/migrations/script.py.mako",
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
        p.name
        for p in (REPO_ROOT / "saas_os" / "infra" / "db" / "migrations" / "versions").glob("*.py")
    }
    shipped_versions = {
        Path(n).name
        for n in names
        if n.startswith("saas_os/infra/db/migrations/versions/") and n.endswith(".py")
    }
    assert shipped_versions == real_source_versions


# docs/ADR/0038-package-namespace-and-public-import-contract.md: the
# top-level import names the distribution owns are public contract -- a
# consumer must not reuse any of them. Pinned here so that a change to the
# set is a deliberate decision, never a side effect of adding a directory.
_TOP_LEVEL_IMPORT_NAMES = {"saas_os"}


def test_wheel_owns_exactly_the_documented_top_level_import_names(built_wheel: Path) -> None:
    with zipfile.ZipFile(built_wheel) as zf:
        top_level = {
            name.split("/")[0].removesuffix(".py")
            for name in zf.namelist()
            if not name.split("/")[0].endswith(".dist-info")
        }
    assert top_level == _TOP_LEVEL_IMPORT_NAMES


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
        "import saas_os.core.tenancy, saas_os.core.billing, saas_os.core.rbac, "
        "saas_os.infra.db, saas_os.infra.db.backup, "
        "saas_os.infra.jobs, saas_os.infra.secrets, saas_os.control_plane.orchestration, "
        "saas_os.control_plane.self_learning.adaptive, saas_os.contracts, "
        "saas_os.api.platform, saas_os.api.auth; "
        "from saas_os.infra.db.migration_runner import core_head_revision; "
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


# --- docs/ADR/0041-dependency-and-packaging-modularity.md: optional provider SDKs --------

_SDK_STATE = (
    "import importlib.util as u; "
    "print(int(u.find_spec('stripe') is not None), int(u.find_spec('boto3') is not None))"
)
_PLATFORM_IMPORTS = (
    "import saas_os.api.platform, saas_os.api.worker, saas_os.core.billing, saas_os.core.usage, "
    "saas_os.infra.db.backup, saas_os.control_plane.orchestration; print('ok')"
)
_STRIPE_ADAPTER = (
    "from saas_os.core.billing.service import _default_provider\n"
    "try:\n"
    "    _default_provider()\n"
    "except ModuleNotFoundError as exc:\n"
    "    print('missing', exc.name, exc.msg)\n"
    "except Exception as exc:\n"
    "    print('importable', type(exc).__name__)\n"
)
_S3_ADAPTER = (
    "from saas_os.infra.db.backup.destination import S3CompatibleBackupDestination\n"
    "try:\n"
    "    S3CompatibleBackupDestination()\n"
    "except ModuleNotFoundError as exc:\n"
    "    print('missing', exc.name, exc.msg)\n"
    "except Exception as exc:\n"
    "    print('importable', type(exc).__name__)\n"
)


def test_wheel_declares_the_provider_extras_and_no_mandatory_provider_sdk(
    built_wheel: Path,
) -> None:
    with zipfile.ZipFile(built_wheel) as zf:
        (metadata_name,) = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")]
        metadata = zf.read(metadata_name).decode("utf-8").splitlines()
    extras = {line.split(": ", 1)[1] for line in metadata if line.startswith("Provides-Extra: ")}
    assert {"stripe", "s3-backup", "all"} <= extras
    requires = [line.split(": ", 1)[1] for line in metadata if line.startswith("Requires-Dist: ")]
    unconditional = [r for r in requires if "extra ==" not in r]
    assert not [r for r in unconditional if r.lower().startswith(("stripe", "boto3"))]
    assert [r for r in requires if r.startswith("stripe>=11.0") and 'extra == "stripe"' in r]
    assert [r for r in requires if r.startswith("boto3>=1.34") and 'extra == "s3-backup"' in r]


def test_minimal_install_has_neither_provider_sdk_and_each_extra_adds_exactly_its_own(
    built_wheel: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """One isolated venv, three installs of the same wheel file: no extra,
    then `[stripe]`, then `[s3-backup]`. After each, which SDK is present,
    that the platform imports, and what each adapter does."""
    venv_dir = tmp_path_factory.mktemp("venv-extras")
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
    venv_python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    # The adapters read configuration only after the SDK import, so a
    # missing-secret error means "the SDK imported", never a false pass.
    env = {k: v for k, v in os.environ.items() if not k.startswith(("STRIPE_", "BACKUP_"))}
    env["ENVIRONMENT"] = "test"

    def run(code: str) -> str:
        result = subprocess.run(
            [str(venv_python), "-c", code],
            cwd=str(venv_dir),
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout.strip()

    def install(extra: str) -> None:
        result = subprocess.run(
            [str(venv_python), "-m", "pip", "install", f"{built_wheel}{extra}"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    install("")
    assert run(_SDK_STATE) == "0 0"
    assert run(_PLATFORM_IMPORTS) == "ok"
    assert run(_STRIPE_ADAPTER).startswith("missing stripe")
    assert 'install "saas-os[stripe]"' in run(_STRIPE_ADAPTER)
    assert 'install "saas-os[s3-backup]"' in run(_S3_ADAPTER)

    install("[stripe]")
    assert run(_SDK_STATE) == "1 0"
    assert run(_STRIPE_ADAPTER).startswith("importable")
    assert run(_S3_ADAPTER).startswith("missing boto3")

    install("[s3-backup]")
    assert run(_SDK_STATE) == "1 1"
    assert run(_S3_ADAPTER).startswith("importable")
    assert run(_PLATFORM_IMPORTS) == "ok"
