"""The two provider SDKs that only one adapter needs -- `stripe`
(`saas_os/core/billing/stripe_provider.py`) and `boto3`
(`saas_os/infra/db/backup/destination.py`) -- are optional dependencies
(docs/ADR/0041-dependency-and-packaging-modularity.md, docs/P-ROADMAP.md P5).

Three properties make that safe, and each is pinned here:

1. importing the platform never loads either SDK;
2. using an adapter without its SDK fails at the adapter boundary with an
   `ImportError` that names the extra to install -- not with a bare "No
   module named ..." from inside a billing or backup call;
3. the extras carry exactly the version constraints the packages had as
   mandatory dependencies, and this repository's own `dev` extra still
   installs both, so the test suite and `pip-audit` keep covering them.

Each probe runs in a fresh interpreter: in this process another test may
already have imported either SDK. The real minimal-install proof (a wheel
installed with no extra, then with each extra) is
`tests/test_wheel_contents.py`, under the `packaging` marker.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

_PYPROJECT = tomllib.loads(
    (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
)

_PROBE = """
import sys

import saas_os.api.platform
import saas_os.core.billing
import saas_os.infra.db.backup

loaded = sorted(name for name in ("stripe", "boto3", "botocore") if name in sys.modules)
print(",".join(loaded))
"""

_MISSING_STRIPE = """
import sys

sys.modules["stripe"] = None  # what an environment without the extra looks like

from saas_os.core.billing.service import _default_provider

try:
    _default_provider()
except ModuleNotFoundError as exc:
    print(exc.name, "|", exc.msg)
"""

_MISSING_BOTO3 = """
import sys

sys.modules["boto3"] = None

from saas_os.infra.db.backup.destination import S3CompatibleBackupDestination

try:
    S3CompatibleBackupDestination()
except ModuleNotFoundError as exc:
    print(exc.name, "|", exc.msg)
"""

_PLATFORM_WITHOUT_EITHER = """
import sys

sys.modules["stripe"] = None
sys.modules["boto3"] = None

import saas_os.api.platform
import saas_os.core.billing
import saas_os.core.usage
import saas_os.infra.db.backup
from saas_os.core.billing import FakeBillingProvider

print("ok")
"""


def _run(probe: str) -> str:
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


# --- 1. the platform never loads either SDK ---------------------------------------------


def test_importing_the_platform_does_not_import_the_stripe_or_s3_sdk() -> None:
    assert _run(_PROBE) == ""


def test_the_probe_would_see_an_eager_import() -> None:
    """Not vacuous: the same probe reports an SDK once something imports it."""
    probe = _PROBE.replace(
        "import saas_os.infra.db.backup", "import saas_os.infra.db.backup\nimport stripe"
    )
    assert _run(probe) == "stripe"


def test_the_platform_imports_when_neither_sdk_is_installed() -> None:
    assert _run(_PLATFORM_WITHOUT_EITHER) == "ok"


# --- 2. a missing SDK fails at the adapter boundary, naming the extra --------------------


def test_the_stripe_adapter_without_its_sdk_names_the_extra_to_install() -> None:
    name, _, message = _run(_MISSING_STRIPE).partition(" | ")
    assert name == "stripe"
    assert 'install "saas-os[stripe]"' in message


def test_the_s3_destination_without_its_sdk_names_the_extra_to_install() -> None:
    name, _, message = _run(_MISSING_BOTO3).partition(" | ")
    assert name == "boto3"
    assert 'install "saas-os[s3-backup]"' in message


# --- 3. packaging metadata ----------------------------------------------------------------


def _names(requirements: list[str]) -> set[str]:
    return {r.split(">")[0].split("=")[0].split("[")[0].strip().lower() for r in requirements}


def test_neither_sdk_is_a_mandatory_dependency() -> None:
    assert not _names(_PYPROJECT["project"]["dependencies"]) & {"stripe", "boto3", "botocore"}


def test_the_extras_keep_the_original_version_constraints() -> None:
    extras = _PYPROJECT["project"]["optional-dependencies"]
    assert extras["stripe"] == ["stripe>=11.0"]
    assert extras["s3-backup"] == ["boto3>=1.34"]
    assert sorted(extras["all"]) == sorted(extras["stripe"] + extras["s3-backup"])


def test_the_development_extra_still_installs_both_sdks() -> None:
    """The suite exercises both adapters and `pip-audit` scans the
    development environment: optional for consumers, never unscanned here."""
    dev = _PYPROJECT["project"]["optional-dependencies"]["dev"]
    assert {"stripe>=11.0", "boto3>=1.34"} <= set(dev)


def test_development_tools_are_not_runtime_dependencies() -> None:
    runtime = _names(_PYPROJECT["project"]["dependencies"])
    tools = {"pytest", "ruff", "pyright", "import-linter", "pip-audit", "detect-secrets"}
    assert not runtime & tools
