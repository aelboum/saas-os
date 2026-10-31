"""`constraints.txt` (ADR-0041 amendment of 2026-10-31): the exact versions
CI and the Dockerfile image install.

It must be well formed, cover every package pyproject.toml declares, and
satisfy pyproject.toml's own specifiers, so a stale or hand-edited file is
caught before CI resolves it; and every install of the repository in CI
and in the image must use it.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[2]
CONSTRAINTS = REPO_ROOT / "constraints.txt"
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9.+!-]*)$")


def _pins() -> dict[str, Version]:
    pins: dict[str, Version] = {}
    for line in CONSTRAINTS.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        match = _PIN.match(line)
        assert match, f"not a name==version line: {line!r}"
        name = canonicalize_name(match[1])
        assert name not in pins, f"{name} is pinned twice"
        pins[name] = Version(match[2])
    return pins


def _declared() -> list[Requirement]:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    requirements = list(project["dependencies"])
    for extra in ("all", "dev", "security"):
        requirements += project["optional-dependencies"][extra]
    return [Requirement(text) for text in requirements]


def test_every_line_is_a_comment_or_one_exact_pin_in_sorted_order() -> None:
    lines = [
        line
        for line in CONSTRAINTS.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    assert lines, "constraints.txt pins nothing"
    assert lines == sorted(lines, key=str.lower)
    _pins()


def test_the_file_never_pins_saas_os_itself_or_pip() -> None:
    pins = _pins()
    assert "saas-os" not in pins
    assert "pip" not in pins


def test_every_declared_package_is_pinned_within_its_specifier() -> None:
    pins = _pins()
    for requirement in _declared():
        name = canonicalize_name(requirement.name)
        assert name in pins, f"{name} is declared in pyproject.toml but not pinned"
        assert requirement.specifier.contains(pins[name], prereleases=True), (
            f"{name}=={pins[name]} does not satisfy pyproject.toml's {requirement}"
        )


def test_every_repository_install_in_ci_uses_the_constraints() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    installs = re.findall(r"pip install [^\n]*-e \"\.[^\n]*", workflow)
    assert len(installs) == 5, installs
    for line in installs:
        assert "-c constraints.txt" in line, line


def test_the_image_install_uses_the_constraints() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY pyproject.toml README.md constraints.txt ./" in dockerfile
    installs = re.findall(r"^RUN pip install [^\n]*", dockerfile, re.MULTILINE)
    assert installs == ['RUN pip install --no-cache-dir -c constraints.txt -e ".[all]"']


def test_the_regeneration_script_keeps_the_header_it_rewrites() -> None:
    text = CONSTRAINTS.read_text(encoding="utf-8")
    script = (REPO_ROOT / "scripts" / "update-constraints.sh").read_text(encoding="utf-8")
    assert text.startswith("# Exact versions")
    assert "# satisfies pyproject.toml.\n" in text
    assert "/^# Exact versions/,/^# satisfies pyproject.toml\\.$/p" in script
