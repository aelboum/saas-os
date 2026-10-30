"""Living documents name only files and ADRs that exist (production-readiness
gate 15: "nothing checks the documents for staleness").

Checked: every backticked repository path in the documents people follow
today (guides, runbooks, security and readiness pages), and every `ADR-NNNN`
number in all of `docs/` and the README. A path abbreviated as
`docs/ADR/0015-...` must name an existing ADR number. The deferred-issue
ledger, the changelog, ADRs and dated evidence records are history: their
paths are what existed when they were written, so they are not checked
here. Glob patterns and placeholders (`*`, `<...>`) are skipped.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LIVING_DOCUMENTS = (
    "README.md",
    "docs/AI-CONTROL-PLANE.md",
    "docs/API-ARCHITECTURE.md",
    "docs/ARCHITECTURE.md",
    "docs/AUTO-UPDATE-CLI.md",
    "docs/BACKUP-RESTORE.md",
    "docs/CONSUMER-GUIDE.md",
    "docs/DATA-ARCHITECTURE.md",
    "docs/DEPLOYMENT-ARCHITECTURE.md",
    "docs/LOCAL-IDENTITY.md",
    "docs/MULTI-TENANCY.md",
    "docs/OBSERVABILITY.md",
    "docs/PRODUCTION-READINESS.md",
    "docs/RELEASING.md",
    "docs/RUNBOOKS.md",
    "docs/SECURITY.md",
    "docs/SINGLE-ORIGIN-RUNTIME.md",
)
_PATH = re.compile(
    r"`((?:saas_os|scripts|tests|docs|deploy|examples|\.github|frontend|local-dev)/[A-Za-z0-9_./-]+)`"
)
_ADR_PREFIX = re.compile(r"^docs/ADR/(\d{4})-$")
_ADR_NUMBERS = {path.name[:4] for path in (REPO_ROOT / "docs" / "ADR").glob("[0-9]" * 4 + "-*.md")}


def _missing_paths(text: str) -> list[str]:
    missing = []
    for match in _PATH.finditer(text):
        ref = match.group(1).split("::")[0].rstrip("/.")
        if "*" in ref or "<" in ref:
            continue
        prefix = _ADR_PREFIX.match(ref)
        if prefix:
            if prefix.group(1) not in _ADR_NUMBERS:
                missing.append(ref)
            continue
        if not (REPO_ROOT / ref).exists():
            missing.append(ref)
    return sorted(set(missing))


@pytest.mark.parametrize("document", LIVING_DOCUMENTS)
def test_every_path_in_a_living_document_exists(document: str) -> None:
    text = (REPO_ROOT / document).read_text(encoding="utf-8")
    assert not _missing_paths(text), _missing_paths(text)


def test_every_adr_number_cited_in_the_docs_exists() -> None:
    cited: dict[str, set[str]] = {}
    for path in [*sorted((REPO_ROOT / "docs").rglob("*.md")), REPO_ROOT / "README.md"]:
        for number in re.findall(r"ADR-(\d{4})", path.read_text(encoding="utf-8")):
            if number not in _ADR_NUMBERS:
                cited.setdefault(path.relative_to(REPO_ROOT).as_posix(), set()).add(number)
    assert not cited, cited


def test_the_check_sees_a_missing_path() -> None:
    """Not vacuous: a reference to a file that does not exist is reported."""
    assert _missing_paths("see `scripts/no-such-script.sh` and `docs/ADR/9999-...`") == [
        "docs/ADR/9999-",
        "scripts/no-such-script.sh",
    ]
