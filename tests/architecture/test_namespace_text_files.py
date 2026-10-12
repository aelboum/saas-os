"""The `saas_os` import root in everything that is not Python
(docs/ADR/0038-...): container, Compose, CI, systemd and shell files, and
Python carried inside them.

`test_namespace_contract.py` scans Python `import` statements (and
`pyproject.toml`). A
`python -m api.worker` in a Compose file, or `from core import x` inside a
shell heredoc, is invisible to it and fails only when that file is run.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FORMER = "api|contracts|control_plane|core|infra"

_PATTERNS = {
    "python -m <former root>": re.compile(rf"python[\d.]*\s+-m\s+(?:{_FORMER})(?:\.|\s|$)"),
    '"-m", "<former root>…"': re.compile(rf"""["']-m["']\s*,\s*["'](?:{_FORMER})(?:\.|["'])"""),
    "import of a former root": re.compile(
        rf"(?m)^[ \t]*(?:from|import)[ \t]+(?:{_FORMER})(?:\.|[ \t]|$)"
    ),
    "COPY of a former directory": re.compile(
        r"(?m)^COPY\s+(?:--\S+\s+)*(?:api|contracts|control-plane|core|infra)\s"
    ),
    "path into a former directory": re.compile(
        r"(?:(?<![\w/.\-])|(?<=\./)|(?<=\)s/)|(?<=\}/))(?:core|infra|api|contracts|control-plane)/"
        r"(?:db|jobs|billing|identity|tenancy|rbac|worker|server|main|edge|control_plane)\b"
    ),
}


def _text_files() -> list[Path]:
    files = [
        _REPO_ROOT / "Dockerfile",
        _REPO_ROOT / "docker-compose.yml",
        _REPO_ROOT / "docker-compose.prod.yml",
        _REPO_ROOT / "alembic.ini",
        _REPO_ROOT / ".github" / "workflows" / "ci.yml",
    ]
    files += sorted((_REPO_ROOT / "scripts").glob("*.sh"))
    files += sorted(
        p
        for p in (_REPO_ROOT / "deploy").rglob("*")
        if p.is_file() and p.suffix not in {".py", ".pyc"}
    )
    files += sorted(p for p in (_REPO_ROOT / "local-dev").glob("*") if p.suffix in {".yml", ".md"})
    return files


def test_the_scan_covers_the_runtime_configuration() -> None:
    names = {p.name for p in _text_files()}
    assert {"Dockerfile", "docker-compose.yml", "docker-compose.prod.yml", "ci.yml"} <= names
    assert "check-docker.sh" in names and len(names) >= 15
    assert all(p.exists() for p in _text_files())


@pytest.mark.parametrize("path", _text_files(), ids=lambda p: p.relative_to(_REPO_ROOT).as_posix())
def test_no_runtime_file_refers_to_a_former_root(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    found = [
        f"{kind}: {match.group(0).strip()!r}"
        for kind, pattern in _PATTERNS.items()
        for match in pattern.finditer(text)
    ]
    assert found == []


@pytest.mark.parametrize(
    "line",
    [
        'command: ["python", "-m", "api.worker"]',
        "CMD python -m api.server",
        "    python3.13 -m infra.db.backup",
        "from core.tenancy import create_tenant",
        "    import infra.db",
        "COPY core ./core",
        "COPY --chown=app:app control-plane ./control-plane",
        "script_location = %(here)s/infra/db/migrations",
        "      - ./infra/edge/assets/Caddyfile.local-edge:/etc/caddy/Caddyfile:ro",
        "bash infra/db/init/01-create-app-role.sh",
        "  - ${REPO_ROOT_HOST}/infra/db/init/01-create-app-role.sh:/initdb.d/x:ro",
    ],
)
def test_the_patterns_catch_each_former_form(line: str) -> None:
    assert any(pattern.search(line) for pattern in _PATTERNS.values()), line


@pytest.mark.parametrize(
    "line",
    [
        'command: ["python", "-m", "saas_os.api.worker"]',
        "from saas_os.core.tenancy import create_tenant",
        "COPY saas_os ./saas_os",
        "script_location = %(here)s/saas_os/infra/db/migrations",
        "bash saas_os/infra/db/init/01-create-app-role.sh",
        "pytest tests/core/billing tests/infra/db",
        "https://example.test/api/v1/things",
    ],
)
def test_the_patterns_accept_the_current_forms(line: str) -> None:
    assert not any(pattern.search(line) for pattern in _PATTERNS.values()), line
