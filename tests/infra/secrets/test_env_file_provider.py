"""`EnvFileSecretsProvider` -- development implementation
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.3, docs/ADR/0012-secrets-management.md).

Uses clearly fake test values throughout -- never a realistic-looking
credential (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3 section 11).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from infra.secrets.providers import EnvFileSecretsProvider


def _write_env_file(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_reads_a_value_from_the_env_file(tmp_path: Path) -> None:
    env_file = _write_env_file(tmp_path / ".env", "FAKE_SECRET=fake-value-abc\n")
    provider = EnvFileSecretsProvider(path=env_file)
    assert provider.get("FAKE_SECRET") == "fake-value-abc"


def test_missing_key_returns_none(tmp_path: Path) -> None:
    env_file = _write_env_file(tmp_path / ".env", "OTHER_KEY=whatever\n")
    provider = EnvFileSecretsProvider(path=env_file)
    assert provider.get("NOT_IN_FILE") is None


def test_missing_file_does_not_crash(tmp_path: Path) -> None:
    provider = EnvFileSecretsProvider(path=tmp_path / "does-not-exist.env")
    assert provider.get("ANYTHING") is None


def test_blank_lines_and_comments_are_skipped(tmp_path: Path) -> None:
    env_file = _write_env_file(
        tmp_path / ".env",
        "\n# a comment\nFAKE_SECRET=value-1\n\n# another comment\nOTHER=value-2\n",
    )
    provider = EnvFileSecretsProvider(path=env_file)
    assert provider.get("FAKE_SECRET") == "value-1"
    assert provider.get("OTHER") == "value-2"


def test_surrounding_quotes_are_stripped(tmp_path: Path) -> None:
    env_file = _write_env_file(
        tmp_path / ".env",
        "DOUBLE_QUOTED=\"value-with-spaces\"\nSINGLE_QUOTED='other-value'\n",
    )
    provider = EnvFileSecretsProvider(path=env_file)
    assert provider.get("DOUBLE_QUOTED") == "value-with-spaces"
    assert provider.get("SINGLE_QUOTED") == "other-value"


def test_falls_back_to_the_process_environment_when_not_in_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A var not defined in `.env` (e.g. exported ad hoc, or set by a test)
    still resolves -- the file is the primary source, not the only one.
    """
    env_file = _write_env_file(tmp_path / ".env", "IN_FILE=from-file\n")
    monkeypatch.setenv("FROM_ENVIRON", "from-environ")
    provider = EnvFileSecretsProvider(path=env_file)
    assert provider.get("FROM_ENVIRON") == "from-environ"


def test_process_environment_takes_precedence_over_file_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicitly exported variable overrides the file's static
    default -- the standard dotenv convention, and what keeps this
    provider's behavior independent of whatever a given developer
    machine's own local `.env` happens to contain.
    """
    env_file = _write_env_file(tmp_path / ".env", "SAME_KEY=from-file\n")
    monkeypatch.setenv("SAME_KEY", "from-environ")
    provider = EnvFileSecretsProvider(path=env_file)
    assert provider.get("SAME_KEY") == "from-environ"


def test_repr_does_not_leak_values(tmp_path: Path) -> None:
    env_file = _write_env_file(tmp_path / ".env", "FAKE_SECRET=fake-value-abc\n")
    provider = EnvFileSecretsProvider(path=env_file)
    assert "fake-value-abc" not in repr(provider)
    assert "fake-value-abc" not in str(provider)


def test_str_does_not_leak_values_via_default_object_str(tmp_path: Path) -> None:
    """`str()` falls back to `__repr__` when a class defines no `__str__`
    of its own -- confirm the object's default string form is also safe.
    """
    env_file = _write_env_file(tmp_path / ".env", "FAKE_SECRET=fake-value-abc\n")
    provider = EnvFileSecretsProvider(path=env_file)
    assert "fake-value-abc" not in f"{provider}"
