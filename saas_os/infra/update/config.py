"""The consumer's updater configuration: `[tool.saas-os-update]` in its
`pyproject.toml` (docs/AUTO-UPDATE-CLI.md).

    [tool.saas-os-update]
    validation = [
        ["python", "-m", "pytest", "-q"],
        ["python", "-m", "ruff", "check", "."],
    ]
    timeout_seconds = 1800          # optional, per check
    pin_files = ["pyproject.toml"]  # optional; default: pyproject.toml and requirements files

Validation commands are argument vectors, never shell strings. The table
configures *what to run*; it cannot change the safety policy
(`saas_os/infra/update/policy.py`), which no consumer or candidate can override.
Parsing is strict: an unknown key or a wrong type is a malformed
configuration, which blocks an update rather than being ignored.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from saas_os.infra.update.pins import DEFAULT_PIN_FILES

_KEYS = frozenset({"validation", "timeout_seconds", "pin_files"})
_DEFAULT_TIMEOUT_SECONDS = 3600
_MAX_TIMEOUT_SECONDS = 24 * 3600


class ConfigError(ValueError):
    """The `[tool.saas-os-update]` table is malformed."""


@dataclass(frozen=True)
class UpdateConfig:
    validation: tuple[tuple[str, ...], ...] = ()
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS
    pin_files: tuple[str, ...] = DEFAULT_PIN_FILES
    configured: bool = field(default=False)


def load_config(root: Path) -> UpdateConfig:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return UpdateConfig()
    try:
        document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError("pyproject.toml is not valid TOML") from exc
    table = document.get("tool", {}).get("saas-os-update")
    if table is None:
        return UpdateConfig()
    if not isinstance(table, dict):
        raise ConfigError("[tool.saas-os-update] must be a table")
    unknown = sorted(set(table) - _KEYS)
    if unknown:
        raise ConfigError(f"unknown [tool.saas-os-update] key(s): {', '.join(unknown)}")

    validation = table.get("validation", [])
    if not isinstance(validation, list) or not all(
        isinstance(command, list)
        and command
        and all(isinstance(part, str) and part for part in command)
        for command in validation
    ):
        raise ConfigError("validation must be a list of non-empty argument lists of strings")

    timeout = table.get("timeout_seconds", _DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise ConfigError("timeout_seconds must be an integer")
    if not 1 <= timeout <= _MAX_TIMEOUT_SECONDS:
        raise ConfigError(f"timeout_seconds must be between 1 and {_MAX_TIMEOUT_SECONDS}")

    pin_files = table.get("pin_files", list(DEFAULT_PIN_FILES))
    if (
        not isinstance(pin_files, list)
        or not pin_files
        or not all(
            isinstance(item, str)
            and item
            and not item.startswith(("/", "\\"))
            and ".." not in item
            and ":" not in item
            for item in pin_files
        )
    ):
        raise ConfigError("pin_files must be a non-empty list of relative paths or patterns")

    return UpdateConfig(
        validation=tuple(tuple(command) for command in validation),
        timeout_seconds=timeout,
        pin_files=tuple(pin_files),
        configured=True,
    )
