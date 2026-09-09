"""Concrete `SecretsProvider` implementations (docs/ADR/0012-secrets-management.md).

Two implementations, matching the ADR's accepted initial deployment model
exactly -- no more:

- `EnvFileSecretsProvider` -- development. Reads a local `.env` file
  (never committed, gitignored -- docs/SECURITY.md section 4); an
  explicitly exported process-environment variable takes precedence over
  the file (the standard dotenv convention), so a var set ad hoc, e.g. by
  a test or a shell, still overrides the file's default.
- `EnvironmentSecretsProvider` -- Docker/host production. Reads secrets
  injected into the container's runtime environment at start-up: plain
  environment variables, or a Docker Compose `secrets:` file mount via
  the conventional `<NAME>_FILE` indirection (a path to a file whose
  content is the secret, per ADR-0012's "env vars or files mounted via
  Docker Compose secrets:").

Neither implementation ever caches or stores a *resolved* secret value on
the instance -- only `EnvFileSecretsProvider` holds a parsed dict of the
`.env` file's own contents (itself gitignored, local-only), and only for
the lifetime of the process. Both providers override `__repr__` so an
accidental `repr()`/log/exception never reveals a value (docs/SECURITY.md).

This module is intentionally not part of the public `infra.secrets`
import surface -- see `infra/secrets/__init__.py` and pyproject.toml's
"Only infra/secrets may import its own concrete provider implementations"
import-linter contract.
"""

from __future__ import annotations

import os
from pathlib import Path

from infra.secrets.provider import SecretsConfigurationError, SecretsProvider


def _parse_env_file(path: Path) -> dict[str, str]:
    """Minimal `KEY=VALUE` parser -- no external dependency needed for
    the handful of lines a local `.env` file holds (docs/IMPLEMENTATION-
    ROADMAP.md Phase 2.3 section 13: prefer zero new dependencies).
    Blank lines, `#` comments, and lines without `=` are skipped; a
    value's surrounding matching quotes (`'` or `"`) are stripped.
    """
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


class EnvFileSecretsProvider(SecretsProvider):
    """Development implementation: reads from a local `.env` file.

    The process environment is checked first, the file second -- the
    standard dotenv convention (an explicitly exported variable is a more
    deliberate override than a static file default), and what makes this
    implementation's behavior independent of whether a given developer
    machine happens to have created a local `.env` yet.
    """

    def __init__(self, path: str | Path = ".env") -> None:
        self._path = Path(path)
        self._values = _parse_env_file(self._path)

    def get(self, name: str) -> str | None:
        value = os.environ.get(name)
        if value is not None:
            return value
        return self._values.get(name)

    def __repr__(self) -> str:
        return f"EnvFileSecretsProvider(path={str(self._path)!r})"


class EnvironmentSecretsProvider(SecretsProvider):
    """Docker/host production implementation: reads secrets injected into
    the container's runtime environment at start-up.
    """

    def get(self, name: str) -> str | None:
        value = os.environ.get(name)
        if value is not None:
            return value
        return self._read_file_mount(name)

    def _read_file_mount(self, name: str) -> str | None:
        # Docker Compose `secrets:` convention: `<NAME>_FILE` names a
        # mounted file whose content is the secret value.
        file_path = os.environ.get(f"{name}_FILE")
        if not file_path:
            return None
        try:
            return Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SecretsConfigurationError(
                f"Secret file mount for {name!r} (from {name}_FILE) could not be read."
            ) from exc

    def __repr__(self) -> str:
        return "EnvironmentSecretsProvider()"
