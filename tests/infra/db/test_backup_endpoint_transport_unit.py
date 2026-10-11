"""ADR-0028 D4-B -- the endpoint transport for `saas_os.infra.db.backup`.

`docker exec` has no meaning for an operator-managed external PostgreSQL
(ADR-0028 D1): there is no container to exec into. These tests pin the
second transport's contract without a live server and without Docker --
`subprocess.run` is patched at the point `saas_os/infra/db/backup` imported it, so
what is asserted is the exact argv and child environment the module *would*
hand to `pg_dump`/`pg_restore`/`psql`.

The properties that matter here are security properties, not plumbing: the
operator's TLS mode must reach the client intact (never silently rewritten
to `require`), and neither the password nor any connection string may reach
argv, a log line, or an exception message.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from saas_os.infra.db import backup as backup_module
from saas_os.infra.db.backup import BackupError, RestoreError, create_backup, restore_backup
from saas_os.infra.db.config import DatabaseConfig

PASSWORD = "endpoint-only-password"  # pragma: allowlist secret
VERIFY_FULL_URL = (
    "postgresql+psycopg://saas_os:" + PASSWORD + "@db.internal.example:6432/saas_os"
    "?sslmode=verify-full&sslrootcert=/ca/managed.pem"
)
PLAIN_URL = "postgresql+psycopg://saas_os:" + PASSWORD + "@db.internal.example:6432/saas_os"


class _Recorder:
    """Stand-in for `subprocess.run` that records every invocation and
    reports success, writing a byte or two so the artifact is non-empty."""

    def __init__(self, returncode: int = 0, stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def __call__(
        self,
        cmd: list[str],
        *,
        env: dict[str, str],
        stdin: Any = None,
        stdout: Any = None,
        **kw: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((cmd, env))
        # `_run` passes `subprocess.PIPE` (an int) when the caller wants no
        # file; only a real file object gets the fake archive bytes.
        if hasattr(stdout, "write"):
            stdout.write(b"PGDMP fake archive bytes")
        return subprocess.CompletedProcess(cmd, self.returncode, b"", self.stderr)

    @property
    def last_cmd(self) -> list[str]:
        return self.calls[-1][0]

    @property
    def last_env(self) -> dict[str, str]:
        return self.calls[-1][1]


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(backup_module.subprocess, "run", rec)
    # Pretend the client tools are installed; their absence is its own test.
    monkeypatch.setattr(backup_module.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    return rec


def _config(url: str = VERIFY_FULL_URL) -> DatabaseConfig:
    return DatabaseConfig(url=url)


# --- the existing container transport must not shift ---------------------


def test_container_transport_still_uses_docker_exec(recorder: _Recorder, tmp_path: Path) -> None:
    """The bundled/local path is unchanged: still `docker exec`, still no
    TLS environment (it reaches PostgreSQL over the container's loopback)."""
    create_backup(container="saas-os-db-1", admin_config=_config(), output_dir=tmp_path)
    assert recorder.last_cmd[:3] == ["docker", "exec", "-e"]
    assert "pg_dump" in recorder.last_cmd
    assert "PGSSLMODE" not in recorder.last_env


# --- endpoint transport: invocation shape --------------------------------


def test_endpoint_backup_invokes_pg_dump_against_the_endpoint(
    recorder: _Recorder, tmp_path: Path
) -> None:
    create_backup(admin_config=_config(), output_dir=tmp_path)
    cmd = recorder.last_cmd
    assert cmd[0].endswith("pg_dump")
    assert "docker" not in cmd
    assert cmd[cmd.index("-h") + 1] == "db.internal.example"
    assert cmd[cmd.index("-p") + 1] == "6432"
    assert cmd[cmd.index("-d") + 1] == "saas_os"
    assert cmd[cmd.index("-U") + 1] == "saas_os"
    assert "-Fc" in cmd and "--no-password" in cmd


def test_endpoint_restore_invokes_pg_restore_against_the_endpoint(
    recorder: _Recorder, tmp_path: Path
) -> None:
    metadata = create_backup(admin_config=_config(), output_dir=tmp_path)
    restore_backup(
        admin_config=_config(),
        metadata_path=metadata.metadata_path,
        target_database="restore_target",
    )
    # psql CREATE DATABASE first, then pg_restore -- both over the endpoint.
    assert recorder.calls[-2][0][0].endswith("psql")
    assert 'CREATE DATABASE "restore_target"' in recorder.calls[-2][0]
    cmd = recorder.last_cmd
    assert cmd[0].endswith("pg_restore")
    assert "docker" not in cmd
    assert cmd[cmd.index("-d") + 1] == "restore_target"
    assert "--single-transaction" in cmd and "--exit-on-error" in cmd


# --- endpoint transport: TLS is forwarded, never decided ------------------


@pytest.mark.parametrize("sslmode", ["verify-full", "verify-ca", "require"])
def test_endpoint_forwards_the_configured_sslmode_unchanged(
    recorder: _Recorder, tmp_path: Path, sslmode: str
) -> None:
    """The operator's mode reaches libpq intact. A stronger mode is never
    downgraded to `require` for backup, which would silently make the
    backup connection weaker than the application's own (ADR-0028 D2)."""
    url = PLAIN_URL + f"?sslmode={sslmode}&sslrootcert=/ca/managed.pem"
    create_backup(admin_config=_config(url), output_dir=tmp_path)
    assert recorder.last_env["PGSSLMODE"] == sslmode


def test_endpoint_forwards_the_ca_and_client_certificate_paths(
    recorder: _Recorder, tmp_path: Path
) -> None:
    url = (
        PLAIN_URL + "?sslmode=verify-full&sslrootcert=/ca/managed.pem"
        "&sslcert=/certs/client.crt&sslkey=/certs/client.key"
    )
    create_backup(admin_config=_config(url), output_dir=tmp_path)
    env = recorder.last_env
    assert env["PGSSLROOTCERT"] == "/ca/managed.pem"
    assert env["PGSSLCERT"] == "/certs/client.crt"
    assert env["PGSSLKEY"] == "/certs/client.key"


def test_endpoint_restore_carries_the_same_tls_as_the_backup(
    recorder: _Recorder, tmp_path: Path
) -> None:
    """Restore is not a weaker path than backup: the CREATE DATABASE step
    and `pg_restore` both get the configured verification mode."""
    metadata = create_backup(admin_config=_config(), output_dir=tmp_path)
    restore_backup(
        admin_config=_config(),
        metadata_path=metadata.metadata_path,
        target_database="restore_target",
    )
    for _cmd, env in recorder.calls[-2:]:
        assert env["PGSSLMODE"] == "verify-full"
        assert env["PGSSLROOTCERT"] == "/ca/managed.pem"


def test_endpoint_adds_no_tls_settings_when_the_url_carries_none(
    recorder: _Recorder, tmp_path: Path
) -> None:
    """This module forwards policy, it does not invent it -- a URL with no
    `sslmode` (development, where `saas_os/infra/db/config.py` requires none) must
    not acquire one here."""
    create_backup(admin_config=_config(PLAIN_URL), output_dir=tmp_path)
    assert "PGSSLMODE" not in recorder.last_env


# --- endpoint transport: secrets stay out of argv ------------------------


def test_password_never_appears_in_argv(recorder: _Recorder, tmp_path: Path) -> None:
    create_backup(admin_config=_config(), output_dir=tmp_path)
    assert all(PASSWORD not in element for element in recorder.last_cmd)
    assert recorder.last_env["PGPASSWORD"] == PASSWORD


def test_connection_string_never_appears_in_argv(recorder: _Recorder, tmp_path: Path) -> None:
    create_backup(admin_config=_config(), output_dir=tmp_path)
    assert all("postgresql" not in element for element in recorder.last_cmd)


# --- endpoint transport: failures are actionable and never leak ----------


def test_missing_client_tool_is_an_actionable_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(backup_module.shutil, "which", lambda tool: None)
    with pytest.raises(BackupError) as excinfo:
        create_backup(admin_config=_config(), output_dir=tmp_path)
    message = str(excinfo.value)
    assert "pg_dump" in message and "PATH" in message
    assert "container=" in message  # points at the other transport
    assert PASSWORD not in message


def test_pg_dump_failure_propagates_without_leaking_the_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rec = _Recorder(returncode=1, stderr=b"FATAL: SSL certificate verification failed")
    monkeypatch.setattr(backup_module.subprocess, "run", rec)
    monkeypatch.setattr(backup_module.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    with pytest.raises(BackupError) as excinfo:
        create_backup(admin_config=_config(), output_dir=tmp_path)
    message = str(excinfo.value)
    assert "exit 1" in message
    assert "SSL certificate verification failed" in message  # actionable
    assert PASSWORD not in message


def test_a_url_without_a_host_is_refused_rather_than_guessed(
    recorder: _Recorder, tmp_path: Path
) -> None:
    """No implicit localhost: the endpoint transport connects where the
    configuration says, or not at all."""
    with pytest.raises(Exception) as excinfo:
        create_backup(
            admin_config=_config("postgresql+psycopg://saas_os@/saas_os"),
            output_dir=tmp_path,
        )
    assert "container=" in str(excinfo.value)


def test_missing_psql_during_endpoint_restore_raises_restore_error(
    recorder: _Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    metadata = create_backup(admin_config=_config(), output_dir=tmp_path)
    monkeypatch.setattr(backup_module.shutil, "which", lambda tool: None)
    with pytest.raises(RestoreError) as excinfo:
        restore_backup(
            admin_config=_config(),
            metadata_path=metadata.metadata_path,
            target_database="restore_target",
        )
    assert "psql" in str(excinfo.value)
