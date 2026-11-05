"""The test cleanup that TRUNCATEs the platform audit reference tables
(`tests/support/audit_references.py`) refuses a database that does not look
disposable, and does so before it connects."""

from __future__ import annotations

import pytest

from audit_references import assert_disposable_database, clear_platform_audit_references

_LOOPBACK = (
    "postgresql+psycopg://u:p@localhost:5432/saas_os",
    "postgresql+psycopg://u:p@127.0.0.1:60471/saas_os",
    "postgresql+psycopg://u:p@[::1]:5432/saas_os",
)
_REMOTE = (
    "postgresql+psycopg://u:p@db.internal:5432/saas_os",
    "postgresql+psycopg://u:p@10.0.0.7:5432/saas_os",
    "postgresql+psycopg://u:p@prod-db.example.com/saas_os",
    "postgresql+psycopg://u:p@/saas_os",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SAAS_OS_TEST_DATABASE_DISPOSABLE", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "test")


@pytest.mark.parametrize("url", _LOOPBACK)
def test_a_loopback_database_is_accepted(url: str) -> None:
    assert_disposable_database(url)


@pytest.mark.parametrize("url", _REMOTE)
def test_a_database_on_another_host_is_refused(url: str) -> None:
    with pytest.raises(RuntimeError, match="refusing to truncate"):
        assert_disposable_database(url)


def test_an_explicit_opt_in_accepts_a_remote_disposable_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SAAS_OS_TEST_DATABASE_DISPOSABLE", "1")
    assert_disposable_database(_REMOTE[0])


@pytest.mark.parametrize("environment", ["production", "staging", "test"])
def test_the_environment_name_does_not_decide(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    # Tests set ENVIRONMENT to production or staging on purpose while the
    # cleanup runs (CI found it); only the host decides.
    monkeypatch.setenv("ENVIRONMENT", environment)
    assert_disposable_database(_LOOPBACK[0])
    with pytest.raises(RuntimeError, match="refusing to truncate"):
        assert_disposable_database(_REMOTE[0])


def test_the_cleanup_refuses_before_it_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    import audit_references

    monkeypatch.setenv("MIGRATIONS_DATABASE_URL", _REMOTE[0])

    def no_engine() -> object:
        raise AssertionError("connected to a database that was refused")

    monkeypatch.setattr(audit_references, "_engine", no_engine)
    with pytest.raises(RuntimeError, match="refusing to truncate"):
        clear_platform_audit_references()


def test_the_cleanup_is_a_no_op_without_a_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIGRATIONS_DATABASE_URL", raising=False)
    clear_platform_audit_references()
