"""`infra.db.tenant_session_scope()` input validation
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.1) -- the type check happens
before any database connection is attempted, so this needs no real
database (real RLS/isolation behavior is covered by
`tests/core/tenancy/test_tenant_isolation_integration.py`, marked
`integration`).
"""

from __future__ import annotations

import uuid

import pytest
from infra.db.session import tenant_session_scope


def test_rejects_a_plain_string_even_if_uuid_shaped() -> None:
    """A caller must pass a real uuid.UUID -- not a string -- so an
    arbitrary/malformed value (including something SQL-injection-shaped)
    cannot reach set_config() through this interface at all.
    """
    with pytest.raises(TypeError):
        with tenant_session_scope("11111111-1111-1111-1111-111111111111"):  # type: ignore[arg-type]
            pass


def test_rejects_a_sql_injection_shaped_string() -> None:
    malicious = "'; DROP TABLE core.tenants; --"
    with pytest.raises(TypeError):
        with tenant_session_scope(malicious):  # type: ignore[arg-type]
            pass


def test_rejects_none() -> None:
    with pytest.raises(TypeError):
        with tenant_session_scope(None):  # type: ignore[arg-type]
            pass


def test_error_message_names_the_offending_type_not_the_value() -> None:
    with pytest.raises(TypeError) as excinfo:
        with tenant_session_scope("not-a-uuid"):  # type: ignore[arg-type]
            pass
    assert "str" in str(excinfo.value)
    assert "not-a-uuid" not in str(excinfo.value)


def test_a_real_uuid_passes_the_type_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """The type check itself must not reject a genuine uuid.UUID. Fakes
    out `session_scope()` so this stays independent of DATABASE_URL/a
    real database -- real end-to-end behavior is covered by the
    integration suite.
    """
    from contextlib import contextmanager

    class _FakeSession:
        def __init__(self) -> None:
            self.executed: list[object] = []

        def execute(self, *args: object, **kwargs: object) -> None:
            self.executed.append((args, kwargs))

    calls: list[_FakeSession] = []

    @contextmanager
    def _fake_session_scope(*, session_factory: object = None):
        session = _FakeSession()
        calls.append(session)
        yield session

    monkeypatch.setattr("infra.db.session.session_scope", _fake_session_scope)

    real_uuid = uuid.uuid4()
    with tenant_session_scope(real_uuid) as session:
        assert session is calls[0]
    assert calls[0].executed  # set_config was called on the fake session
