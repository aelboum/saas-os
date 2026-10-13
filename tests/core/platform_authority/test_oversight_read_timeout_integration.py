"""The statement timeout of an oversight read, against a real PostgreSQL
(ADR-0045 section 9d). Both of the read's transactions carry it.

A second connection (the privileged test engine) holds the reader's own
`core.users` row `FOR NO KEY UPDATE`. Authorization takes that row
`FOR SHARE` and therefore waits; PostgreSQL cancels the statement when the
timeout expires. The lock is taken either before the call, so that the
attempt transaction waits, or between the two transactions, so that the
read transaction does. Nothing here sleeps to make a statement slow.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any

import pytest
from phase_c_helpers import P, Scene
from platform_helpers import PlatformWorld, join, start, wait_until_blocked_by
from sqlalchemy import text
from sqlalchemy.orm import Session

import saas_os.core.billing.oversight as oversight
import saas_os.core.platform_authority.audit as platform_audit
import saas_os.core.platform_authority.oversight as platform_oversight
import saas_os.core.tenancy.registry as registry
from saas_os.core.authority import UserCaller
from saas_os.core.billing import commercial_overview
from saas_os.core.platform_authority import OversightReadTimeoutError, get_oversight_read_config
from saas_os.core.tenancy import list_tenant_registry, read_tenant_registry_entry
from saas_os.infra.db import get_engine, set_local_statement_timeout

pytestmark = pytest.mark.integration

_TIMEOUT_MS = 300
_READS = ("registry", "entry", "overview")
_ACTION = {
    "registry": "platform.tenant.read",
    "entry": "platform.tenant.read",
    "overview": "platform.billing.read",
}
_OPERATION = {"registry": "tenant.read", "entry": "tenant.read", "overview": "billing.read"}
_PERMISSION = {"registry": P.TENANT_READ, "entry": P.TENANT_READ, "overview": P.BILLING_READ}
# The module whose `session_scope` opens the read transaction.
_MODULE = {"registry": registry, "entry": registry, "overview": oversight}


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS", str(_TIMEOUT_MS))
    get_oversight_read_config.cache_clear()
    yield
    get_oversight_read_config.cache_clear()


def _call(read: str, reader: UserCaller, tenant: uuid.UUID) -> Any:
    if read == "registry":
        return list_tenant_registry(caller=reader, limit=3)
    if read == "entry":
        return read_tenant_registry_entry(tenant, caller=reader)
    return commercial_overview(caller=reader, limit=3)


def _reader(platform: PlatformWorld, read: str) -> UserCaller:
    reader, _ = platform.operator([_PERMISSION[read]])
    platform.clear_audit()
    return reader


@contextmanager
def _user_row_locked(platform: PlatformWorld, user_id: uuid.UUID) -> Iterator[int]:
    """Hold the user's row on a second connection, in the mode that makes
    an authorization (`FOR SHARE`) wait but lets an audit row that names
    the user be inserted (its foreign key takes `FOR KEY SHARE`). Yields
    that connection's backend pid. Released on exit."""
    connection = platform.admin.connect()
    transaction = connection.begin()
    try:
        connection.execute(
            text("SELECT id FROM core.users WHERE id = :u FOR NO KEY UPDATE"), {"u": user_id}
        )
        yield connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
    finally:
        transaction.rollback()
        connection.close()


def _lock_when_the_read_transaction_opens(
    monkeypatch: pytest.MonkeyPatch,
    read: str,
    platform: PlatformWorld,
    user_id: uuid.UUID,
    held: ExitStack,
) -> None:
    """Take the lock after the attempt transaction has committed and just
    before the read transaction opens; it is released with `held`."""
    module = _MODULE[read]
    real = module.session_scope

    @contextmanager
    def scope() -> Iterator[Any]:
        held.enter_context(_user_row_locked(platform, user_id))
        with real() as session:
            yield session

    monkeypatch.setattr(module, "session_scope", scope)


def _committed(platform: PlatformWorld) -> list[tuple[str, str, str | None]]:
    """`(action, outcome, reason)` of every committed platform audit row."""
    return [(row["action"], row["outcome"], row["reason"]) for row in platform.audit()]


@pytest.mark.parametrize("read", _READS)
def test_an_attempt_that_waits_past_the_timeout_leaves_no_row_and_reads_nothing(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader = _reader(platform, read)
    opened = {"n": 0}
    real = _MODULE[read].session_scope

    @contextmanager
    def counted() -> Iterator[Any]:
        opened["n"] += 1
        with real() as session:
            yield session

    monkeypatch.setattr(_MODULE[read], "session_scope", counted)

    with (
        _user_row_locked(platform, reader.user_id),
        pytest.raises(OversightReadTimeoutError) as raised,
    ):
        _call(read, reader, tenant)

    assert raised.value.timeout_ms == _TIMEOUT_MS
    assert raised.value.operation == _OPERATION[read]
    assert raised.value.stage == "attempt"
    assert opened["n"] == 0  # the read transaction never opened
    assert platform.audit_count() == 0  # no row of any kind: nothing happened


@pytest.mark.parametrize("read", _READS)
def test_a_read_that_waits_past_the_timeout_is_cancelled_and_returns_nothing(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader = _reader(platform, read)

    with ExitStack() as held:
        _lock_when_the_read_transaction_opens(monkeypatch, read, platform, reader.user_id, held)
        with pytest.raises(OversightReadTimeoutError) as raised:
            _call(read, reader, tenant)

    assert raised.value.timeout_ms == _TIMEOUT_MS
    assert raised.value.operation == _OPERATION[read]
    assert raised.value.stage == "read"
    # The attempt was committed before the read began and survives it; the
    # read left no completion row.
    attempt = (_ACTION[read] + "_attempt", "success", None)
    if read == "overview":
        # Its existing failure row, with a reason that says what happened.
        assert _committed(platform) == [attempt, (_ACTION[read], "failure", "statement_timeout")]
    else:
        assert _committed(platform) == [attempt]


@pytest.mark.parametrize("read", _READS)
def test_the_read_succeeds_again_once_the_lock_is_gone(
    scene: Scene, platform: PlatformWorld, read: str
) -> None:
    """The timeout aborted one transaction and changed nothing else: the
    same call, repeated, completes and is audited as usual."""
    tenant = scene.tenant(active=True)
    reader = _reader(platform, read)
    with _user_row_locked(platform, reader.user_id), pytest.raises(OversightReadTimeoutError):
        _call(read, reader, tenant)
    assert platform.audit_count() == 0

    _call(read, reader, tenant)

    assert _committed(platform) == [
        (_ACTION[read] + "_attempt", "success", None),
        (_ACTION[read], "success", None),
    ]


def test_the_timeout_is_local_to_its_transaction() -> None:
    """Set in one transaction, gone in the next on the same connection: a
    pooled connection never carries it to another user."""
    with get_engine().connect() as connection:
        session = Session(bind=connection)  # every transaction below: this connection
        default = session.execute(text("SHOW statement_timeout")).scalar_one()
        session.commit()
        set_local_statement_timeout(session, _TIMEOUT_MS)
        inside = session.execute(text("SHOW statement_timeout")).scalar_one()
        session.commit()
        after = session.execute(text("SHOW statement_timeout")).scalar_one()
        session.rollback()
        session.close()
    assert inside == f"{_TIMEOUT_MS}ms"
    assert after == default != inside


@pytest.mark.parametrize("read", _READS)
def test_without_the_timeout_the_call_waits_for_as_long_as_the_lock_is_held(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    """Negative control: with the statements that set the timeout removed,
    the same blocked call is not cancelled. PostgreSQL reports it waiting
    on the lock, well past the configured timeout, until the lock is
    released; then it completes."""
    tenant = scene.tenant(active=True)
    reader = _reader(platform, read)
    for module in (platform_audit, platform_oversight):
        monkeypatch.setattr(module, "set_local_statement_timeout", lambda *a, **k: None)

    with _user_row_locked(platform, reader.user_id) as blocker:
        thread, outcome = start(lambda: _call(read, reader, tenant), "reader")
        wait_until_blocked_by(platform.admin, blocker)
        thread.join(timeout=_TIMEOUT_MS * 4 / 1000)
        assert thread.is_alive()  # still waiting, four timeouts later
        wait_until_blocked_by(platform.admin, blocker)
    join(thread)

    assert "error" not in outcome
    assert (_ACTION[read], "success", None) in _committed(platform)
