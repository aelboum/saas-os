"""The statement timeout of platform mutations and refusal rows, against a
real PostgreSQL (ADR-0045, amendment of 2026-10-14).

A second connection (the privileged test engine) holds the caller's own
`core.users` row `FOR NO KEY UPDATE`. Authorization takes that row
`FOR SHARE` and therefore waits; PostgreSQL cancels the statement when the
timeout expires. One mutation per module that opens such a transaction:
tenancy, feature flags, identity, and the platform authority itself.
Nothing here sleeps to make a statement slow.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from typing import Any

import pytest
from phase_c_helpers import P, Scene
from platform_helpers import PlatformWorld, join, start, wait_until_blocked_by
from sqlalchemy import text

import saas_os.core.platform_authority.audit as platform_audit
import saas_os.core.platform_authority.transactions as transactions
from saas_os.core.authority import (
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)
from saas_os.core.feature_flags import create_flag
from saas_os.core.identity import deactivate_user, revoke_user_sessions
from saas_os.core.platform_authority import (
    PlatformOperationTimeoutError,
    get_platform_mutation_config,
    grant_platform_permission,
    platform_change_session,
    record_platform_refusal,
)
from saas_os.core.tenancy import TenantStatus, transition_tenant_status
from saas_os.core.tenancy import authority as lifecycle_authority

pytestmark = pytest.mark.integration

_TIMEOUT_MS = 300
_REASON = "timeout test"
_MUTATIONS = ("suspend", "flag", "sessions", "deactivate", "grant")
# What the timeout names: the operation, or -- for a suspension, whose
# preliminary gate runs `platform_can()` in a transaction of its own before
# the transition's -- the permission that gate was checking.
_OPERATION = {
    "suspend": "platform.tenant:suspend",
    "flag": "feature_flag.define",
    "sessions": "session.revoke",
    # Its preliminary check, in a transaction of its own, waits first.
    "deactivate": "platform.user:deactivate",
    "grant": "grant.create",
}
# How each records a timeout: the identity operations write one `failure`
# row; the others record nothing, because a timeout is not a refusal and
# the transaction's evidence was rolled back with it.
_RECORDED = {
    "sessions": [("platform.session.revoke", "failure", "statement_timeout")],
    "deactivate": [("platform.user.deactivate", "failure", "statement_timeout")],
}
# Far longer than the timeout: a call still waiting after this is waiting
# on the lock without limit, and the test fails instead of hanging.
_GRACE_SECONDS = 15
_PERMISSION = {
    "suspend": P.TENANT_SUSPEND,
    "flag": P.FEATURE_FLAG_DEFINE,
    "sessions": P.SESSION_REVOKE,
    "deactivate": P.USER_DEACTIVATE,
    "grant": P.AUTHORITY_MANAGE,
}


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS", str(_TIMEOUT_MS))
    get_platform_mutation_config.cache_clear()
    yield
    get_platform_mutation_config.cache_clear()


@pytest.fixture
def flags(platform: PlatformWorld) -> Iterator[list[str]]:
    created: list[str] = []
    yield created
    if created:
        platform.execute("DELETE FROM core.feature_flags WHERE key = ANY(:k)", {"k": created})


@contextmanager
def _user_row_locked(platform: PlatformWorld, user_id: uuid.UUID) -> Iterator[int]:
    """Hold the user's row on a second connection, in the mode that makes
    an authorization (`FOR SHARE`) wait but lets an audit row that names
    the user be inserted. Yields that connection's backend pid."""
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


class _Case:
    """One mutation: how to call it, and how to tell whether it happened."""

    def __init__(
        self, call: Callable[[], Any], happened: Callable[[], bool], caller: UserCaller
    ) -> None:
        self.call = call
        self.happened = happened
        self.caller = caller


def _case(name: str, scene: Scene, platform: PlatformWorld, flags: list[str]) -> _Case:
    caller, _ = platform.operator([_PERMISSION[name]])
    if name == "suspend":
        tenant = scene.tenant(active=True)
        return _Case(
            lambda: transition_tenant_status(
                tenant, TenantStatus.SUSPENDED, caller=caller, reason=_REASON
            ),
            lambda: scene.status(tenant) == TenantStatus.SUSPENDED.value,
            caller,
        )
    if name == "flag":
        key = f"timeout-{uuid.uuid4().hex[:10]}"
        flags.append(key)
        return _Case(
            lambda: create_flag(key, caller=caller),
            lambda: (
                platform.scalar(
                    "SELECT count(*) FROM core.feature_flags WHERE key = :k", {"k": key}
                )
                == 1
            ),
            caller,
        )
    if name == "sessions":
        target = platform.user()
        scene.session_for(target)
        return _Case(
            lambda: revoke_user_sessions(target, caller=caller, reason=_REASON),
            lambda: scene.live_sessions(target) == 0,
            caller,
        )
    if name == "deactivate":
        target = platform.user()
        return _Case(
            lambda: deactivate_user(target, caller=caller, reason=_REASON),
            lambda: not scene.user_is_active(target),
            caller,
        )
    _, operator_id = platform.operator([])
    return _Case(
        lambda: grant_platform_permission(
            operator_id, P.AUTHORITY_MANAGE, caller=caller, reason=_REASON
        ),
        lambda: (
            platform.scalar(
                "SELECT count(*) FROM core.platform_grants WHERE operator_id = :o "
                "AND revoked_at IS NULL",
                {"o": operator_id},
            )
            == 1
        ),
        caller,
    )


def _run_bounded(fn: Callable[[], Any], name: str, release: Callable[[], None]) -> dict[str, Any]:
    """Run `fn` on a thread while the test holds a lock; wait at most
    `_GRACE_SECONDS`, then `release` the lock whatever happened, so that a
    regression (no timeout) fails the test rather than hanging it."""
    thread, outcome = start(fn, name)
    thread.join(timeout=_GRACE_SECONDS)
    finished = not thread.is_alive()
    release()
    join(thread)
    assert finished, f"{name} still waited on the lock after {_GRACE_SECONDS} s"
    return outcome


@contextmanager
def _held(lock: Any) -> Iterator[Callable[[], None]]:
    """Enter `lock` (a context manager) and yield a function that releases
    it early; released on exit otherwise."""
    stack = ExitStack()
    stack.enter_context(lock)
    try:
        yield stack.close
    finally:
        stack.close()


@pytest.mark.parametrize("name", _MUTATIONS)
def test_a_mutation_that_waits_past_the_timeout_changes_nothing_and_can_be_repeated(
    scene: Scene, platform: PlatformWorld, flags: list[str], name: str
) -> None:
    case = _case(name, scene, platform, flags)
    platform.clear_audit()

    with _held(_user_row_locked(platform, case.caller.user_id)) as release:
        outcome = _run_bounded(case.call, f"timed-{name}", release)

    raised = outcome.get("error")
    assert isinstance(raised, PlatformOperationTimeoutError), outcome
    assert raised.operation == _OPERATION[name]
    assert raised.timeout_ms == _TIMEOUT_MS
    assert raised.code == "statement_timeout"
    assert not case.happened()
    rows = [(row["action"], row["outcome"], row["reason"]) for row in platform.audit()]
    assert rows == _RECORDED.get(name, [])

    # Nothing was decided against the caller: the same call, repeated, succeeds.
    case.call()
    assert case.happened()


@pytest.mark.parametrize("name", _MUTATIONS)
def test_without_the_timeout_the_same_mutation_waits_for_as_long_as_the_lock_is_held(
    scene: Scene,
    platform: PlatformWorld,
    flags: list[str],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    """Negative control: with the statement that sets the timeout removed,
    the mutation is still waiting when the lock is released, and then
    completes."""
    case = _case(name, scene, platform, flags)
    monkeypatch.setattr(transactions, "set_local_statement_timeout", lambda *a, **k: None)

    with _user_row_locked(platform, case.caller.user_id) as blocker:
        thread, outcome = start(case.call, f"untimed-{name}")
        wait_until_blocked_by(platform.admin, blocker)
    join(thread)

    assert "error" not in outcome, outcome.get("error")
    assert case.happened()


def test_a_system_purpose_is_not_bounded_and_a_person_or_a_refused_caller_is(
    platform: PlatformWorld,
) -> None:
    def timeout_of(caller: object) -> str:
        with platform_change_session(caller, "tenant.suspend") as session:
            return str(session.execute(text("SHOW statement_timeout")).scalar_one())

    with platform.admin.connect() as connection:
        default = str(connection.execute(text("SHOW statement_timeout")).scalar_one())

    assert default != f"{_TIMEOUT_MS}ms"
    assert timeout_of(SystemCaller(SystemAuthority.PROVISIONING)) == default
    assert timeout_of(UserCaller(uuid.uuid4())) == f"{_TIMEOUT_MS}ms"
    # A caller the operation will refuse must not wait without limit first.
    service_account = ServiceAccountCaller(uuid.uuid4(), uuid.uuid4())
    assert timeout_of(service_account) == f"{_TIMEOUT_MS}ms"


def _refuse(caller: object) -> bool:
    return record_platform_refusal(
        caller=caller,
        action="platform.tenant.suspend",
        target_type="tenant",
        code="not_authorized",
    )


@contextmanager
def _audit_table_locked(platform: PlatformWorld) -> Iterator[int]:
    connection = platform.admin.connect()
    transaction = connection.begin()
    try:
        connection.execute(text("LOCK TABLE core.platform_audit_log IN ACCESS EXCLUSIVE MODE"))
        yield connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
    finally:
        transaction.rollback()
        connection.close()


def test_a_refusal_row_that_cannot_be_written_in_time_is_skipped_not_awaited(
    platform: PlatformWorld,
) -> None:
    """A lock on the audit table holds the refusal writer for at most the
    timeout; the refusal is still the caller's to receive."""
    caller = UserCaller(platform.user())
    platform.clear_audit()

    with _held(_audit_table_locked(platform)) as release:
        outcome = _run_bounded(lambda: _refuse(caller), "refusal", release)
    assert outcome == {"result": False}
    assert platform.audit_count() == 0

    assert _refuse(caller) is True
    assert platform.audit_count() == 1


def test_without_the_timeout_the_refusal_writer_waits_for_the_lock(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control for the test above."""
    caller = UserCaller(platform.user())
    platform.clear_audit()
    monkeypatch.setattr(platform_audit, "set_local_statement_timeout", lambda *a, **k: None)

    with _audit_table_locked(platform) as blocker:
        thread, outcome = start(lambda: _refuse(caller), "untimed-refusal")
        wait_until_blocked_by(platform.admin, blocker)
    join(thread)

    assert outcome == {"result": True}
    assert platform.audit_count() == 1


def test_a_transition_whose_own_transaction_waits_past_the_timeout_changes_nothing(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock is taken after the preliminary gate has passed, so it is
    the transition's own transaction -- opened by
    `lifecycle_authority.change_session` -- that is cancelled."""
    caller, _ = platform.operator([P.TENANT_SUSPEND])
    tenant = scene.tenant(active=True)
    platform.clear_audit()
    real_gate = lifecycle_authority.passes_transition_gate
    held = ExitStack()

    def gate_then_lock(*args: Any, **kwargs: Any) -> bool:
        passed = real_gate(*args, **kwargs)
        held.enter_context(_user_row_locked(platform, caller.user_id))
        return passed

    monkeypatch.setattr(lifecycle_authority, "passes_transition_gate", gate_then_lock)
    try:
        outcome = _run_bounded(
            lambda: transition_tenant_status(
                tenant, TenantStatus.SUSPENDED, caller=caller, reason=_REASON
            ),
            "timed-transition",
            held.close,
        )
    finally:
        held.close()

    raised = outcome.get("error")
    assert isinstance(raised, PlatformOperationTimeoutError), outcome
    assert raised.operation == "tenant.suspend"
    assert scene.status(tenant) == TenantStatus.ACTIVE.value
    assert platform.audit_count() == 0
