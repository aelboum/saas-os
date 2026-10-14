"""Shared helpers for the platform-authority integration tests (ADR-0045
Phase B), against a real PostgreSQL migrated to head.

Platform authority is deployment-wide state: bootstrap refuses when any
operator exists, and the last-owner invariant is about the whole
deployment. Every test that takes the `platform` fixture therefore starts
from, and leaves behind, **empty platform tables**, cleared with the
privileged role (the runtime role cannot delete platform rows at all).
These tests are for disposable databases only, and must never run
concurrently with each other.

The fixtures are in `conftest.py`; nothing is autouse, because the hermetic
unit tests in this directory need no database.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import Engine, text

from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import create_user
from saas_os.core.identity.service import get_or_create_user_for_external_identity
from saas_os.core.platform_authority import (
    PlatformPermission,
    enroll_operator,
    grant_platform_permission,
)

BOOTSTRAP = SystemCaller(SystemAuthority.PLATFORM_BOOTSTRAP)
ALL_PERMISSIONS: tuple[PlatformPermission, ...] = tuple(PlatformPermission)
REASON = "integration test"
# The issuer of the identities the test operators log in with.
OPERATOR_ISSUER = "https://issuer.platform-operators.test"

CLEAR = "TRUNCATE core.platform_audit_log, core.platform_grants, core.platform_operators"


class PlatformWorld:
    def __init__(self, admin: Engine) -> None:
        self.admin = admin
        self.users: list[uuid.UUID] = []

    # --- setup ---------------------------------------------------------------

    def user(self) -> uuid.UUID:
        """A user someone can log in as: linked to an external identity of
        its own, as every person who has logged in once is. Enrollment
        requires one (ADR-0045 section 6)."""
        user_id = get_or_create_user_for_external_identity(
            OPERATOR_ISSUER, f"user-{uuid.uuid4().hex}"
        ).id
        self.users.append(user_id)
        return user_id

    def unlinked_user(self) -> uuid.UUID:
        """A user nobody can log in as: no external identity, like an erased
        user."""
        user_id = create_user().id
        self.users.append(user_id)
        return user_id

    def operator(
        self, permissions: Sequence[PlatformPermission] = ()
    ) -> tuple[UserCaller, uuid.UUID]:
        """An enrolled, active operator holding exactly `permissions`.
        Returns `(caller, operator_id)`.

        Test setup only: created through the ordinary enroll and grant
        operations, acting with the bootstrap-and-recovery system purpose
        (which the operation table accepts for exactly those two), so that
        setup needs no pre-existing owner and none of the bootstrap or
        recovery composite."""
        user_id = self.user()
        operator = enroll_operator(user_id, caller=BOOTSTRAP, reason=REASON)
        for permission in permissions:
            grant_platform_permission(operator.id, permission, caller=BOOTSTRAP, reason=REASON)
        return UserCaller(user_id), operator.id

    def owner(self) -> tuple[UserCaller, uuid.UUID]:
        """An operator holding every platform permission."""
        return self.operator(ALL_PERMISSIONS)

    def set_user_active(self, user_id: uuid.UUID, active: bool) -> None:
        """No Core function writes `is_active` in Phase B; a deployment
        changes it directly. Done here with the privileged role."""
        self.execute(
            "UPDATE core.users SET is_active = :a WHERE id = :u", {"a": active, "u": user_id}
        )

    # --- inspection -----------------------------------------------------------

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        with self.admin.begin() as conn:
            result = conn.execute(text(sql), params or {})
            return [tuple(row) for row in result] if result.returns_rows else []

    def scalar(self, sql: str, params: dict[str, Any] | None = None) -> Any:
        return self.execute(sql, params)[0][0]

    def operator_status(self, operator_id: uuid.UUID) -> str:
        return self.scalar(
            "SELECT status FROM core.platform_operators WHERE id = :i", {"i": operator_id}
        )

    def live_permissions(self, operator_id: uuid.UUID) -> set[str]:
        rows = self.execute(
            "SELECT permission FROM core.platform_grants "
            "WHERE operator_id = :o AND revoked_at IS NULL",
            {"o": operator_id},
        )
        return {row[0] for row in rows}

    def owner_count(self) -> int:
        """The owner predicate of ADR-0045 section 6, counted."""
        return self.scalar(
            "SELECT count(*) FROM core.platform_operators o "
            "JOIN core.users u ON u.id = o.user_id "
            "JOIN core.platform_grants g ON g.operator_id = o.id "
            "WHERE o.status = 'active' AND u.is_active "
            "AND g.permission = 'platform.authority:manage' AND g.revoked_at IS NULL"
        )

    def audit(self, action: str | None = None, outcome: str | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT actor_type, actor_user_id, system_authority, action, target_type, "
            "target_id, target_tenant_id, outcome, reason, metadata "
            "FROM core.platform_audit_log WHERE true"
        )
        params: dict[str, Any] = {}
        if action is not None:
            sql += " AND action = :action"
            params["action"] = action
        if outcome is not None:
            sql += " AND outcome = :outcome"
            params["outcome"] = outcome
        sql += " ORDER BY created_at, id"
        keys = (
            "actor_type",
            "actor_user_id",
            "system_authority",
            "action",
            "target_type",
            "target_id",
            "target_tenant_id",
            "outcome",
            "reason",
            "metadata",
        )
        return [dict(zip(keys, row, strict=True)) for row in self.execute(sql, params)]

    def audit_count(self) -> int:
        return self.scalar("SELECT count(*) FROM core.platform_audit_log")

    def clear_audit(self) -> None:
        self.execute("TRUNCATE core.platform_audit_log")

    # --- teardown --------------------------------------------------------------

    def cleanup(self) -> None:
        self.execute(CLEAR)
        if self.users:
            self.execute("DELETE FROM core.sessions WHERE user_id = ANY(:u)", {"u": self.users})
            self.execute(
                "DELETE FROM core.external_identities WHERE user_id = ANY(:u)", {"u": self.users}
            )
            self.execute("DELETE FROM core.users WHERE id = ANY(:u)", {"u": self.users})


# --- concurrency helpers ---------------------------------------------------------


class Gate:
    """Stops the transaction running on thread `thread_name` the first time
    it reaches `checkpoint()` -- every lock it has taken still held -- and
    records that transaction's backend pid."""

    def __init__(self, thread_name: str) -> None:
        self.thread_name = thread_name
        self.paused = threading.Event()
        self.release = threading.Event()
        self.pid: int | None = None
        self._fired = False

    def checkpoint(self, session: Any) -> None:
        if threading.current_thread().name != self.thread_name or self._fired:
            return
        self._fired = True
        self.pid = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
        self.paused.set()
        assert self.release.wait(timeout=60), "gate never released"


def start(fn: Any, name: str) -> tuple[threading.Thread, dict[str, Any]]:
    """Run `fn` on a named thread, capturing its result or its exception."""
    outcome: dict[str, Any] = {}

    def _run() -> None:
        try:
            outcome["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 -- surfaced by the assertions
            outcome["error"] = exc

    thread = threading.Thread(target=_run, name=name)
    thread.start()
    return thread, outcome


def join(thread: threading.Thread) -> None:
    thread.join(timeout=60)
    assert not thread.is_alive(), f"thread {thread.name} did not finish"


def wait_until_blocked_by(admin: Engine, blocker_pid: int | None) -> None:
    """Wait (bounded) until PostgreSQL itself reports some backend waiting
    on a lock held by `blocker_pid`. Never a sleep or a timing guess."""
    assert blocker_pid is not None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with admin.connect() as conn:
            blocked = conn.execute(
                text("SELECT pid FROM pg_stat_activity WHERE :p = ANY(pg_blocking_pids(pid))"),
                {"p": blocker_pid},
            ).all()
        if blocked:
            return
        threading.Event().wait(0.02)
    raise AssertionError(f"no backend ever blocked on pid {blocker_pid}'s locks")


def run_first_then_second(
    admin: Engine, pause: Gate, first: Any, second: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Force `first` (running on a thread named "first", gated by `pause`)
    to hold its locks -- change flushed, not committed -- while `second`
    starts and blocks on it; then let `first` commit."""
    first_thread, first_outcome = start(first, "first")
    assert pause.paused.wait(timeout=30), "the first transaction never reached its gate"
    second_thread, second_outcome = start(second, "second")
    wait_until_blocked_by(admin, pause.pid)
    pause.release.set()
    join(first_thread)
    join(second_thread)
    return first_outcome, second_outcome
