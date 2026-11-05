"""Platform audit subject references, hermetic tests (audit identity phase
P1; docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections
4.2 and 4.4): the guard that no platform audit row stores a user id, the
argument rules of `target_user_id`, the collision retry of the get-or-create,
its isolation check and the fallback of the best-effort refusal writer. No
database. The behaviour against PostgreSQL is in
`test_audit_subject_references_integration.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest

import saas_os.core.platform_authority.audit as audit
import saas_os.core.platform_authority.subjects as subjects
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.platform_authority import InvalidPlatformRequestError, PlatformAuditOutcome
from saas_os.core.platform_authority.subjects import (
    AuditSubjectLinkUnavailableError,
    AuditTarget,
)
from saas_os.infra.db import IntegrityError

_CALLER = SystemCaller(SystemAuthority.PLATFORM_BOOTSTRAP)
_USER = uuid.UUID("11111111-1111-4111-8111-111111111111")


def _row(**overrides: Any) -> Any:
    arguments: dict[str, Any] = {
        "caller": _CALLER,
        "action": "platform.user.read",
        "target_type": "user_subject",
        "target_id": str(uuid.uuid4()),
        "target_tenant_id": None,
        "outcome": PlatformAuditOutcome.SUCCESS,
        "reason": None,
        "metadata": None,
    }
    arguments.update(overrides)
    return audit._entry(**arguments)


# --- no writer can store a user id again ---------------------------------------


def test_a_user_target_with_an_id_is_refused_by_every_row_construction() -> None:
    with pytest.raises(InvalidPlatformRequestError, match="reference"):
        _row(target_type="user", target_id=str(_USER))


def test_a_reference_and_no_target_are_the_accepted_shapes_of_a_user_target() -> None:
    assert _row(target_type="user_subject").target_type == "user_subject"
    row = _row(target_type="user", target_id=None)
    assert (row.target_type, row.target_id) == ("user", None)


def test_other_target_types_keep_their_ids() -> None:
    for target_type in ("platform_operator", "session", "tenant"):
        assert _row(target_type=target_type, target_id="abc").target_id == "abc"


@pytest.mark.parametrize(
    ("target_type", "target_id", "target_user_id", "message"),
    [
        ("user", "x", _USER, "needs target_type"),
        ("session", None, _USER, "needs target_type"),
        ("user", None, str(_USER), "must be a uuid"),
    ],
)
def test_target_user_id_needs_a_user_target_and_no_target_id(
    target_type: str, target_id: str | None, target_user_id: Any, message: str
) -> None:
    with pytest.raises(InvalidPlatformRequestError, match=message):
        audit._user_target_arguments(target_type, target_id, target_user_id)


def test_no_target_user_id_is_accepted_for_any_target() -> None:
    audit._user_target_arguments("session", "abc", None)
    audit._user_target_arguments("user", None, None)
    audit._user_target_arguments("user", None, _USER)


# --- the get-or-create's collision retry and isolation check --------------------


class _Collisions:
    """A stand-in session: `execute` raises or returns the next scripted
    outcome; `begin_nested` is a no-op context manager."""

    def __init__(self, *outcomes: Any) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    @contextmanager
    def begin_nested(self) -> Iterator[None]:
        yield

    def execute(self, _statement: object) -> Any:
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(scalar_one_or_none=lambda: outcome)


def _integrity(constraint: str) -> IntegrityError:
    original = SimpleNamespace(diag=SimpleNamespace(constraint_name=constraint))
    return IntegrityError("INSERT", {}, original)  # type: ignore[arg-type]


def test_a_reference_collision_is_retried_and_the_next_attempt_succeeds() -> None:
    reference = uuid.uuid4()
    session = _Collisions(
        _integrity("pk_platform_audit_subject_links"),
        _integrity("pk_platform_audit_subject_links"),
        reference,
    )
    assert subjects._insert_live(session, _USER) == reference  # type: ignore[arg-type]
    assert session.calls == 3


def test_three_reference_collisions_are_unavailable_never_a_raw_id() -> None:
    session = _Collisions(*[_integrity("pk_platform_audit_subject_links")] * 3)
    with pytest.raises(AuditSubjectLinkUnavailableError):
        subjects._insert_live(session, _USER)  # type: ignore[arg-type]
    assert session.calls == 3


def test_a_conflict_on_another_constraint_is_not_retried() -> None:
    session = _Collisions(_integrity("fk_platform_audit_subject_links_user_id"), uuid.uuid4())
    with pytest.raises(IntegrityError):
        subjects._insert_live(session, _USER)  # type: ignore[arg-type]
    assert session.calls == 1


def test_a_lost_race_returns_none_so_the_committed_link_is_read() -> None:
    assert subjects._insert_live(_Collisions(None), _USER) is None  # type: ignore[arg-type]


def test_get_or_create_refuses_any_isolation_other_than_read_committed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    taken: list[str] = []
    monkeypatch.setattr(subjects, "current_transaction_isolation", lambda _s: "repeatable read")
    monkeypatch.setattr(subjects, "acquire_global_advisory_lock", lambda *a, **k: taken.append("x"))
    with pytest.raises(AuditSubjectLinkUnavailableError, match="READ COMMITTED"):
        subjects.platform_audit_subject_ref(object(), user_id=_USER)  # type: ignore[arg-type]
    assert taken == []  # nothing was locked or read


def test_the_helpers_refuse_anything_but_a_uuid() -> None:
    with pytest.raises(TypeError):
        subjects.platform_audit_subject_ref(object(), user_id=str(_USER))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        subjects.user_audit_target(object(), user_id=str(_USER))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        subjects.erase_platform_audit_subject(object(), user_id=str(_USER))  # type: ignore[arg-type]


def test_the_error_names_no_user() -> None:
    for message in (
        "a reference could not be generated",
        "the committed link could not be read back",
    ):
        assert str(_USER) not in str(AuditSubjectLinkUnavailableError(message))


# --- the refusal writer's fallback (owner decision of 2026-11-04, O6-5) ---------


class _Savepoint:
    @contextmanager
    def begin_nested(self) -> Iterator[None]:
        yield


def test_the_refusal_target_is_the_reference_when_it_can_be_got(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = str(uuid.uuid4())
    monkeypatch.setattr(
        audit, "user_audit_target", lambda _s, user_id: AuditTarget("user_subject", reference)
    )
    assert audit._refusal_target(
        _Savepoint(),  # type: ignore[arg-type]
        target_type="user",
        target_id=None,
        target_user_id=_USER,
        action="platform.user.read",
        code="not_authorized",
    ) == ("user_subject", reference, False)


def test_the_refusal_target_falls_back_to_no_target_when_the_reference_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing(_session: object, *, user_id: uuid.UUID) -> AuditTarget:
        raise AuditSubjectLinkUnavailableError("three collisions")

    monkeypatch.setattr(audit, "user_audit_target", failing)
    assert audit._refusal_target(
        _Savepoint(),  # type: ignore[arg-type]
        target_type="user",
        target_id=None,
        target_user_id=_USER,
        action="platform.user.read",
        code="not_authorized",
    ) == ("user", None, True)


def test_a_refusal_without_a_target_user_keeps_its_target() -> None:
    assert audit._refusal_target(
        _Savepoint(),  # type: ignore[arg-type]
        target_type="platform_operator",
        target_id="abc",
        target_user_id=None,
        action="platform.operator.suspend",
        code="x",
    ) == ("platform_operator", "abc", False)


# --- the existence read is FOR KEY SHARE (option A1) ------------------------------


def test_the_existence_read_takes_a_key_share_lock_on_the_user_row() -> None:
    """Not `FOR SHARE` (it would block the non-key updates other code makes to
    the row), not `FOR UPDATE`, not unlocked (a concurrent delete could race
    the audit write): exactly `FOR KEY SHARE`, on `core.users`."""
    from sqlalchemy.dialects import postgresql

    statements: list[object] = []

    class Capture:
        def execute(self, statement: object) -> Any:
            statements.append(statement)
            return SimpleNamespace(first=lambda: None)

    assert subjects.user_exists_for_audit(Capture(), _USER) is False  # type: ignore[arg-type]
    (statement,) = statements
    sql = str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[attr-defined]
    assert sql.endswith("FOR KEY SHARE"), sql
    assert "FROM core.users" in sql and "FOR NO KEY" not in sql
