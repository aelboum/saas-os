"""The permission grant register's audit rows name the user they are about
by reference, never by id (audit identity phase P1; ADR 0045 amendment; the
operator events do the same under `user_subject_ref`). Hermetic: the two
writers (`_write`, `_replay`) run against a stub session, with the platform
audit writer and the reference lookup replaced by recorders. The behaviour
against PostgreSQL is in
`tests/core/platform_authority/test_register_audit_subject_ref_integration.py`.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from saas_os.core.authority import UserCaller
from saas_os.core.permission_grants import register
from saas_os.core.permission_grants.models import REGISTER_ENROLMENT, ApproverRegisterEntry
from saas_os.core.platform_authority.subjects import AuditSubjectLinkUnavailableError

_SUBJECT = uuid.UUID("22222222-2222-4222-8222-222222222222")
_REFERENCE = uuid.UUID("33333333-3333-4333-8333-333333333333")
_CALLER = UserCaller(uuid.UUID("44444444-4444-4444-8444-444444444444"))
_OPERATION = "permission_grant_ledger.approver_enrol"


class _Session:
    def add(self, _entry: object) -> None: ...
    def flush(self) -> None: ...
    def refresh(self, _entry: object) -> None: ...


def _entry() -> ApproverRegisterEntry:
    return ApproverRegisterEntry(
        id=uuid.uuid4(),
        entry_type=REGISTER_ENROLMENT,
        subject_user_id=_SUBJECT,
        recorded_by_user_id=_CALLER.user_id,
        ticket_ref="TICKET-1",
        natural_person_ref="P-1",
        valid_until=datetime(2027, 1, 1, tzinfo=UTC),
        recorded_by_platform_audit_id=uuid.uuid4(),
    )


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {"lookups": []}

    def fake_event(_session: object, **kwargs: Any) -> None:
        seen["event"] = kwargs

    def fake_ref(_session: object, *, user_id: uuid.UUID) -> uuid.UUID:
        seen["lookups"].append(user_id)
        return _REFERENCE

    monkeypatch.setattr(register, "record_platform_event_in_transaction", fake_event)
    monkeypatch.setattr(register, "platform_audit_subject_ref", fake_ref)
    return seen


def _assert_reference_only(seen: dict[str, Any]) -> None:
    event = seen["event"]
    assert event["metadata"]["user_subject_ref"] == str(_REFERENCE)
    assert "subject_user_id" not in event["metadata"]
    # Neither the metadata nor the target carries the user id.
    assert str(_SUBJECT) not in json.dumps(event["metadata"], default=str)
    assert event["target_id"] != str(_SUBJECT)
    assert event.get("target_type") == "permission_grant_ledger_approver_register"
    assert seen["lookups"] == [_SUBJECT]


def test_the_written_entrys_audit_row_carries_a_reference_not_the_user_id(
    recorded: dict[str, Any],
) -> None:
    register._write(
        _Session(),  # type: ignore[arg-type]
        caller=_CALLER,
        operation=_OPERATION,
        reason="TICKET-1: enrol",
        entry=_entry(),
        extra={"channel": "platform_http"},
    )
    _assert_reference_only(recorded)
    assert recorded["event"]["metadata"]["channel"] == "platform_http"


def test_the_replay_row_carries_the_same_reference(recorded: dict[str, Any]) -> None:
    register._replay(
        _Session(),  # type: ignore[arg-type]
        caller=_CALLER,
        operation=_OPERATION,
        reason="TICKET-1: enrol",
        entry=_entry(),
        extra={"channel": "platform_http"},
    )
    _assert_reference_only(recorded)
    assert recorded["event"]["metadata"]["replay"] is True


def test_a_failed_reference_lookup_stops_the_write_before_any_audit_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    written: list[object] = []

    def refuse(_session: object, *, user_id: uuid.UUID) -> uuid.UUID:
        raise AuditSubjectLinkUnavailableError("link table unavailable")

    monkeypatch.setattr(register, "platform_audit_subject_ref", refuse)
    monkeypatch.setattr(register, "record_platform_event_in_transaction", written.append)
    with pytest.raises(AuditSubjectLinkUnavailableError):
        register._write(
            _Session(),  # type: ignore[arg-type]
            caller=_CALLER,
            operation=_OPERATION,
            reason="TICKET-1: enrol",
            entry=_entry(),
            extra={},
        )
    assert written == []
    with pytest.raises(AuditSubjectLinkUnavailableError):
        register._replay(
            _Session(),  # type: ignore[arg-type]
            caller=_CALLER,
            operation=_OPERATION,
            reason="TICKET-1: enrol",
            entry=_entry(),
            extra={},
        )
    assert written == []
