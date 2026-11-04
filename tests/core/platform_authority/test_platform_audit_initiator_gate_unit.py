"""Owner decision D2 (2026-11-02) in the platform audit writers -- hermetic.

The platform audit log has no typed attribution argument; the only way an
initiator reaches a platform row is caller metadata. Every platform writer
goes through `_entry()`, which runs
`saas_os.core.audit_log.metadata.refuse_user_initiators()` before
`validate_metadata()` and before the insert:

- `record_platform_event_in_transaction()` raises `InvalidActorError`
  (no id in it) and adds nothing to the session;
- `record_platform_refusal()` (best effort, never raises) records the
  denial with `{"metadata_refused": "d2"}` in place of the refused
  metadata, and logs `platform_refusal_metadata_refused` without the id;
- `recording_platform_refusal()` re-raises the refusal and records it so;
- `record_oversight_attempt()` and `run_oversight_read()` raise before the
  attempt row, so nothing is read.

Allowlisted values (`None`, `"unavailable"`, a service-account or system
initiator's recorded shape) are stored exactly as given: never converted.
A database-backed version of each path, with the scan of both audit tables,
is `test_audit_initiator_gate_integration.py`.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest

import saas_os.core.platform_authority.audit as audit_module
from saas_os.core.audit_log import InvalidActorError
from saas_os.core.authority import (
    Initiator,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)
from saas_os.core.platform_authority import (
    PlatformAuditOutcome,
    PlatformNotAuthorizedError,
    record_oversight_attempt,
    record_platform_event_in_transaction,
    record_platform_refusal,
    recording_platform_refusal,
    run_oversight_read,
)
from saas_os.core.platform_authority.audit import REFUSED_METADATA_MARKER
from saas_os.core.platform_authority.operations import OPERATOR_READ

_USER = uuid.uuid4()
_OPERATOR = UserCaller(uuid.uuid4())
_SYSTEM = SystemCaller(SystemAuthority.PROVISIONING)
_ACTOR = SystemActor(SystemActorKind.MAINTENANCE, "platform_job")
_USER_SHAPE = {"type": "user", "user_id": str(_USER)}


def _user_shape_from_caller() -> dict[str, object]:
    """The shape `Initiator.from_caller(UserCaller(...))` records."""
    initiator = Initiator.from_caller(UserCaller(_USER))
    assert initiator is not None
    return initiator.as_metadata()


_REFUSED: dict[str, Callable[[], dict[str, object]]] = {
    "user-shape": lambda: {"initiated_by": dict(_USER_SHAPE)},
    "user-initiator-object": lambda: {"initiated_by": Initiator.user(_USER)},
    "from-user-caller": lambda: {"initiated_by": _user_shape_from_caller()},
    "bare-user-id": lambda: {"initiated_by": str(_USER)},
    "upper-case-key": lambda: {"INITIATED_BY": dict(_USER_SHAPE)},
    "padded-key": lambda: {" initiated_by ": dict(_USER_SHAPE)},
    "nested": lambda: {"request": {"initiated_by": dict(_USER_SHAPE)}},
    "in-a-list": lambda: {"items": [{"initiated_by": dict(_USER_SHAPE)}]},
    "extra-field": lambda: {
        "initiated_by": {
            "type": "service_account",
            "service_account_id": str(uuid.uuid4()),
            "user_id": str(_USER),
        }
    },
    "not-an-allowlisted-shape": lambda: {"initiated_by": ["unavailable"]},
}
_ACCEPTED: dict[str, object] = {
    "none": None,
    "unavailable": "unavailable",
    "service-account": Initiator.service_account(_USER).as_metadata(),
    "system": Initiator.system(
        _ACTOR, record_type="provider_event", record_id="evt_1"
    ).as_metadata(),
}


def _assert_no_id(text: str) -> None:
    for spelling in (str(_USER), _USER.hex):
        assert spelling not in text


@pytest.fixture
def no_database(monkeypatch: pytest.MonkeyPatch) -> list[MagicMock]:
    """The writers' own transactions, replaced by recording mocks; the
    authorization a real attempt row needs, replaced by a pass."""
    sessions: list[MagicMock] = []

    @contextmanager
    def _scope() -> Iterator[MagicMock]:
        session = MagicMock()
        sessions.append(session)
        yield session

    monkeypatch.setattr(audit_module, "session_scope", _scope)
    monkeypatch.setattr(audit_module, "authorize_platform_caller", lambda *a, **k: None)
    return sessions


@pytest.mark.parametrize("caller", [_OPERATOR, _SYSTEM], ids=["user", "system"])
@pytest.mark.parametrize("metadata", _REFUSED.values(), ids=_REFUSED)
def test_record_platform_event_refuses_a_user_initiator_before_the_insert(
    metadata: Callable[[], dict[str, object]], caller: object
) -> None:
    session = MagicMock()
    given = metadata()
    with pytest.raises(InvalidActorError) as refused:
        record_platform_event_in_transaction(
            session,
            caller=caller,
            action="platform.test.recorded",
            target_type="test",
            metadata=given,
        )
    assert "D2" in str(refused.value)
    _assert_no_id(str(refused.value))
    assert session.mock_calls == []


@pytest.mark.parametrize("value", _ACCEPTED.values(), ids=_ACCEPTED)
def test_record_platform_event_stores_an_allowlisted_initiator_unchanged(value: object) -> None:
    session = MagicMock()
    metadata = {"initiated_by": value, "nested": {"initiated_by": value}, "n": 1}
    entry = record_platform_event_in_transaction(
        session,
        caller=_OPERATOR,
        action="platform.test.recorded",
        target_type="test",
        metadata=metadata,
    )
    session.add.assert_called_once_with(entry)
    # Stored as given: `None` stays `None` (no conversion to "unavailable").
    assert entry.entry_metadata == {
        "initiated_by": value,
        "nested": {"initiated_by": value},
        "n": 1,
    }


@pytest.mark.parametrize("metadata", _REFUSED.values(), ids=_REFUSED)
def test_record_platform_refusal_records_the_denial_with_a_marker_not_the_initiator(
    metadata: Callable[[], dict[str, object]],
    no_database: list[MagicMock],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Review of 25c9a77 (LOW): the evidence of a refusal is not lost. The
    metadata carrying the user initiator is refused -- not stored, not
    turned into `None` -- and the `denied` row is written with the fixed
    marker in its place. Nothing logged or written names the id."""
    with caplog.at_level(logging.WARNING, logger=audit_module.logger.name):
        written = record_platform_refusal(
            caller=_OPERATOR,
            action="platform.operator.read",
            target_type="platform_operator",
            code="not_authorized",
            outcome=PlatformAuditOutcome.DENIED,
            metadata=metadata(),
        )
    assert written is True
    (session,) = no_database
    (entry,) = [c.args[0] for c in session.add.call_args_list]
    assert entry.entry_metadata == REFUSED_METADATA_MARKER == {"metadata_refused": "d2"}
    assert entry.outcome == "denied" and entry.reason == "not_authorized"
    assert entry.actor_user_id == _OPERATOR.user_id
    _assert_no_id(repr(entry.entry_metadata))
    assert "platform_refusal_metadata_refused" in caplog.text
    assert "platform_refusal_audit_failed" not in caplog.text
    _assert_no_id(caplog.text)


def test_record_platform_refusal_keeps_allowlisted_metadata_unchanged(
    no_database: list[MagicMock],
) -> None:
    metadata: dict[str, object] = {"initiated_by": "unavailable", "n": 1}
    assert record_platform_refusal(
        caller=_SYSTEM,
        action="platform.operator.read",
        target_type="platform_operator",
        code="not_authorized",
        metadata=metadata,
    )
    (session,) = no_database
    (entry,) = [c.args[0] for c in session.add.call_args_list]
    assert entry.entry_metadata == {"initiated_by": "unavailable", "n": 1}


def test_recording_platform_refusal_re_raises_and_records_the_marker(
    no_database: list[MagicMock], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=audit_module.logger.name):
        with (
            pytest.raises(PlatformNotAuthorizedError),
            recording_platform_refusal(
                caller=_OPERATOR,
                operation=OPERATOR_READ,
                target_type="platform_operator",
                metadata={"request": {"initiated_by": dict(_USER_SHAPE)}},
            ),
        ):
            raise PlatformNotAuthorizedError(OPERATOR_READ)
    (session,) = no_database
    (entry,) = [c.args[0] for c in session.add.call_args_list]
    assert entry.entry_metadata == {"metadata_refused": "d2"}
    assert entry.action == "platform.operator.read" and entry.outcome == "denied"
    _assert_no_id(caplog.text)


def test_record_oversight_attempt_refuses_before_the_attempt_row(
    no_database: list[MagicMock],
) -> None:
    with pytest.raises(InvalidActorError) as refused:
        record_oversight_attempt(
            caller=_OPERATOR,
            operation=OPERATOR_READ,
            target_type="platform_operator",
            metadata={"initiated_by": dict(_USER_SHAPE)},
        )
    _assert_no_id(str(refused.value))
    (session,) = no_database
    session.add.assert_not_called()
    session.flush.assert_not_called()


def test_run_oversight_read_refuses_request_metadata_before_anything_is_read(
    no_database: list[MagicMock],
) -> None:
    def read(session: object) -> Any:
        raise AssertionError("nothing may be read")

    with pytest.raises(InvalidActorError):
        run_oversight_read(
            caller=_OPERATOR,
            operation=OPERATOR_READ,
            target_type="platform_operator",
            read=read,
            request_metadata={"filters": {"initiated_by": dict(_USER_SHAPE)}},
        )
    # Only the attempt transaction was opened, and it wrote nothing.
    (session,) = no_database
    session.add.assert_not_called()
