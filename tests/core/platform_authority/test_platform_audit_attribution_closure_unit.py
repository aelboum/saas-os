"""Final closure of owner decision D2 (owner, 2026-11-03) in the platform
audit writers -- hermetic.

Every platform writer path (`record_platform_event_in_transaction`, the
refusal writers, the oversight attempt, the operator-session writer) goes
through `_entry()`, which stores `trusted_metadata()`:

- no user id through an `initiated_by` key under any spelling (case,
  padding, `_ - .` separators, a lying `str` subclass) at any depth;
- a `correlation` or `system_actor` value at any depth -- the platform log
  has no reserved keys -- is rebuilt through `SystemCorrelation` /
  `SystemActor`, or refused when it carries identity or an odd shape;
- the stored metadata is a plain copy, never the caller's objects, and the
  actor columns are rebuilt from the caller's fields;
- the refusal writer still records the denial, with the fixed marker in
  place of refused metadata; nothing is converted to `None`.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

import saas_os.core.platform_authority.audit as audit_module
from saas_os.core.audit_log import InvalidActorError, MetadataNotJSONSerializableError
from saas_os.core.authority import (
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    SystemCorrelation,
    UserCaller,
)
from saas_os.core.platform_authority import (
    record_oversight_attempt,
    record_platform_event_in_transaction,
    record_platform_refusal,
)
from saas_os.core.platform_authority.audit import (
    INVALID_METADATA_MARKER,
    REFUSED_METADATA_MARKER,
    record_operator_session_issued_in_transaction,
)
from saas_os.core.platform_authority.operations import OPERATOR_READ

_USER = uuid.uuid4()
_EVENT = uuid.uuid4()
_OPERATOR = UserCaller(uuid.uuid4())
_SYSTEM = SystemCaller(SystemAuthority.PROVISIONING)
_USER_SHAPE = {"type": "user", "user_id": str(_USER)}


class _LyingKey(str):
    __slots__ = ()

    def strip(self, *args: object) -> str:  # type: ignore[override]
        return "harmless"

    def lower(self) -> str:  # type: ignore[override]
        return "harmless"

    __hash__ = str.__hash__


class _LyingUUID(uuid.UUID):
    __slots__ = ()

    def __str__(self) -> str:
        return "not-the-real-id"


def _assert_no_id(text: str) -> None:
    for spelling in (str(_USER), _USER.hex):
        assert spelling not in text


@pytest.fixture
def no_database(monkeypatch: pytest.MonkeyPatch) -> list[MagicMock]:
    sessions: list[MagicMock] = []

    @contextmanager
    def _scope() -> Iterator[MagicMock]:
        session = MagicMock()
        sessions.append(session)
        yield session

    monkeypatch.setattr(audit_module, "session_scope", _scope)
    monkeypatch.setattr(audit_module, "authorize_platform_caller", lambda *a, **k: None)
    return sessions


def _event(metadata: object, caller: object = _OPERATOR) -> object:
    return record_platform_event_in_transaction(
        MagicMock(),
        caller=caller,
        action="platform.test.recorded",
        target_type="test",
        metadata=metadata,  # type: ignore[arg-type]
    )


_REFUSED: dict[str, dict[str, object]] = {
    "camel-case-key": {"initiatedBy": dict(_USER_SHAPE)},
    "hyphen-key": {"x": {"initiated-by": dict(_USER_SHAPE)}},
    "dotted-key": {"x": [{"INITIATED.BY": dict(_USER_SHAPE)}]},
    "lying-str-key": {"x": {_LyingKey("initiated_by"): dict(_USER_SHAPE)}},
    "no-break-space-key": {"\u00a0initiated_by": dict(_USER_SHAPE)},
    "vertical-tab-key": {"x": {"\x0binitiated_by\x0c": dict(_USER_SHAPE)}},
    "next-line-key": {"\x85initiated_by": dict(_USER_SHAPE)},
    "em-space-key": {"initiated_by\u2003": dict(_USER_SHAPE)},
    "dotted-capital-i-key": {"\u0130nitiated_by": dict(_USER_SHAPE)},
    "fullwidth-key": {
        "\uff49\uff4e\uff49\uff54\uff49\uff41\uff54\uff45\uff44\uff3f\uff42\uff59": dict(
            _USER_SHAPE
        )
    },
    "zero-width-key": {"x": [{"initiated\u200b_by": dict(_USER_SHAPE)}]},
    "slash-key": {"initiated/by": dict(_USER_SHAPE)},
    "no-break-space-correlation": {"\u00a0correlation": {"user_id": str(_USER)}},
    "correlation-user-field": {"correlation": {"user_id": str(_USER)}},
    "correlation-request-id-user": {"correlation": {"request_id": f"user:{_USER}"}},
    "correlation-job-id-member": {"x": {"Correlation": {"arq_job_id": "member-1"}}},
    "correlation-object": {"correlation": SystemCorrelation(request_id="r-1")},
    "correlation-odd-event-id": {"correlation": {"outbox_event_id": _EVENT.hex}},
    "system-actor-user-field": {
        "system_actor": {"kind": "worker_job", "name": "a", "user_id": str(_USER)}
    },
    "system-actor-name-embeds-id": {
        "x": {"systemActor": {"kind": "worker_job", "name": f"job_{_USER.hex}"}}
    },
    "system-actor-object": {"system_actor": SystemActor(SystemActorKind.WORKER_JOB, "a")},
}


@pytest.mark.parametrize("caller", [_OPERATOR, _SYSTEM], ids=["user", "system"])
@pytest.mark.parametrize("metadata", _REFUSED.values(), ids=_REFUSED)
def test_the_platform_event_writer_refuses_identity_in_attribution_values(
    metadata: dict[str, object], caller: object
) -> None:
    session = MagicMock()
    with pytest.raises(InvalidActorError) as refused:
        record_platform_event_in_transaction(
            session,
            caller=caller,
            action="platform.test.recorded",
            target_type="test",
            metadata=metadata,
        )
    assert "D2" in str(refused.value)
    _assert_no_id(str(refused.value))
    assert session.mock_calls == []


@pytest.mark.parametrize("metadata", _REFUSED.values(), ids=_REFUSED)
def test_the_refusal_writer_records_the_denial_with_the_marker(
    metadata: dict[str, object],
    no_database: list[MagicMock],
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert record_platform_refusal(
        caller=_OPERATOR,
        action="platform.test.recorded",
        target_type="test",
        code="not_authorized",
        metadata=metadata,
    )
    (session,) = no_database
    (call,) = session.add.call_args_list
    entry = call.args[0]
    assert entry.entry_metadata == REFUSED_METADATA_MARKER
    assert entry.entry_metadata is not REFUSED_METADATA_MARKER
    _assert_no_id(repr(entry.entry_metadata) + caplog.text)


@pytest.mark.parametrize("metadata", _REFUSED.values(), ids=_REFUSED)
def test_the_oversight_attempt_refuses_before_its_row(
    metadata: dict[str, object], no_database: list[MagicMock]
) -> None:
    with pytest.raises(InvalidActorError):
        record_oversight_attempt(
            caller=_OPERATOR, operation=OPERATOR_READ, target_type="test", metadata=metadata
        )
    (session,) = no_database
    session.add.assert_not_called()


_ACCEPTED: dict[str, dict[str, object]] = {
    "correlation": {
        "correlation": SystemCorrelation(
            arq_job_id=uuid.uuid4().hex, outbox_event_id=_EVENT, request_id=str(uuid.uuid4())
        ).as_metadata()
    },
    "nested-correlation": {"page": {"correlation": {"arq_job_id": "cron:digest:1730600000000"}}},
    "system-actor": {"system_actor": {"kind": "maintenance", "name": "platform_job"}},
    "unavailable": {"initiated_by": "unavailable", "correlation": None, "system_actor": None},
    "operator-session": {"operator_id": str(uuid.uuid4())},
    "oversight-completion": {"attempt_id": str(uuid.uuid4()), "returned": 3},
}


@pytest.mark.parametrize("metadata", _ACCEPTED.values(), ids=_ACCEPTED)
def test_recorded_shapes_are_stored_as_a_rebuilt_equal_plain_copy(
    metadata: dict[str, object],
) -> None:
    entry = _event(metadata)
    stored = entry.entry_metadata  # type: ignore[attr-defined]
    assert stored == metadata
    assert stored is not metadata
    assert json.dumps(stored) == json.dumps(metadata)


def test_the_stored_platform_metadata_never_holds_the_callers_objects() -> None:
    inner = {"initiated_by": "unavailable"}
    given: dict[str, object] = {"tuple": ("a", 1), "inner": inner}
    entry = _event(given)
    stored = entry.entry_metadata  # type: ignore[attr-defined]
    assert stored == {"tuple": ["a", 1], "inner": {"initiated_by": "unavailable"}}
    assert stored["inner"] is not inner


def test_the_platform_actor_columns_are_rebuilt_from_the_callers_fields() -> None:
    entry = _event(None, UserCaller(_LyingUUID(int=_USER.int)))
    assert type(entry.actor_user_id) is uuid.UUID  # type: ignore[attr-defined]
    assert entry.actor_user_id == _USER  # type: ignore[attr-defined]
    forged = SystemCaller(SystemAuthority.PROVISIONING)
    object.__setattr__(forged, "authority", "not_a_purpose")
    with pytest.raises(InvalidActorError):
        _event(None, forged)
    system_entry = _event(None, SystemCaller(SystemAuthority.PLATFORM_BOOTSTRAP))
    assert system_entry.system_authority == "platform_bootstrap"  # type: ignore[attr-defined]
    assert type(system_entry.system_authority) is str  # type: ignore[attr-defined]


def test_the_operator_session_writer_stores_only_the_operator_record_id() -> None:
    session = MagicMock()
    operator_id = uuid.uuid4()
    session.execute.return_value.first.return_value = MagicMock(id=operator_id)
    assert record_operator_session_issued_in_transaction(
        session, user_id=_USER, session_id=uuid.uuid4()
    )
    (call,) = session.add.call_args_list
    entry = call.args[0]
    assert entry.entry_metadata == {"operator_id": str(operator_id)}
    assert entry.actor_user_id == _USER
    assert type(entry.actor_user_id) is uuid.UUID


# --- Odd shapes: refused as not serializable; the refusal row survives -------------


def _deep(depth: int) -> list[object]:
    """Lists nested `depth` deep: 2 bytes a level, so 3000 levels stay under
    the 8 KiB size limit while exceeding Python's recursion limit on every
    platform (a C-stack-based `json.dumps` may still serialize it; the key
    check or the copy then overflows instead)."""
    root: list[object] = []
    node = root
    for _ in range(depth):
        child: list[object] = []
        node.append(child)
        node = child
    return root


_INVALID: dict[str, dict[str, object]] = {
    "nested-3000-deep": {"deep": _deep(3000)},
    "nan": {"ratio": float("nan")},
    "infinity": {"x": [float("inf")]},
    "not-serializable": {"x": object()},
}


@pytest.mark.parametrize("metadata", _INVALID.values(), ids=_INVALID)
def test_the_event_writer_refuses_odd_shapes_as_not_serializable(
    metadata: dict[str, object],
) -> None:
    session = MagicMock()
    with pytest.raises(MetadataNotJSONSerializableError):
        record_platform_event_in_transaction(
            session,
            caller=_OPERATOR,
            action="platform.test.recorded",
            target_type="test",
            metadata=metadata,
        )
    assert session.mock_calls == []


@pytest.mark.parametrize("metadata", _INVALID.values(), ids=_INVALID)
def test_the_refusal_writer_keeps_the_denial_row_with_the_invalid_marker(
    metadata: dict[str, object], no_database: list[MagicMock]
) -> None:
    assert record_platform_refusal(
        caller=_OPERATOR,
        action="platform.test.recorded",
        target_type="test",
        code="not_authorized",
        metadata=metadata,
    )
    (session,) = no_database
    (call,) = session.add.call_args_list
    entry = call.args[0]
    assert entry.entry_metadata == INVALID_METADATA_MARKER
    assert entry.reason == "not_authorized"
