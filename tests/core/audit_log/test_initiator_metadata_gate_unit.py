"""Owner decision D2 (2026-11-02), the metadata path, without a database.

The typed `initiated_by=` argument of the tenant writers is gated in
`test_system_actor_unit.py`. This file covers the other way a value can
reach an `initiated_by` key of a new audit row: the metadata itself.

- `refuse_user_initiators()` accepts, under any `initiated_by` key at any
  depth, only `None`, `"unavailable"` and the exact recorded shape of a
  service-account or system initiator; everything else -- a user shape
  above all -- is `InvalidActorError`, naming no id.
- The three tenant writers run it on the final metadata before any write:
  a user initiator nested in caller metadata is refused like the typed
  argument; a top-level `initiated_by` key stays reserved
  (`ReservedMetadataKeyError`), as before.

The platform writers are covered in
`tests/core/platform_authority/test_platform_audit_initiator_gate_unit.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from saas_os.core.audit_log import (
    ActorType,
    AuditOutcome,
    InvalidActorError,
    ReservedMetadataKeyError,
    record,
    record_in_transaction,
    record_system_action_in_transaction,
)
from saas_os.core.audit_log import service as audit_service
from saas_os.core.audit_log.metadata import (
    AUDIT_INITIATOR_TYPES,
    refuse_user_initiators,
    validate_metadata,
)
from saas_os.core.authority import (
    Caller,
    Initiator,
    InitiatorType,
    InvalidSystemActorError,
    ServiceAccountCaller,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)

_USER = uuid.uuid4()
_TENANT = uuid.uuid4()
_ACTOR = SystemActor(SystemActorKind.WORKER_JOB, "nightly_export")
_LINK = SystemActor(SystemActorKind.PUBLIC_LINK, "my_product.unsubscribe")
_USER_SHAPE = {"type": "user", "user_id": str(_USER)}
_ACCOUNT_SHAPE = {"type": "service_account", "service_account_id": str(_USER)}
_SYSTEM_SHAPE = Initiator.system(
    _LINK, record_type="unsubscribe_link", record_id="l-1"
).as_metadata()


def _user_shape_from_caller() -> dict[str, object]:
    """The shape `Initiator.from_caller(UserCaller(...))` records."""
    initiator = Initiator.from_caller(UserCaller(_USER))
    assert initiator is not None
    return initiator.as_metadata()


# Values that may stand under an `initiated_by` key of a new audit row.
_ACCEPTED: dict[str, object] = {
    "none": None,
    "unavailable": "unavailable",
    "service-account": _ACCOUNT_SHAPE,
    "system": Initiator.system(_ACTOR).as_metadata(),
    "system-with-record": _SYSTEM_SHAPE,
}

# Values that may not: every user encoding, and anything outside the
# allowlisted shapes.
_REFUSED: dict[str, object] = {
    "user-shape": _USER_SHAPE,
    "user-shape-from-caller": _user_shape_from_caller(),
    "user-initiator-object": Initiator.user(_USER),
    "service-account-initiator-object": Initiator.service_account(_USER),
    "bare-user-id": str(_USER),
    "bare-uuid-object": _USER,
    "user-id-hex": _USER.hex,
    "prefixed-user-id": f"user:{_USER}",
    "unavailable-other-case": "Unavailable",
    "empty-string": "",
    "empty-dict": {},
    "list-of-user-shape": [_USER_SHAPE],
    "list-of-service-account": [_ACCOUNT_SHAPE],
    "user-shape-uppercase-id": {"type": "user", "user_id": str(_USER).upper()},
    "user-type-uppercase": {"type": "USER", "user_id": str(_USER)},
    "service-account-with-user-id": {**_ACCOUNT_SHAPE, "user_id": str(_USER)},
    "service-account-wrong-field": {"type": "service_account", "user_id": str(_USER)},
    "system-with-user-id": {**Initiator.system(_ACTOR).as_metadata(), "user_id": str(_USER)},
    "system-with-nested-user": {
        **Initiator.system(_ACTOR).as_metadata(),
        "on_behalf_of": _USER_SHAPE,
    },
    "system-with-null-record": {
        **Initiator.system(_ACTOR).as_metadata(),
        "record_type": None,
        "record_id": None,
    },
    "unknown-type": {"type": "person", "user_id": str(_USER)},
    "number": 7,
    "boolean": True,
}

# Every place a value can sit: the top level of platform metadata, and
# nested in a dict, a list or a tuple of any metadata, under any spelling.
_PLACEMENTS: dict[str, Callable[[object], dict[str, object]]] = {
    "top-level": lambda v: {"initiated_by": v},
    "upper-case-key": lambda v: {"INITIATED_BY": v},
    "padded-key": lambda v: {" initiated_by\t": v},
    "nested-dict": lambda v: {"request": {"initiated_by": v}},
    "deeply-nested": lambda v: {"a": {"b": {"c": {"Initiated_By": v}}}},
    "in-a-list": lambda v: {"items": [{"x": 1}, {"initiated_by": v}]},
    "in-a-tuple": lambda v: {"items": ({"initiated_by": v},)},
    "list-in-list": lambda v: {"items": [[{"initiated_by": v}]]},
}


def _assert_no_id(error: BaseException) -> None:
    message = str(error)
    assert "D2" in message
    for spelling in (str(_USER), _USER.hex, str(_USER).upper()):
        assert spelling not in message


def test_the_allowlist_is_the_service_account_and_system_types() -> None:
    assert frozenset({InitiatorType.SERVICE_ACCOUNT, InitiatorType.SYSTEM}) == (
        AUDIT_INITIATOR_TYPES
    )
    assert InitiatorType.USER not in AUDIT_INITIATOR_TYPES
    # The typed check of the tenant writers uses the same set.
    assert audit_service._AUDIT_INITIATOR_TYPES is AUDIT_INITIATOR_TYPES


@pytest.mark.parametrize("placement", _PLACEMENTS.values(), ids=_PLACEMENTS)
@pytest.mark.parametrize("value", _ACCEPTED.values(), ids=_ACCEPTED)
def test_allowlisted_initiators_pass_anywhere(
    value: object, placement: Callable[[object], dict[str, object]]
) -> None:
    metadata = placement(value)
    refuse_user_initiators(metadata)
    validate_metadata(metadata)


@pytest.mark.parametrize("placement", _PLACEMENTS.values(), ids=_PLACEMENTS)
@pytest.mark.parametrize("value", _REFUSED.values(), ids=_REFUSED)
def test_anything_else_is_refused_anywhere_and_names_no_id(
    value: object, placement: Callable[[object], dict[str, object]]
) -> None:
    with pytest.raises(InvalidActorError) as refused:
        refuse_user_initiators(placement(value))
    _assert_no_id(refused.value)


def test_the_check_reads_every_initiated_by_key_not_only_the_first() -> None:
    metadata = {
        "initiated_by": "unavailable",
        "nested": {"initiated_by": _ACCOUNT_SHAPE},
        "list": [{"INITIATED_BY": None}, {"x": {"initiated_by": _USER_SHAPE}}],
    }
    with pytest.raises(InvalidActorError):
        refuse_user_initiators(metadata)


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {},
        {"user_id": str(_USER)},  # another key: not D2's (O1), not refused here
        {"initiator": _USER_SHAPE},  # another key name: product metadata (O5)
        {"initiated_by_count": 3},
        {"note": "initiated_by"},  # the word as a value, not a key
        {"items": ["initiated_by", {"type": "user"}]},
        {1: "x", None: "y"},
    ],
)
def test_metadata_without_an_initiated_by_key_is_not_this_checks_business(
    metadata: dict[object, object] | None,
) -> None:
    refuse_user_initiators(metadata)


def test_a_self_referencing_value_terminates_and_is_then_refused_as_not_json() -> None:
    loop: dict[str, object] = {"x": 1}
    loop["self"] = loop
    refuse_user_initiators(loop)  # no infinite loop
    items: list[object] = []
    items.append(items)
    refuse_user_initiators({"items": items})
    from saas_os.core.audit_log import MetadataNotJSONSerializableError

    with pytest.raises(MetadataNotJSONSerializableError):
        validate_metadata(loop)


def test_a_refused_initiator_is_never_rewritten_to_none() -> None:
    """D2 refuses: the caller's metadata is left exactly as given, never
    "fixed" by dropping or nulling the user initiator."""
    metadata: dict[str, object] = {"request": {"initiated_by": dict(_USER_SHAPE)}}
    with pytest.raises(InvalidActorError):
        refuse_user_initiators(metadata)
    assert metadata == {"request": {"initiated_by": _USER_SHAPE}}


# --- The tenant writers ------------------------------------------------------------


@pytest.fixture
def no_database(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """`record()`'s own transaction, replaced: what it would have written
    is collected instead, and nothing reaches a database."""
    written: list[object] = []

    @contextmanager
    def _scope(tenant_id: uuid.UUID) -> Iterator[MagicMock]:
        session = MagicMock()
        session.add.side_effect = written.append
        yield session

    monkeypatch.setattr(audit_service, "tenant_session_scope", _scope)
    return written


_CALLERS: dict[str, Callable[[], Caller]] = {
    "user": lambda: UserCaller(uuid.uuid4()),
    "service-account": lambda: ServiceAccountCaller(uuid.uuid4(), _TENANT),
    "system": lambda: SystemCaller(SystemAuthority.PROVISIONING),
    "attributed-system": lambda: SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR),
}
_NESTED = {
    k: v for k, v in _PLACEMENTS.items() if k not in {"top-level", "upper-case-key", "padded-key"}
}
_NESTED_USER = {
    "user-shape": _USER_SHAPE,
    "user-initiator-object": Initiator.user(_USER),
    "bare-user-id": str(_USER),
}


@pytest.mark.parametrize("placement", _NESTED.values(), ids=_NESTED)
@pytest.mark.parametrize("value", _NESTED_USER.values(), ids=_NESTED_USER)
def test_record_refuses_a_user_initiator_nested_in_metadata(
    value: object,
    placement: Callable[[object], dict[str, object]],
    no_database: list[object],
) -> None:
    with pytest.raises(InvalidActorError) as refused:
        record(
            tenant_id=_TENANT,
            actor_type=ActorType.USER,
            actor_user_id=uuid.uuid4(),
            action="x.y",
            resource_type="x",
            outcome=AuditOutcome.SUCCESS,
            metadata=placement(value),
        )
    _assert_no_id(refused.value)
    assert no_database == []


@pytest.mark.parametrize("caller", _CALLERS.values(), ids=_CALLERS)
@pytest.mark.parametrize("placement", _NESTED.values(), ids=_NESTED)
def test_record_in_transaction_refuses_a_user_initiator_nested_in_metadata(
    caller: Callable[[], Caller], placement: Callable[[object], dict[str, object]]
) -> None:
    session = MagicMock()
    with pytest.raises(InvalidActorError) as refused:
        record_in_transaction(
            session,
            caller=caller(),
            tenant_id=_TENANT,
            action="x.y",
            resource_type="x",
            metadata=placement(_USER_SHAPE),
        )
    _assert_no_id(refused.value)
    assert session.mock_calls == []


@pytest.mark.parametrize("placement", _NESTED.values(), ids=_NESTED)
def test_record_system_action_refuses_a_user_initiator_nested_in_metadata(
    placement: Callable[[object], dict[str, object]],
) -> None:
    """The typed argument is `None` (recorded as `"unavailable"`), so the
    user initiator could only arrive through the metadata: refused there."""
    session = MagicMock()
    with pytest.raises(InvalidActorError) as refused:
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            metadata=placement(_USER_SHAPE),
            initiated_by=None,
        )
    _assert_no_id(refused.value)
    assert session.mock_calls == []


@pytest.mark.parametrize("value", _NESTED_USER.values(), ids=_NESTED_USER)
def test_a_top_level_initiated_by_key_stays_reserved_in_tenant_metadata(
    value: object, no_database: list[object]
) -> None:
    """Unchanged from #196: a caller-supplied top-level `initiated_by` is
    refused as a reserved key, whatever it holds, before the D2 check."""
    with pytest.raises(ReservedMetadataKeyError):
        record(
            tenant_id=_TENANT,
            actor_type=ActorType.SYSTEM,
            action="x.y",
            resource_type="x",
            outcome=AuditOutcome.SUCCESS,
            metadata={"initiated_by": value},
        )
    session = MagicMock()
    with pytest.raises(ReservedMetadataKeyError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            metadata={"initiated_by": value},
        )
    assert no_database == [] and session.mock_calls == []


@pytest.mark.parametrize("value", _ACCEPTED.values(), ids=_ACCEPTED)
def test_tenant_writers_still_accept_allowlisted_initiators_nested_in_metadata(
    value: object, no_database: list[object]
) -> None:
    metadata: dict[str, object] = {"source": {"initiated_by": value}}
    entry = record(
        tenant_id=_TENANT,
        actor_type=ActorType.USER,
        actor_user_id=uuid.uuid4(),
        action="x.y",
        resource_type="x",
        outcome=AuditOutcome.SUCCESS,
        metadata=metadata,
    )
    assert no_database == [entry]
    assert entry.entry_metadata == metadata
    session = MagicMock()
    system_row = record_system_action_in_transaction(
        session,
        tenant_id=_TENANT,
        actor=_ACTOR,
        action="x.y",
        resource_type="x",
        metadata=metadata,
        initiated_by=Initiator.service_account(_USER),
    )
    session.add.assert_called_once_with(system_row)
    assert system_row.entry_metadata is not None
    assert system_row.entry_metadata["source"] == {"initiated_by": value}
    assert system_row.entry_metadata["initiated_by"] == _ACCOUNT_SHAPE


def test_the_metadata_check_also_guards_the_typed_attribution() -> None:
    """Defence in depth: the attribution `_attribution()` writes under the
    top-level `initiated_by` passes through the same metadata check in
    `_validated_entry()`. With the typed check bypassed, a user initiator
    is still refused there, before the insert."""
    session = MagicMock()
    forged = {"system_actor": _ACTOR.as_metadata(), "initiated_by": _USER_SHAPE}
    with pytest.raises(InvalidActorError) as refused:
        audit_service._validated_entry(
            tenant_id=_TENANT,
            actor_type=ActorType.SYSTEM,
            action="x.y",
            resource_type="x",
            outcome=AuditOutcome.SUCCESS,
            actor_user_id=None,
            actor_service_account_id=None,
            resource_id=None,
            correlation_id=None,
            metadata=forged,
            acting_as_tenant_id=None,
            delegation_grant_id=None,
            support_access_id=None,
        )
    _assert_no_id(refused.value)
    assert session.mock_calls == []


# --- Review of 25c9a77 (MEDIUM): a system initiator never carries a user id ---------

_PRINCIPAL_RECORD_TYPES = [
    "user",
    "users",
    "user_id",
    "userid",
    "username",
    "app_user",
    "my_product.user",
    "member",
    "membership",
    "tenant_member",
    "principal",
    "operator",
    "platform_operator",
    "person",
    "people",
    "identity",
    "external_identity",
    "subject",
    "owner",
    "actor",
    "account",
    "service_account",
    "my_product.service_accounts",
]
_RECORD_TYPES_STILL_ACCEPTED = [
    "provider_event",
    "unsubscribe_link",
    "link",
    "billing_account",
    "merchant_account",
    "invoice",
    "my_product.trial",
]


@pytest.mark.parametrize("record_type", _PRINCIPAL_RECORD_TYPES)
def test_a_system_initiator_record_type_never_names_a_principal(record_type: str) -> None:
    with pytest.raises(InvalidSystemActorError) as refused:
        Initiator.system(_ACTOR, record_type=record_type, record_id=_USER)
    assert refused.value.field == "record_type"
    _assert_no_id_or_value(refused.value, record_type)


@pytest.mark.parametrize("record_type", _RECORD_TYPES_STILL_ACCEPTED)
def test_record_types_naming_a_record_are_still_accepted(record_type: str) -> None:
    initiator = Initiator.system(_ACTOR, record_type=record_type, record_id=uuid.uuid4())
    assert initiator.as_metadata()["record_type"] == record_type


@pytest.mark.parametrize(
    "record_id",
    ["user:42", "user-alice", "member_7", "operator.1", "service_account:x", "account-9"],
)
def test_a_system_initiator_record_id_never_starts_with_a_principal(record_id: str) -> None:
    with pytest.raises(InvalidSystemActorError) as refused:
        Initiator.system(_ACTOR, record_type="provider_event", record_id=record_id)
    assert refused.value.field == "record_id"


@pytest.mark.parametrize("record_id", ["evt_1", "evt_1QuserAbc", "l-1", "cus_x", "acct_1"])
def test_opaque_record_ids_are_still_accepted(record_id: str) -> None:
    """Only the first word of a record id counts, so a random tail that
    happens to contain `user` is not refused."""
    Initiator.system(_ACTOR, record_type="provider_event", record_id=record_id)


@pytest.mark.parametrize(
    "name",
    [
        f"user.{_USER}",
        f"job-{_USER.hex}",
        f"my_product.{str(_USER).replace('-', '')}",
        f"{_USER}",
    ],
)
def test_a_system_actor_name_never_embeds_an_id(name: str) -> None:
    with pytest.raises(InvalidSystemActorError) as refused:
        SystemActor(SystemActorKind.MAINTENANCE, name)
    assert refused.value.field == "name"
    _assert_no_id_or_value(refused.value, name)


@pytest.mark.parametrize("record_type", [f"x_{_USER.hex}", f"x.{_USER}"])
def test_a_record_type_never_embeds_an_id(record_type: str) -> None:
    with pytest.raises(InvalidSystemActorError):
        Initiator.system(_ACTOR, record_type=record_type, record_id="r-1")


@pytest.mark.parametrize(
    "shape",
    [
        {"type": "system", **_ACTOR.as_metadata(), "record_type": "user", "record_id": str(_USER)},
        {"type": "system", **_ACTOR.as_metadata(), "record_type": "link", "record_id": "user:1"},
        {"type": "system", "kind": "maintenance", "name": f"user.{_USER}"},
    ],
    ids=["record-type-user", "record-id-user", "actor-name-embeds-id"],
)
def test_a_serialized_system_shape_encoding_a_user_is_refused_by_the_metadata_check(
    shape: dict[str, object],
) -> None:
    """Already-serialized dicts go through `Initiator.from_metadata`, which
    builds the `Initiator` and so applies the same construction rules."""
    for placement in _PLACEMENTS.values():
        with pytest.raises(InvalidActorError):
            refuse_user_initiators(placement(shape))
    with pytest.raises(InvalidSystemActorError):
        Initiator.from_metadata(shape)


def test_the_typed_writers_cannot_be_handed_such_a_system_initiator() -> None:
    """The refusal happens when the value is built, before any writer."""
    with pytest.raises(InvalidSystemActorError):
        record_system_action_in_transaction(
            MagicMock(),
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            initiated_by=Initiator.system(_ACTOR, record_type="user", record_id=_USER),
        )


def _assert_no_id_or_value(error: BaseException, value: str) -> None:
    """The message names the field, never the rejected value (a bare word
    such as `user` may of course appear in the fixed reason)."""
    message = str(error)
    if len(value) > 12:
        assert value not in message
    for spelling in (str(_USER), _USER.hex):
        assert spelling not in message
