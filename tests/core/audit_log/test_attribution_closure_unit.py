"""Final closure of owner decision D2 (owner, 2026-11-03), tenant writers and
the shared metadata contract -- hermetic.

What a tenant audit row stores is never a caller-supplied object:

- metadata is stored as `trusted_metadata()`'s plain-JSON copy, in which
  every `initiated_by`, `correlation` and `system_actor` value -- under any
  spelling of the key (case, padding, `_ - .` separators, a `str` subclass)
  and at any depth -- is rebuilt through the constructor of `Initiator`
  (service-account or system), `SystemCorrelation` or `SystemActor`, or
  refused with `InvalidActorError` naming no value;
- the typed `correlation=` argument is rebuilt from its exact-type-checked
  fields through `SystemCorrelation`'s constructor, which refuses an id
  naming a user or other principal; real producers (arq job ids, cron job
  ids, generated request ids, outbox event ids) keep working;
- the actor columns and the system purpose are rebuilt from the caller's
  fields.

Legitimate metadata is stored equal to the input, to the same bytes. The
platform writers are covered in
`tests/core/platform_authority/test_platform_audit_attribution_closure_unit.py`;
the database-backed versions are in
`tests/core/platform_authority/test_audit_initiator_gate_integration.py`.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from saas_os.core.audit_log import (
    ActorType,
    AuditOutcome,
    InvalidActorError,
    MetadataNotJSONSerializableError,
    ReservedMetadataKeyError,
    record,
    record_in_transaction,
    record_system_action_in_transaction,
)
from saas_os.core.audit_log import service as audit_service
from saas_os.core.audit_log.metadata import (
    attribution_key,
    trusted_metadata,
    validate_metadata,
)
from saas_os.core.authority import (
    Initiator,
    InvalidSystemActorError,
    ServiceAccountCaller,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    SystemCorrelation,
    UserCaller,
)

_USER = uuid.uuid4()
_TENANT = uuid.uuid4()
_EVENT = uuid.uuid4()
_ACTOR = SystemActor(SystemActorKind.WORKER_JOB, "outbox.webhook_delivery")
_USER_SHAPE = {"type": "user", "user_id": str(_USER)}
_ACCOUNT_SHAPE = {"type": "service_account", "service_account_id": str(uuid.uuid4())}


class _LyingKey(str):
    """A key whose own string methods lie about what it is."""

    __slots__ = ()

    def strip(self, *args: object) -> str:  # type: ignore[override]
        return "harmless"

    def lower(self) -> str:  # type: ignore[override]
        return "harmless"

    def translate(self, *args: object) -> str:  # type: ignore[override]
        return "harmless"

    def __eq__(self, other: object) -> bool:
        return False

    __hash__ = str.__hash__


class _LyingStr(str):
    __slots__ = ()


class _LyingUUID(uuid.UUID):
    """A UUID subclass whose text says something else."""

    __slots__ = ()

    def __str__(self) -> str:
        return "not-the-real-id"

    @property
    def hex(self) -> str:  # type: ignore[override]
        return "0" * 32


def _assert_names_nothing(error: BaseException, *values: str) -> None:
    message = str(error)
    assert "D2" in message
    for value in (str(_USER), _USER.hex, *values):
        assert value not in message


def _walk_types(value: object) -> set[type]:
    found = {type(value)}
    if isinstance(value, dict):
        for key, nested in value.items():
            found |= {type(key)} | _walk_types(nested)
    elif isinstance(value, list):
        for item in value:
            found |= _walk_types(item)
    return found


_PLAIN_TYPES = {dict, list, str, int, float, bool, type(None)}


@pytest.fixture
def no_database(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    written: list[object] = []

    @contextmanager
    def _scope(tenant_id: uuid.UUID) -> Iterator[MagicMock]:
        session = MagicMock()
        session.add.side_effect = written.append
        yield session

    monkeypatch.setattr(audit_service, "tenant_session_scope", _scope)
    return written


def _write_record(metadata: dict[str, object]) -> object:
    return record(
        tenant_id=_TENANT,
        actor_type=ActorType.USER,
        actor_user_id=uuid.uuid4(),
        action="x.y",
        resource_type="x",
        outcome=AuditOutcome.SUCCESS,
        metadata=metadata,
    )


def _write_in_transaction(metadata: dict[str, object]) -> object:
    return record_in_transaction(
        MagicMock(),
        caller=SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR),
        tenant_id=_TENANT,
        action="x.y",
        resource_type="x",
        metadata=metadata,
    )


def _write_system_action(metadata: dict[str, object]) -> object:
    return record_system_action_in_transaction(
        MagicMock(),
        tenant_id=_TENANT,
        actor=_ACTOR,
        action="x.y",
        resource_type="x",
        metadata=metadata,
    )


_WRITERS: dict[str, Callable[[dict[str, object]], object]] = {
    "record": _write_record,
    "record_in_transaction": _write_in_transaction,
    "record_system_action": _write_system_action,
}


# --- Key spellings ----------------------------------------------------------------

_SPELLINGS = {
    "camel-case": "initiatedBy",
    "hyphen": "initiated-by",
    "title-hyphen-padded": " Initiated-By ",
    "dots": "INITIATED.BY",
    "space": "initiated by",
    "no-separator": "initiatedby",
    "lying-str-subclass": _LyingKey("initiated_by"),
    # Unicode padding the old `strip()` removed (re-review of `ef0e7e1`).
    "no-break-space": "\u00a0initiated_by",
    "em-space": "initiated_by\u2003",
    "vertical-tab": "\x0binitiated_by",
    "form-feed": "initiated_by\x0c",
    "next-line": "\x85initiated_by",
    # Compatibility, format and combining characters, other separators.
    "dotted-capital-i": "\u0130nitiated_by",
    "fullwidth": "\uff49\uff4e\uff49\uff54\uff49\uff41\uff54\uff45\uff44\uff3f\uff42\uff59",
    "zero-width-space": "initiated\u200b_by",
    "word-joiner": "INITIATED\u2060BY",
    "slash": "initiated/by",
    "colon": "initiated:by",
}


@pytest.mark.parametrize("spelling", _SPELLINGS.values(), ids=_SPELLINGS)
def test_every_spelling_of_initiated_by_is_the_same_key(spelling: str) -> None:
    assert attribution_key(spelling) == "initiated_by"


@pytest.mark.parametrize(
    "key", ["initiator", "initiated", "initiated_by_job", "corr", "actor", "system", 7, None]
)
def test_other_keys_are_not_attribution_keys(key: object) -> None:
    assert attribution_key(key) is None


@pytest.mark.parametrize("writer", _WRITERS.values(), ids=_WRITERS)
@pytest.mark.parametrize("spelling", _SPELLINGS.values(), ids=_SPELLINGS)
def test_a_user_initiator_under_any_spelling_is_refused_by_every_tenant_writer(
    spelling: str, writer: Callable[[dict[str, object]], object], no_database: list[object]
) -> None:
    with pytest.raises(InvalidActorError) as refused:
        writer({"request": {spelling: dict(_USER_SHAPE)}})
    _assert_names_nothing(refused.value)
    assert no_database == []


@pytest.mark.parametrize(
    "key",
    [
        "initiatedBy",
        "Initiated-By",
        "CORRELATION ",
        "system-actor",
        "systemActor",
        "\u00a0initiated_by",
        "\x85correlation",
        "system_actor\x0b",
        "\u0130nitiated_by",
        "initiated\u200b_by",
        "system/actor",
        "\uff43\uff4f\uff52\uff52\uff45\uff4c\uff41\uff54\uff49\uff4f\uff4e",
    ],
)
def test_a_top_level_attribution_key_under_any_spelling_stays_reserved(
    key: str, no_database: list[object]
) -> None:
    for writer in _WRITERS.values():
        with pytest.raises(ReservedMetadataKeyError):
            writer({key: "unavailable"})
    assert no_database == []


@pytest.mark.parametrize("key", ["systemAuthority", "System-Authority"])
def test_system_authority_stays_reserved_for_the_system_action_writer(key: str) -> None:
    with pytest.raises(ReservedMetadataKeyError):
        _write_system_action({key: "provisioning"})


# --- Nested correlation and system_actor values -----------------------------------

_REFUSED_CORRELATIONS: dict[str, object] = {
    "user-id-field": {"user_id": str(_USER)},
    "request-id-names-a-user": {"request_id": f"user:{_USER}"},
    "request-id-user-hex": {"request_id": f"user_{_USER.hex}"},
    "arq-job-id-names-a-member": {"arq_job_id": "member-17"},
    "arq-job-id-service-account": {"arq_job_id": f"service_account:{_USER}"},
    "request-id-operator": {"request_id": "operator.42"},
    "credential-shape": {"request_id": "sok_abcdef"},
    "extra-field": {"request_id": "r-1", "initiated_by": "unavailable"},
    "upper-case-event-id": {"outbox_event_id": str(_EVENT).upper()},
    "hex-event-id": {"outbox_event_id": _EVENT.hex},
    "event-id-not-a-uuid": {"outbox_event_id": "evt-1"},
    "number-value": {"arq_job_id": 7},
    "nested-dict-value": {"request_id": {"user_id": str(_USER)}},
    "too-long": {"request_id": "r" * 101},
    "a-list": [{"request_id": "r-1"}],
    "a-string": "r-1",
    "a-correlation-object": SystemCorrelation(request_id="r-1"),
}

_ACCEPTED_CORRELATIONS: dict[str, object] = {
    "none": None,
    "empty": {},
    "arq-hex-job-id": {"arq_job_id": uuid.uuid4().hex},
    "cron-job-id": {"arq_job_id": "cron:cleanup_sessions:1730600000000"},
    "generated-request-id": {"request_id": str(uuid.uuid4())},
    "client-request-id": {"request_id": "req-7Hk2_abc.def"},
    "event-id": {"outbox_event_id": str(_EVENT)},
    "all-three": SystemCorrelation(
        arq_job_id=uuid.uuid4().hex, outbox_event_id=_EVENT, request_id="r-1"
    ).as_metadata(),
}

_REFUSED_ACTORS: dict[str, object] = {
    "extra-user-id": {"kind": "worker_job", "name": "a", "user_id": str(_USER)},
    "name-embeds-an-id": {"kind": "worker_job", "name": f"job_{_USER.hex}"},
    "missing-name": {"kind": "worker_job"},
    "unknown-kind": {"kind": "person", "name": "a"},
    "upper-case-name": {"kind": "worker_job", "name": "Job"},
    "a-string": "worker_job",
    "an-actor-object": _ACTOR,
}

_ACCEPTED_ACTORS: dict[str, object] = {
    "none": None,
    "worker-job": _ACTOR.as_metadata(),
    "public-link": {"kind": "public_link", "name": "my_product.unsubscribe"},
}


@pytest.mark.parametrize("writer", _WRITERS.values(), ids=_WRITERS)
@pytest.mark.parametrize("value", _REFUSED_CORRELATIONS.values(), ids=_REFUSED_CORRELATIONS)
def test_a_nested_correlation_carrying_identity_or_an_odd_shape_is_refused(
    value: object, writer: Callable[[dict[str, object]], object], no_database: list[object]
) -> None:
    with pytest.raises(InvalidActorError) as refused:
        writer({"origin": {"Correlation": value}})
    _assert_names_nothing(refused.value, "member-17", "operator.42")
    assert no_database == []


@pytest.mark.parametrize("writer", _WRITERS.values(), ids=_WRITERS)
@pytest.mark.parametrize("value", _REFUSED_ACTORS.values(), ids=_REFUSED_ACTORS)
def test_a_nested_system_actor_with_an_odd_shape_is_refused(
    value: object, writer: Callable[[dict[str, object]], object], no_database: list[object]
) -> None:
    with pytest.raises(InvalidActorError) as refused:
        writer({"items": [{"system-actor": value}]})
    _assert_names_nothing(refused.value)
    assert no_database == []


@pytest.mark.parametrize("value", _ACCEPTED_CORRELATIONS.values(), ids=_ACCEPTED_CORRELATIONS)
def test_a_nested_recorded_correlation_is_stored_rebuilt_and_equal(value: object) -> None:
    entry = _write_system_action({"origin": {"correlation": value}})
    stored = entry.entry_metadata["origin"]["correlation"]  # type: ignore[attr-defined]
    assert stored == value
    assert value is None or stored is not value
    assert _walk_types(stored) <= _PLAIN_TYPES


@pytest.mark.parametrize("value", _ACCEPTED_ACTORS.values(), ids=_ACCEPTED_ACTORS)
def test_a_nested_recorded_system_actor_is_stored_rebuilt_and_equal(value: object) -> None:
    entry = _write_system_action({"origin": {"system_actor": value}})
    stored = entry.entry_metadata["origin"]["system_actor"]  # type: ignore[attr-defined]
    assert stored == value
    assert _walk_types(stored) <= _PLAIN_TYPES


# --- The stored copy ---------------------------------------------------------------


def test_the_stored_metadata_is_a_plain_copy_never_the_callers_objects() -> None:
    inner = {"initiated_by": dict(_ACCOUNT_SHAPE)}
    given: dict[str, object] = {
        "tuple": ("a", 1),
        "subclass_value": _LyingStr("plain"),
        "inner": inner,
        "lying_key": {_LyingKey("note"): 1},
    }
    for writer in (_write_in_transaction, _write_system_action):
        entry = writer(given)
        stored = entry.entry_metadata  # type: ignore[attr-defined]
        assert stored is not given
        assert stored["inner"] is not inner
        assert stored["inner"]["initiated_by"] is not inner["initiated_by"]
        assert stored["tuple"] == ["a", 1]
        assert _walk_types(stored) <= _PLAIN_TYPES


def test_a_user_initiator_in_unserializable_metadata_is_refused_as_a_user_initiator() -> None:
    with pytest.raises(InvalidActorError):
        trusted_metadata({"x": {"initiated_by": dict(_USER_SHAPE)}, "y": object()})
    with pytest.raises(MetadataNotJSONSerializableError):
        trusted_metadata({"y": object()})


_LEGITIMATE: dict[str, dict[str, object]] = {
    "role-grant": {"service_account_id": str(uuid.uuid4()), "role_id": str(uuid.uuid4())},
    "billing-purpose": {"system_authority": "billing_operations", "provider": "stripe"},
    "plain-values": {
        "changes": [{"field": "name", "old": "Zoë", "new": "Ζ"}],
        "ratio": 0.1,
        "flag": True,
        "none": None,
        "count": 2**40,
    },
    "nested-recorded-initiator": {"origin": {"initiated_by": dict(_ACCOUNT_SHAPE)}},
    "nested-unavailable": {"origin": {"initiated_by": "unavailable"}},
    "nested-correlation": {"origin": {"correlation": {"outbox_event_id": str(_EVENT)}}},
}


@pytest.mark.parametrize("metadata", _LEGITIMATE.values(), ids=_LEGITIMATE)
def test_legitimate_metadata_is_stored_equal_to_the_same_bytes(
    metadata: dict[str, object],
) -> None:
    stored = trusted_metadata(metadata)
    assert stored == metadata
    assert json.dumps(stored) == json.dumps(metadata)


def test_a_real_job_attribution_is_stored_to_the_exact_bytes() -> None:
    """A representative producer: an outbox consumer's job context."""
    job_id = "5f0c6a3e9b2d4c1a8e7f6d5c4b3a2918"
    context = SimpleNamespace(job_id=job_id, event_id=_EVENT, correlation_id="req-1")
    entry = record_system_action_in_transaction(
        MagicMock(),
        tenant_id=_TENANT,
        actor=_ACTOR,
        action="webhook.delivered",
        resource_type="webhook",
        metadata={"attempt": 1},
        initiated_by=Initiator.system(
            SystemActor(SystemActorKind.PROVIDER_EVENT_PROCESSOR, "stripe"),
            record_type="provider_event",
            record_id="evt_1NqXyZ",
        ),
        correlation=SystemCorrelation.from_job_context(context),
    )
    assert json.dumps(entry.entry_metadata) == (
        '{"attempt": 1, "system_actor": {"kind": "worker_job", "name": '
        '"outbox.webhook_delivery"}, "initiated_by": {"type": "system", "kind": '
        '"provider_event_processor", "name": "stripe", "record_type": "provider_event", '
        f'"record_id": "evt_1NqXyZ"}}, "correlation": {{"arq_job_id": "{job_id}", '
        f'"outbox_event_id": "{_EVENT}", "request_id": "req-1"}}}}'
    )


# --- SystemCorrelation's construction rules ---------------------------------------

_PRINCIPAL_IDS = [
    f"user:{_USER}",
    f"user_{_USER.hex}",
    f"users-{_USER}",
    "username.alice",
    "member-17",
    "operator:1",
    "principal.x",
    f"service_account:{_USER}",
    f"service-accounts.{_USER.hex}",
    "account:1",
    "Owner-1",
]


@pytest.mark.parametrize("value", _PRINCIPAL_IDS)
@pytest.mark.parametrize("field", ["arq_job_id", "request_id"])
def test_a_correlation_id_never_names_a_principal(field: str, value: str) -> None:
    with pytest.raises(InvalidSystemActorError) as refused:
        SystemCorrelation(**{field: value})  # type: ignore[arg-type]
    assert value not in str(refused.value)
    assert "D2" in str(refused.value)


@pytest.mark.parametrize(
    "value",
    [
        uuid.uuid4().hex,  # arq's default job id
        str(uuid.uuid4()),  # the middleware's generated request id
        "cron:cleanup_sessions:1730600000000",  # arq's cron job id
        "cron:user_cleanup:1730600000000",  # a principal word after the prefix
        "req-7Hk2_abc.def",
        "evt_1QuserAbc",
        "billing_account:1",
    ],
)
@pytest.mark.parametrize("field", ["arq_job_id", "request_id"])
def test_real_correlation_ids_are_still_accepted(field: str, value: str) -> None:
    correlation = SystemCorrelation(**{field: value})  # type: ignore[arg-type]
    assert correlation.as_metadata() == {field: value}


def test_a_job_context_correlation_id_naming_a_principal_is_left_out() -> None:
    context = SimpleNamespace(job_id=f"user:{_USER}", event_id=_EVENT, correlation_id="member-1")
    assert SystemCorrelation.from_job_context(context) == SystemCorrelation(outbox_event_id=_EVENT)
    legit = SimpleNamespace(job_id="abc123", event_id=None, correlation_id=str(_EVENT))
    assert SystemCorrelation.from_job_context(legit).as_metadata() == {
        "arq_job_id": "abc123",
        "request_id": str(_EVENT),
    }


# --- Forged typed correlation, actor ids and purpose ------------------------------


class _AlwaysEqual(dict):  # type: ignore[type-arg]
    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False

    __hash__ = None  # type: ignore[assignment]


def _write_with_correlation(correlation: object, *, typed_writer: str = "system_action") -> object:
    if typed_writer == "system_action":
        return record_system_action_in_transaction(
            MagicMock(),
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            correlation=correlation,  # type: ignore[arg-type]
        )
    return record_in_transaction(
        MagicMock(),
        caller=SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR),
        tenant_id=_TENANT,
        action="x.y",
        resource_type="x",
        correlation=correlation,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("typed_writer", ["system_action", "in_transaction"])
def test_a_forged_correlation_shape_is_never_stored_only_the_rebuilt_one(
    typed_writer: str,
) -> None:
    forged = SystemCorrelation(request_id="r-1", outbox_event_id=_EVENT)
    object.__setattr__(forged, "as_metadata", lambda: _AlwaysEqual(user_id=str(_USER)))
    entry = _write_with_correlation(forged, typed_writer=typed_writer)
    stored = entry.entry_metadata["correlation"]  # type: ignore[attr-defined]
    assert type(stored) is dict
    assert stored == {"outbox_event_id": str(_EVENT), "request_id": "r-1"}
    assert str(_USER) not in repr(entry.entry_metadata)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", f"user:{_USER}"),  # names a principal
        ("arq_job_id", "member-1"),
        ("request_id", 7),  # wrong type
        ("request_id", _LyingStr("r-1")),  # not exactly a str
        ("outbox_event_id", str(_EVENT)),  # a str, not a UUID
        ("outbox_event_id", _LyingUUID(int=_EVENT.int)),  # not exactly a UUID
        ("request_id", "sok_abc"),  # a credential shape
    ],
)
@pytest.mark.parametrize("typed_writer", ["system_action", "in_transaction"])
def test_a_forged_correlation_field_is_refused(
    field: str, value: object, typed_writer: str
) -> None:
    forged = SystemCorrelation(request_id="r-1")
    object.__setattr__(forged, field, value)
    with pytest.raises(InvalidActorError) as refused:
        _write_with_correlation(forged, typed_writer=typed_writer)
    _assert_names_nothing(refused.value, "member-1")


def test_the_actor_columns_are_rebuilt_never_the_callers_id_objects() -> None:
    lying = _LyingUUID(int=_USER.int)
    entry = record_in_transaction(
        MagicMock(), caller=UserCaller(lying), tenant_id=_TENANT, action="x.y", resource_type="x"
    )
    assert type(entry.actor_user_id) is uuid.UUID
    assert entry.actor_user_id == _USER
    account = ServiceAccountCaller(_LyingUUID(int=_EVENT.int), _TENANT)
    entry = record_in_transaction(
        MagicMock(), caller=account, tenant_id=_TENANT, action="x.y", resource_type="x"
    )
    assert type(entry.actor_service_account_id) is uuid.UUID
    assert entry.actor_service_account_id == _EVENT


def test_a_forged_system_purpose_is_refused_and_a_real_one_is_looked_up() -> None:
    forged = SystemCaller(SystemAuthority.PROVISIONING)
    object.__setattr__(forged, "authority", SimpleNamespace(value=str(_USER)))
    with pytest.raises(InvalidActorError):
        record_in_transaction(
            MagicMock(), caller=forged, tenant_id=_TENANT, action="x.y", resource_type="x"
        )
    entry = record_in_transaction(
        MagicMock(),
        caller=SystemCaller(SystemAuthority.TENANT_PURGE),
        tenant_id=_TENANT,
        action="x.y",
        resource_type="x",
    )
    stored = entry.entry_metadata["system_authority"]  # type: ignore[index]
    assert type(stored) is str and stored == "tenant_purge"


# --- Odd shapes refused as not serializable (re-review of `ef0e7e1`) --------------


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


@pytest.mark.parametrize(
    "metadata",
    [
        {"deep": _deep(3000)},
        {"ratio": float("nan")},
        {"x": [float("inf")]},
        {"x": {"y": -float("inf")}},
    ],
    ids=["nested-3000-deep", "nan", "infinity", "minus-infinity"],
)
@pytest.mark.parametrize("writer", _WRITERS.values(), ids=_WRITERS)
def test_metadata_nested_too_deep_or_not_finite_is_refused_as_not_serializable(
    metadata: dict[str, object],
    writer: Callable[[dict[str, object]], object],
    no_database: list[object],
) -> None:
    with pytest.raises(MetadataNotJSONSerializableError):
        writer(metadata)
    with pytest.raises(MetadataNotJSONSerializableError):
        validate_metadata(metadata)
    assert no_database == []


def test_finite_floats_are_still_stored_to_the_same_bytes() -> None:
    metadata: dict[str, object] = {"ratio": 0.1, "big": 1e300, "neg": -2.5}
    assert json.dumps(trusted_metadata(metadata)) == json.dumps(metadata)
