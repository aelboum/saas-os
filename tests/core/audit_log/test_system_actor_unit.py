"""ADR 0061 step 1 -- `SystemActor` attribution, without a database.

- `SystemActor` validates every field at construction (closed kinds, short
  identifiers) and names the executing component only.
- Owner decision C: `Initiator` (who or what originally requested the
  action, or "unavailable") and `SystemCorrelation` (arq job id, outbox
  event id, request id) are distinct values, validated the same way; a
  system initiator never carries a user id.
- It is attribution, never authority: `require_caller()` refuses it, and a
  `SystemCaller` carrying an actor is authorized exactly as one without.
- The audit service refuses a caller-supplied `system_actor` metadata key
  before any write, writes the actor in a fixed shape, and warns (without
  refusing) on a successful `system` row through `record()` that carries
  neither a purpose nor an actor.
- The job wrapper derives the actor a handler's context carries.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
import warnings
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from saas_os.core.audit_log import (
    ActorType,
    AuditLogEntry,
    AuditOutcome,
    ForbiddenMetadataKeyError,
    InvalidActorError,
    ReservedMetadataKeyError,
    record,
    record_in_transaction,
    record_system_action_in_transaction,
)
from saas_os.core.audit_log import service as audit_service
from saas_os.core.audit_log.metadata import trusted_metadata
from saas_os.core.authority import (
    INITIATOR_UNAVAILABLE,
    Caller,
    CallerTypeError,
    Initiator,
    InitiatorType,
    InvalidSystemActorError,
    ServiceAccountCaller,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    SystemCorrelation,
    UserCaller,
    require_caller,
)
from saas_os.core.billing.authorization import authorize_billing
from saas_os.core.billing.errors import BillingNotAuthorizedError
from saas_os.core.platform_authority import (
    PLATFORM_OPERATIONS,
    authorize_platform_caller,
    platform_caller_could_hold_any,
)
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import authorize_caller
from saas_os.infra.jobs import (
    JobActor,
    JobInitiator,
    JobKind,
    SystemJobContext,
    TenantJobContext,
)
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.payload import TenantJobPayload
from saas_os.infra.jobs.queue import _with_retry_and_dead_letter

_ACTOR = SystemActor(SystemActorKind.WORKER_JOB, "nightly_export")
_TENANT = uuid.uuid4()


# --- Validation ---------------------------------------------------------------------


def test_the_kind_list_is_closed_and_owned_by_core() -> None:
    assert {kind.value for kind in SystemActorKind} == {
        "worker_job",
        "scheduled_job",
        "webhook_processor",
        "provider_event_processor",
        "inbound_processor",
        "public_link",
        "maintenance",
        "billing_process",
    }


@pytest.mark.parametrize("kind", ["worker_job", "robot", None, 1])
def test_an_unknown_or_untyped_kind_is_refused(kind: object) -> None:
    with pytest.raises(InvalidSystemActorError) as excinfo:
        SystemActor(kind, "x")  # type: ignore[arg-type]
    assert excinfo.value.field == "kind"


@pytest.mark.parametrize(
    "name",
    ["", "Upper", "has space", "slash/name", "x" * 101, "nul\x00", "émoji", None, 7],
)
def test_a_bad_name_is_refused(name: object) -> None:
    with pytest.raises(InvalidSystemActorError) as excinfo:
        SystemActor(SystemActorKind.MAINTENANCE, name)  # type: ignore[arg-type]
    assert excinfo.value.field == "name"


def test_an_actor_names_the_executor_only() -> None:
    """Owner decision C: no initiator and no job id on the executing actor."""
    assert list(SystemActor.__dataclass_fields__) == ["kind", "name"]
    with pytest.raises(TypeError):
        SystemActor(SystemActorKind.WORKER_JOB, "x", "arq_job", "job-1")  # type: ignore[call-arg]
    assert _ACTOR.as_metadata() == {"kind": "worker_job", "name": "nightly_export"}


# --- The initiating actor (owner decision C) -------------------------------------------

_LINK = SystemActor(SystemActorKind.PUBLIC_LINK, "unsubscribe")


def test_the_initiator_types_are_closed_and_owned_by_core() -> None:
    assert {t.value for t in InitiatorType} == {"user", "service_account", "system"}
    assert INITIATOR_UNAVAILABLE == "unavailable"


def test_the_three_initiator_shapes() -> None:
    user_id, account_id, link_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    assert Initiator.user(user_id).as_metadata() == {"type": "user", "user_id": str(user_id)}
    assert Initiator.service_account(account_id).as_metadata() == {
        "type": "service_account",
        "service_account_id": str(account_id),
    }
    assert Initiator.system(_LINK).as_metadata() == {
        "type": "system",
        "kind": "public_link",
        "name": "unsubscribe",
    }
    assert Initiator.system(
        _LINK, record_type="unsubscribe_link", record_id=link_id
    ).as_metadata() == {
        "type": "system",
        "kind": "public_link",
        "name": "unsubscribe",
        "record_type": "unsubscribe_link",
        "record_id": str(link_id),
    }


@pytest.mark.parametrize("record_type", ["", "Outbox", "a b", "y" * 101])
def test_a_bad_record_type_is_refused(record_type: str) -> None:
    with pytest.raises(InvalidSystemActorError):
        Initiator.system(_LINK, record_type=record_type, record_id="id-1")


@pytest.mark.parametrize(
    ("record_type", "record_id"),
    [
        ("link_token", "abc"),  # the type names a credential
        ("webhook_secret", "abc"),
        ("session_cookie", "abc"),
        ("user_api_key", "abc"),
        ("public_link", "sok_" + "a" * 40),  # pragma: allowlist secret
        ("provider_event", "eyJhbGciOiJIUzI1NiJ9.e30.sig"),  # pragma: allowlist secret
        ("public_link", "Bearer abc"),
        ("public_link", "a+b/c=="),
        ("public_link", "z" * 101),
        ("public_link", ""),
        ("public_link", 12345),
    ],
)
def test_a_token_like_initiator_record_is_refused(record_type: str, record_id: object) -> None:
    with pytest.raises(InvalidSystemActorError):
        Initiator.system(_LINK, record_type=record_type, record_id=record_id)  # type: ignore[arg-type]


def test_the_initiator_record_is_given_whole_or_not_at_all() -> None:
    with pytest.raises(InvalidSystemActorError):
        Initiator.system(_LINK, record_type="unsubscribe_link")
    with pytest.raises(InvalidSystemActorError):
        Initiator.system(_LINK, record_id=uuid.uuid4())


_INCONSISTENT_INITIATORS = {
    "user-without-id": lambda: Initiator(InitiatorType.USER),
    "user-with-str-id": lambda: Initiator(InitiatorType.USER, principal_id="x"),  # type: ignore[arg-type]
    "account-without-id": lambda: Initiator(InitiatorType.SERVICE_ACCOUNT),
    "user-with-actor": lambda: Initiator(
        InitiatorType.USER, principal_id=uuid.uuid4(), system_actor=_LINK
    ),
    "user-with-record": lambda: Initiator(
        InitiatorType.USER, principal_id=uuid.uuid4(), record_type="x", record_id="y"
    ),
    # A system initiator never carries a user id, and must name a SystemActor.
    "system-with-user-id": lambda: Initiator(
        InitiatorType.SYSTEM, principal_id=uuid.uuid4(), system_actor=_LINK
    ),
    "system-without-actor": lambda: Initiator(InitiatorType.SYSTEM),
    "system-with-dict-actor": lambda: Initiator(
        InitiatorType.SYSTEM,
        system_actor={"kind": "public_link"},  # type: ignore[arg-type]
    ),
    "untyped": lambda: Initiator("user", principal_id=uuid.uuid4()),  # type: ignore[arg-type]
}


@pytest.mark.parametrize("case", sorted(_INCONSISTENT_INITIATORS))
def test_an_inconsistent_initiator_is_refused(case: str) -> None:
    with pytest.raises(InvalidSystemActorError):
        _INCONSISTENT_INITIATORS[case]()


def test_an_initiator_is_derived_from_a_caller_never_invented() -> None:
    user_id, account_id = uuid.uuid4(), uuid.uuid4()
    assert Initiator.from_caller(UserCaller(user_id)) == Initiator.user(user_id)
    assert Initiator.from_caller(ServiceAccountCaller(account_id, _TENANT)) == (
        Initiator.service_account(account_id)
    )
    # A purpose is an authority, not an initiator: unavailable without an actor.
    assert Initiator.from_caller(SystemCaller(SystemAuthority.PROVISIONING)) is None
    attributed = SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR)
    assert Initiator.from_caller(attributed) == Initiator.system(_ACTOR)
    assert "user_id" not in Initiator.system(_ACTOR).as_metadata()
    for not_a_caller in (_ACTOR, None, user_id, {"type": "user"}):
        with pytest.raises(CallerTypeError):
            Initiator.from_caller(not_a_caller)


def test_a_recorded_initiator_round_trips_and_unavailable_is_none() -> None:
    for initiator in (
        Initiator.user(uuid.uuid4()),
        Initiator.service_account(uuid.uuid4()),
        Initiator.system(_LINK, record_type="unsubscribe_link", record_id="link-1"),
        Initiator.system(_ACTOR),
    ):
        assert Initiator.from_metadata(initiator.as_metadata()) == initiator
    assert Initiator.from_metadata(None) is None
    assert Initiator.from_metadata(INITIATOR_UNAVAILABLE) is None


@pytest.mark.parametrize(
    "stored",
    [
        "someone",
        ["user"],
        {"type": "admin", "user_id": str(uuid.uuid4())},
        {"type": "user"},
        {"type": "user", "user_id": "not-a-uuid"},
        {"type": "user", "user_id": str(uuid.uuid4()), "kind": "worker_job"},
        {"type": "system", "kind": "robot", "name": "x"},
        {"type": "system", "kind": "worker_job"},
        {"type": "system", "kind": "worker_job", "name": "x", "user_id": str(uuid.uuid4())},
        {"type": "system", "kind": "public_link", "name": "x", "record_type": "link_token"},
        # Review of b6a7f07 (LOW): a JSON value of the wrong type anywhere in
        # the stored shape -- unhashable ones included -- is refused as
        # invalid, never with a `TypeError` that would fail the event.
        {"type": ["user"], "user_id": str(uuid.uuid4())},
        {"type": {"user": 1}},
        {"type": 1},
        {"type": None},
        {"type": "system", "kind": ["worker_job"], "name": "x"},
        {"type": "system", "kind": {"k": 1}, "name": "x"},
        {"type": "system", "kind": "worker_job", "name": ["x"]},
        {"type": "system", "kind": "worker_job", "name": "x", "record_type": "r", "record_id": [1]},
        {"type": "user", "user_id": 12},
        # Review of b6a7f07 (LOW): only the canonical spelling is accepted.
        {"type": "user", "user_id": str(uuid.uuid4()).upper()},
        {"type": "user", "user_id": "{" + str(uuid.uuid4()) + "}"},
        {"type": "user", "user_id": "urn:uuid:" + str(uuid.uuid4())},
        {"type": "user", "user_id": uuid.uuid4().hex},
        {"type": "service_account", "service_account_id": str(uuid.uuid4()).upper()},
    ],
)
def test_an_invalid_recorded_initiator_fails_closed(stored: object) -> None:
    with pytest.raises(InvalidSystemActorError):
        Initiator.from_metadata(stored)


# --- The correlation identity (owner decision C) -------------------------------------


def test_the_correlation_parts_are_distinct_and_optional() -> None:
    event_id = uuid.uuid4()
    assert SystemCorrelation().as_metadata() == {}
    assert SystemCorrelation(
        arq_job_id="cron:job_x:1700000000000", outbox_event_id=event_id, request_id="req-1"
    ).as_metadata() == {
        "arq_job_id": "cron:job_x:1700000000000",
        "outbox_event_id": str(event_id),
        "request_id": "req-1",
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"arq_job_id": ""},
        {"arq_job_id": "a b"},
        {"arq_job_id": "x" * 101},
        {"request_id": "sok_" + "c" * 30},  # pragma: allowlist secret
        {"request_id": 5},
        {"outbox_event_id": "not-a-uuid"},
    ],
)
def test_an_invalid_correlation_part_is_refused(kwargs: dict[str, object]) -> None:
    with pytest.raises(InvalidSystemActorError):
        SystemCorrelation(**kwargs)  # type: ignore[arg-type]


def test_correlation_from_a_job_context_keeps_valid_ids_only() -> None:
    event_id = uuid.uuid4()
    context = TenantJobContext(
        tenant_id=_TENANT, correlation_id="req-9", event_id=event_id, job_id="arq-1"
    )
    assert SystemCorrelation.from_job_context(context) == SystemCorrelation(
        arq_job_id="arq-1", outbox_event_id=event_id, request_id="req-9"
    )
    odd = TenantJobContext(tenant_id=_TENANT, correlation_id="has space")
    assert SystemCorrelation.from_job_context(odd) == SystemCorrelation()
    assert SystemCorrelation.from_job_context(SystemJobContext(job_id="j-2")) == (
        SystemCorrelation(arq_job_id="j-2")
    )


def test_an_actor_is_immutable() -> None:
    with pytest.raises(AttributeError):
        _ACTOR.name = "other"  # type: ignore[misc]


# --- Separation from authority -------------------------------------------------------


def test_require_caller_refuses_a_system_actor() -> None:
    with pytest.raises(CallerTypeError):
        require_caller("op", _ACTOR)
    with pytest.raises(CallerTypeError):
        require_caller("op", _ACTOR, (UserCaller, ServiceAccountCaller, SystemCaller))


def test_record_in_transaction_refuses_a_system_actor_as_its_caller() -> None:
    session = MagicMock()
    with pytest.raises(CallerTypeError):
        record_in_transaction(
            session,
            caller=_ACTOR,  # type: ignore[arg-type]
            tenant_id=_TENANT,
            action="x.y",
            resource_type="x",
        )
    session.add.assert_not_called()


def test_a_system_caller_refuses_a_non_actor_and_ignores_its_actor_for_equality() -> None:
    with pytest.raises(TypeError):
        SystemCaller(SystemAuthority.PROVISIONING, actor={"kind": "worker_job"})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SystemCaller(SystemAuthority.PROVISIONING, actor=UserCaller(uuid.uuid4()))  # type: ignore[arg-type]
    attributed = SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR)
    plain = SystemCaller(SystemAuthority.PROVISIONING)
    assert attributed == plain
    assert hash(attributed) == hash(plain)
    assert attributed.authority is SystemAuthority.PROVISIONING


def _outcome(call: object) -> object:
    try:
        result = call()  # type: ignore[operator]
    except Exception as exc:  # noqa: BLE001 -- the outcome under comparison
        return type(exc)
    return result


_PURPOSES = list(SystemAuthority)


@pytest.mark.parametrize("purpose", _PURPOSES, ids=[p.value for p in _PURPOSES])
def test_a_system_caller_with_an_actor_is_authorized_exactly_as_without(
    purpose: SystemAuthority,
) -> None:
    """Every decision point that reads a system purpose: the platform
    chokepoint (every declared operation), its preliminary question, the
    tenant authority check (every purpose set) and billing. The session is
    a mock: none of them reads it for a `SystemCaller`."""
    plain = SystemCaller(purpose)
    attributed = SystemCaller(purpose, actor=_ACTOR)
    session = MagicMock()
    decisions = 0
    for operation in PLATFORM_OPERATIONS:
        expected = _outcome(
            lambda c=plain, o=operation: authorize_platform_caller(c, session=session, operation=o)
        )
        actual = _outcome(
            lambda c=attributed, o=operation: authorize_platform_caller(
                c, session=session, operation=o
            )
        )
        assert actual == expected, operation
        assert platform_caller_could_hold_any(attributed, [operation]) is (
            platform_caller_could_hold_any(plain, [operation])
        )
        decisions += 1
    for accepted in [frozenset(), *(frozenset({p}) for p in _PURPOSES), frozenset(_PURPOSES)]:
        results = [
            _outcome(
                lambda c=caller, a=accepted: authorize_caller(
                    c,
                    session=session,
                    operation="op",
                    tenant_id=_TENANT,
                    resource="role",
                    action="create",
                    system_authorities=a,
                )
            )
            for caller in (plain, attributed)
        ]
        assert results[0] == results[1]
        assert results[0] in (None, AuthorityNotAuthorizedError)
        decisions += 1
    billing = [
        _outcome(
            lambda c=caller: type(
                authorize_billing(
                    c, [(_TENANT, "billing.plan", "read")], operation="op", session=session
                )
            )
        )
        for caller in (plain, attributed)
    ]
    assert billing[0] == billing[1]
    assert (billing[0] is BillingNotAuthorizedError) is (
        purpose is not SystemAuthority.BILLING_OPERATIONS
    )
    session.execute.assert_not_called()
    assert decisions == len(PLATFORM_OPERATIONS) + len(_PURPOSES) + 2


# --- The audit service ---------------------------------------------------------------


@pytest.fixture
def no_database(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """`record()`'s own transaction, replaced: what it would have written is
    collected instead, and nothing reaches a database."""
    written: list[object] = []

    @contextmanager
    def _scope(tenant_id: uuid.UUID) -> Iterator[MagicMock]:
        session = MagicMock()
        session.add.side_effect = written.append
        yield session

    monkeypatch.setattr(audit_service, "tenant_session_scope", _scope)
    return written


@pytest.mark.parametrize(
    "key",
    [
        "system_actor",
        "SYSTEM_ACTOR",
        " system_actor ",
        "initiated_by",
        "Initiated_By",
        "correlation",
        " CORRELATION",
    ],
)
def test_a_caller_supplied_attribution_key_is_refused_before_any_write(
    key: str, no_database: list[object]
) -> None:
    forged: dict[str, object] = {key: {"kind": "maintenance", "name": "forged"}}
    with pytest.raises(ReservedMetadataKeyError):
        record(
            tenant_id=_TENANT,
            actor_type=ActorType.SYSTEM,
            action="x.y",
            resource_type="x",
            outcome=AuditOutcome.SUCCESS,
            metadata=forged,
        )
    assert no_database == []
    for caller in (UserCaller(uuid.uuid4()), SystemCaller(SystemAuthority.PROVISIONING)):
        session = MagicMock()
        with pytest.raises(ReservedMetadataKeyError):
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=_TENANT,
                action="x.y",
                resource_type="x",
                metadata=forged,
            )
        session.add.assert_not_called()
    session = MagicMock()
    with pytest.raises(ReservedMetadataKeyError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            metadata=forged,
        )
    session.add.assert_not_called()


@pytest.mark.parametrize("key", ["system_authority", "SYSTEM_AUTHORITY", " system_authority "])
def test_a_system_action_row_cannot_claim_a_system_authority_purpose(key: str) -> None:
    """Review of b6a7f07 (LOW): `record_system_action_in_transaction()`
    authorizes nothing, so its row must not carry a caller-supplied
    `system_authority` that would read as a `SystemCaller` purpose."""
    session = MagicMock()
    with pytest.raises(ReservedMetadataKeyError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            metadata={key: "provisioning"},
        )
    session.add.assert_not_called()


def test_record_still_accepts_a_system_authority_key(no_database: list[object]) -> None:
    """Only the new system-action form refuses it: `record()` keeps
    accepting `system_authority`, as existing callers rely on."""
    record(
        tenant_id=_TENANT,
        actor_type=ActorType.SYSTEM,
        action="x.y",
        resource_type="x",
        outcome=AuditOutcome.SUCCESS,
        metadata={"system_authority": "billing_operations"},
    )
    assert no_database != []


@pytest.mark.parametrize(
    "actor",
    [
        None,
        "worker_job",
        {"kind": "worker_job", "name": "x"},
        SystemCaller(SystemAuthority.PROVISIONING),
    ],
)
def test_record_system_action_refuses_anything_but_a_system_actor(actor: object) -> None:
    session = MagicMock()
    with pytest.raises(InvalidActorError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=actor,  # type: ignore[arg-type]
            action="x.y",
            resource_type="x",
        )
    session.add.assert_not_called()


@pytest.mark.parametrize(
    ("initiated_by", "correlation"),
    [
        ({"type": "user", "user_id": str(uuid.uuid4())}, None),
        ("unavailable", None),
        (UserCaller(uuid.uuid4()), None),
        (_ACTOR, None),
        (None, {"arq_job_id": "j-1"}),
        (None, "j-1"),
    ],
    ids=["dict", "string", "caller", "actor", "correlation-dict", "correlation-str"],
)
def test_record_system_action_refuses_unvalidated_initiators_and_correlations(
    initiated_by: object, correlation: object
) -> None:
    session = MagicMock()
    with pytest.raises(InvalidActorError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            initiated_by=initiated_by,  # type: ignore[arg-type]
            correlation=correlation,  # type: ignore[arg-type]
        )
    session.add.assert_not_called()


def test_record_system_action_validates_like_record_before_the_insert() -> None:
    session = MagicMock()
    with pytest.raises(ValueError):
        record_system_action_in_transaction(
            session, tenant_id=_TENANT, actor=_ACTOR, action="", resource_type="x"
        )
    with pytest.raises(ValueError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            metadata={"token": "abc"},
        )
    with pytest.raises(ValueError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="x.y",
            resource_type="x",
            metadata={"blob": "x" * 9000},
        )
    session.add.assert_not_called()


def test_record_system_action_builds_a_system_row_in_the_given_session() -> None:
    """Without an initiator the row says so explicitly: `"unavailable"`,
    never the executing job, and no user id anywhere."""
    session = MagicMock()
    other_tenant = uuid.uuid4()
    entry = record_system_action_in_transaction(
        session,
        tenant_id=other_tenant,
        actor=SystemActor(SystemActorKind.SCHEDULED_JOB, "digest"),
        action="report.generated",
        resource_type="report",
        resource_id="r-1",
        correlation_id="corr-1",
        metadata={"rows": 3},
    )
    session.add.assert_called_once_with(entry)
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()
    # The tenant is the one the caller passed from verified context; the
    # actor carries none.
    assert entry.tenant_id == other_tenant
    assert entry.actor_type == "system"
    assert entry.actor_user_id is None and entry.actor_service_account_id is None
    assert entry.outcome == "success"
    assert entry.correlation_id == "corr-1"
    assert entry.entry_metadata == {
        "rows": 3,
        "system_actor": {"kind": "scheduled_job", "name": "digest"},
        "initiated_by": "unavailable",
        "correlation": {},
    }


def test_record_system_action_records_the_three_roles_distinctly() -> None:
    event_id = uuid.uuid4()
    initiator = Initiator.system(
        SystemActor(SystemActorKind.PROVIDER_EVENT_PROCESSOR, "billing.stripe"),
        record_type="provider_event",
        record_id="evt_1",
    )
    entry = record_system_action_in_transaction(
        MagicMock(),
        tenant_id=_TENANT,
        actor=SystemActor(SystemActorKind.WORKER_JOB, "_run_outbox_event"),
        action="subscription.synced",
        resource_type="subscription",
        initiated_by=initiator,
        correlation=SystemCorrelation(
            arq_job_id="arq-7", outbox_event_id=event_id, request_id="req-7"
        ),
    )
    assert entry.entry_metadata == {
        "system_actor": {"kind": "worker_job", "name": "_run_outbox_event"},
        "initiated_by": {
            "type": "system",
            "kind": "provider_event_processor",
            "name": "billing.stripe",
            "record_type": "provider_event",
            "record_id": "evt_1",
        },
        "correlation": {
            "arq_job_id": "arq-7",
            "outbox_event_id": str(event_id),
            "request_id": "req-7",
        },
    }
    # A system-initiated row never yields a user id.
    assert entry.actor_user_id is None
    assert "user_id" not in str(entry.entry_metadata)


def test_record_system_action_records_a_user_initiator_as_a_reference_and_a_service_account(
    subject_refs: list[tuple[uuid.UUID, uuid.UUID]],
) -> None:
    """Owner decision D2 (2026-11-02), as completed by audit identity phase
    P3: a user initiator is recorded as the user's tenant audit reference,
    never as the raw user id, and never as the row's actor. A service
    account is recorded only as the initiator, never as the row's actor."""
    user_id = _D2_USER
    session = MagicMock()
    referenced = record_system_action_in_transaction(
        session,
        tenant_id=_TENANT,
        actor=_ACTOR,
        action="export.finished",
        resource_type="export",
        initiated_by=Initiator.from_caller(UserCaller(user_id)),
    )
    assert referenced.actor_user_id is None
    _assert_reference_recorded(referenced)
    assert subject_refs == [(_TENANT, user_id)]

    account_id = uuid.uuid4()
    entry = record_system_action_in_transaction(
        MagicMock(),
        tenant_id=_TENANT,
        actor=_ACTOR,
        action="export.finished",
        resource_type="export",
        initiated_by=Initiator.from_caller(ServiceAccountCaller(account_id, _TENANT)),
    )
    # Never fabricated as the row's actor: the row is still a system row.
    assert entry.actor_type == "system"
    assert entry.actor_user_id is None and entry.actor_service_account_id is None
    assert entry.entry_metadata is not None
    assert entry.entry_metadata["initiated_by"] == {
        "type": "service_account",
        "service_account_id": str(account_id),
    }
    assert entry.entry_metadata["system_actor"] == _ACTOR.as_metadata()


def test_record_in_transaction_writes_a_system_callers_attribution_beside_its_purpose() -> None:
    session = MagicMock()
    entry = record_in_transaction(
        session,
        caller=SystemCaller(SystemAuthority.TENANT_PURGE, actor=_ACTOR),
        tenant_id=_TENANT,
        action="tenant.purge",
        resource_type="tenant",
        metadata={"step": "started"},
        correlation=SystemCorrelation(arq_job_id="arq-1"),
    )
    assert entry.entry_metadata == {
        "step": "started",
        "system_authority": "tenant_purge",
        "system_actor": {"kind": "worker_job", "name": "nightly_export"},
        "initiated_by": "unavailable",
        "correlation": {"arq_job_id": "arq-1"},
    }
    plain = record_in_transaction(
        MagicMock(),
        caller=SystemCaller(SystemAuthority.TENANT_PURGE),
        tenant_id=_TENANT,
        action="tenant.purge",
        resource_type="tenant",
    )
    assert plain.entry_metadata == {"system_authority": "tenant_purge"}
    # Phase P3: a user initiator is recorded as its tenant reference ...
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(audit_service, "audit_subject_ref", lambda session, **_: _D2_REF)
        referenced = record_in_transaction(
            MagicMock(),
            caller=SystemCaller(SystemAuthority.TENANT_PURGE),
            tenant_id=_TENANT,
            action="tenant.purge",
            resource_type="tenant",
            initiated_by=Initiator.user(_D2_USER),
        )
    _assert_reference_recorded(referenced)
    # ... while a service-account initiator is still recorded beside the
    # purpose.
    account = uuid.uuid4()
    initiated = record_in_transaction(
        MagicMock(),
        caller=SystemCaller(SystemAuthority.TENANT_PURGE),
        tenant_id=_TENANT,
        action="tenant.purge",
        resource_type="tenant",
        initiated_by=Initiator.service_account(account),
    )
    assert initiated.entry_metadata == {
        "system_authority": "tenant_purge",
        "initiated_by": {"type": "service_account", "service_account_id": str(account)},
        "correlation": {},
    }


@pytest.mark.parametrize(
    "caller",
    [UserCaller(uuid.uuid4()), ServiceAccountCaller(uuid.uuid4(), uuid.uuid4())],
    ids=["user", "service-account"],
)
def test_a_principal_caller_is_its_own_initiator(caller: object) -> None:
    # Non-user initiators: a user initiator is refused by D2 before this
    # rule is reached (covered below), so it would not exercise this rule.
    for kwargs in (
        {"initiated_by": Initiator.service_account(uuid.uuid4())},
        {"initiated_by": Initiator.system(_ACTOR)},
        {"correlation": SystemCorrelation(arq_job_id="arq-1")},
    ):
        session = MagicMock()
        with pytest.raises(InvalidActorError):
            record_in_transaction(
                session,
                caller=caller,  # type: ignore[arg-type]
                tenant_id=_TENANT,
                action="x.y",
                resource_type="x",
                **kwargs,  # type: ignore[arg-type]
            )
        session.add.assert_not_called()


# --- Owner decision D2 (2026-11-02): no user initiator in a new audit record ---------

_D2_USER = uuid.uuid4()
_D2_USER_INITIATORS = {
    "user": lambda: Initiator.user(_D2_USER),
    "from-user-caller": lambda: Initiator.from_caller(UserCaller(_D2_USER)),
    "from-outbox-job-context": lambda: Initiator.from_job_initiator(
        JobInitiator("user", user_id=str(_D2_USER))
    ),
}
_D2_CALLERS = {
    "system": lambda: SystemCaller(SystemAuthority.TENANT_PURGE),
    "attributed-system": lambda: SystemCaller(SystemAuthority.TENANT_PURGE, actor=_ACTOR),
    "user": lambda: UserCaller(uuid.uuid4()),
    "service-account": lambda: ServiceAccountCaller(uuid.uuid4(), _TENANT),
}


def _assert_d2_refusal(error: InvalidActorError) -> None:
    message = str(error)
    assert "D2" in message
    assert str(_D2_USER) not in message and _D2_USER.hex not in message


# Audit identity phase P3 (docs/architecture/AUDIT-IDENTITY-P3-PLAN.md): a
# user initiator is no longer refused. Both tenant writers record it as the
# user's tenant audit reference, never as the user id, and get or create the
# reference only after every other check of the row has passed.
_D2_REF = uuid.uuid4()
_SYSTEM_CALLERS = {key: _D2_CALLERS[key] for key in ("system", "attributed-system")}
_PRINCIPAL_CALLERS = {key: _D2_CALLERS[key] for key in ("user", "service-account")}


@pytest.fixture
def subject_refs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Replaces the tenant get-or-create; records `(tenant_id, user_id)`."""
    calls: list[tuple[uuid.UUID, uuid.UUID]] = []

    def fake(session: object, *, tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
        calls.append((tenant_id, user_id))
        return _D2_REF

    monkeypatch.setattr(audit_service, "audit_subject_ref", fake)
    return calls


def _assert_reference_recorded(entry: AuditLogEntry) -> None:
    assert entry.entry_metadata is not None
    assert entry.entry_metadata["initiated_by"] == {"type": "user", "subject_ref": str(_D2_REF)}
    stored = json.dumps(entry.entry_metadata)
    assert str(_D2_USER) not in stored and _D2_USER.hex not in stored


@pytest.mark.parametrize("initiator", _D2_USER_INITIATORS.values(), ids=_D2_USER_INITIATORS)
def test_record_system_action_records_a_user_initiator_as_its_reference(
    initiator: Callable[[], Initiator | None], subject_refs: list[tuple[uuid.UUID, uuid.UUID]]
) -> None:
    session = MagicMock()
    entry = record_system_action_in_transaction(
        session,
        tenant_id=_TENANT,
        actor=_ACTOR,
        action="export.finished",
        resource_type="export",
        initiated_by=initiator(),
        correlation=SystemCorrelation(arq_job_id="arq-1"),
    )
    assert subject_refs == [(_TENANT, _D2_USER)]
    session.add.assert_called_once_with(entry)
    _assert_reference_recorded(entry)


@pytest.mark.parametrize("caller", _SYSTEM_CALLERS.values(), ids=_SYSTEM_CALLERS)
@pytest.mark.parametrize("initiator", _D2_USER_INITIATORS.values(), ids=_D2_USER_INITIATORS)
def test_record_in_transaction_records_a_user_initiator_as_its_reference(
    caller: Callable[[], Caller],
    initiator: Callable[[], Initiator | None],
    subject_refs: list[tuple[uuid.UUID, uuid.UUID]],
) -> None:
    session = MagicMock()
    entry = record_in_transaction(
        session,
        caller=caller(),
        tenant_id=_TENANT,
        action="tenant.purge",
        resource_type="tenant",
        initiated_by=initiator(),
    )
    assert subject_refs == [(_TENANT, _D2_USER)]
    _assert_reference_recorded(entry)


@pytest.mark.parametrize("caller", _PRINCIPAL_CALLERS.values(), ids=_PRINCIPAL_CALLERS)
@pytest.mark.parametrize("initiator", _D2_USER_INITIATORS.values(), ids=_D2_USER_INITIATORS)
def test_a_principal_caller_still_refuses_a_user_initiator_and_writes_nothing(
    caller: Callable[[], Caller],
    initiator: Callable[[], Initiator | None],
    subject_refs: list[tuple[uuid.UUID, uuid.UUID]],
) -> None:
    session = MagicMock()
    with pytest.raises(InvalidActorError) as refused:
        record_in_transaction(
            session,
            caller=caller(),
            tenant_id=_TENANT,
            action="tenant.purge",
            resource_type="tenant",
            initiated_by=initiator(),
        )
    assert str(_D2_USER) not in str(refused.value)
    assert subject_refs == []
    assert session.mock_calls == []


def test_a_user_initiator_gets_no_reference_when_the_row_is_refused(
    subject_refs: list[tuple[uuid.UUID, uuid.UUID]],
) -> None:
    """Every check runs before any write: a row refused for another reason
    (a forbidden metadata key) creates no reference."""
    session = MagicMock()
    with pytest.raises(ForbiddenMetadataKeyError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="export.finished",
            resource_type="export",
            metadata={"password": "x"},
            initiated_by=Initiator.user(_D2_USER),
        )
    assert subject_refs == []
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "metadata",
    [
        {"detail": {"initiated_by": {"type": "user", "subject_ref": str(_D2_USER)}}},
        {"detail": [{"initiatedBy": {"type": "user", "subject_ref": str(_D2_REF)}}]},
        {"detail": {"initiated_by": {"type": "user", "user_id": str(_D2_USER)}}},
    ],
    ids=["nested-user-id-as-reference", "nested-reference-spelling", "nested-raw-user-id"],
)
@pytest.mark.parametrize("typed", [None, "user"], ids=["no-initiator", "user-initiator"])
def test_a_caller_supplied_user_shape_is_still_refused(
    metadata: dict[str, object],
    typed: str | None,
    subject_refs: list[tuple[uuid.UUID, uuid.UUID]],
) -> None:
    """The reference shape is accepted only at the top level, with the
    reference the writer just got: a caller who nests one -- above all one
    holding a user id under `subject_ref` -- is refused, whether or not the
    row also has a user initiator."""
    session = MagicMock()
    with pytest.raises(InvalidActorError):
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="export.finished",
            resource_type="export",
            metadata=metadata,
            initiated_by=None if typed is None else Initiator.user(_D2_USER),
        )
    assert subject_refs == []
    assert session.mock_calls == []


def test_negative_control_the_top_level_shape_must_carry_the_writers_reference() -> None:
    """`trusted_metadata()` itself: with the writer's reference, a top-level
    user shape carrying any other value -- a user id above all -- is
    refused, as is a shape with an extra field."""
    for value in (
        {"type": "user", "subject_ref": str(_D2_USER)},
        {"type": "user", "subject_ref": str(_D2_REF), "user_id": str(_D2_USER)},
        {"type": "user", "user_id": str(_D2_USER)},
        "unavailable",
    ):
        with pytest.raises(InvalidActorError):
            trusted_metadata({"initiated_by": value}, user_subject_ref=_D2_REF)
    accepted = trusted_metadata(
        {"a": 1, "initiated_by": {"type": "user", "subject_ref": str(_D2_REF)}, "b": 2},
        user_subject_ref=_D2_REF,
    )
    assert list(accepted or {}) == ["a", "initiated_by", "b"]


_D2_ACCEPTED: dict[str, tuple[Callable[[], Initiator | None], object]] = {
    "none": (lambda: None, "unavailable"),
    "service-account": (
        lambda: Initiator.service_account(_D2_USER),
        {"type": "service_account", "service_account_id": str(_D2_USER)},
    ),
    "system": (
        lambda: Initiator.system(_LINK, record_type="unsubscribe_link", record_id="l-1"),
        {
            "type": "system",
            **_LINK.as_metadata(),
            "record_type": "unsubscribe_link",
            "record_id": "l-1",
        },
    ),
}


@pytest.mark.parametrize(("initiator", "recorded"), _D2_ACCEPTED.values(), ids=_D2_ACCEPTED)
def test_non_user_initiators_and_none_are_still_recorded(
    initiator: Callable[[], Initiator | None], recorded: object
) -> None:
    """A service account (even one whose id equals a user's), a system
    initiator and `None` (`"unavailable"`) are written by both writers in
    their own shapes, as before (a user initiator: its reference, above)."""
    session = MagicMock()
    entry = record_system_action_in_transaction(
        session,
        tenant_id=_TENANT,
        actor=_ACTOR,
        action="export.finished",
        resource_type="export",
        initiated_by=initiator(),
    )
    session.add.assert_called_once_with(entry)
    assert entry.entry_metadata is not None
    assert entry.entry_metadata["initiated_by"] == recorded
    via_caller = record_in_transaction(
        MagicMock(),
        caller=SystemCaller(SystemAuthority.TENANT_PURGE, actor=_ACTOR),
        tenant_id=_TENANT,
        action="tenant.purge",
        resource_type="tenant",
        initiated_by=initiator(),
    )
    assert via_caller.entry_metadata is not None
    assert via_caller.entry_metadata["initiated_by"] == recorded


def test_an_initiator_type_outside_the_allowlist_is_refused() -> None:
    """The D2 gate is an allowlist: an initiator whose type is none of
    user, service account and system actor -- here a stand-in for a future
    `InitiatorType`, forced past construction -- is refused by both
    writers before anything is written."""
    future = Initiator.service_account(_D2_USER)
    object.__setattr__(future, "type", "future_type")
    session = MagicMock()
    with pytest.raises(InvalidActorError) as refused:
        record_system_action_in_transaction(
            session,
            tenant_id=_TENANT,
            actor=_ACTOR,
            action="export.finished",
            resource_type="export",
            initiated_by=future,
        )
    _assert_d2_refusal(refused.value)
    with pytest.raises(InvalidActorError) as refused_by_caller:
        record_in_transaction(
            session,
            caller=SystemCaller(SystemAuthority.TENANT_PURGE, actor=_ACTOR),
            tenant_id=_TENANT,
            action="tenant.purge",
            resource_type="tenant",
            initiated_by=future,
        )
    _assert_d2_refusal(refused_by_caller.value)
    assert session.mock_calls == []


def test_a_user_initiator_is_still_built_and_parsed_for_the_outbox() -> None:
    """D2 gates the audit writers only: the outbox still stores and hands
    over a user initiator, so `Initiator` keeps producing and parsing the
    user shape (`append_event`, `_split_initiator`, `_job_initiator` and
    erasure are unchanged)."""
    user_id = uuid.uuid4()
    shape = {"type": "user", "user_id": str(user_id)}
    assert Initiator.user(user_id).as_metadata() == shape
    assert Initiator.from_metadata(shape) == Initiator.user(user_id)
    assert Initiator.from_caller(UserCaller(user_id)) == Initiator.user(user_id)


def _record_system(outcome: AuditOutcome, metadata: dict[str, object] | None = None) -> None:
    record(
        tenant_id=_TENANT,
        actor_type=ActorType.SYSTEM,
        action="x.y",
        resource_type="x",
        outcome=outcome,
        metadata=metadata,
    )


def test_an_unattributed_successful_system_row_is_written_with_a_warning(
    no_database: list[object], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="saas_os.core.audit_log.service"):
        with pytest.warns(DeprecationWarning, match="ADR 0061") as caught:
            _record_system(AuditOutcome.SUCCESS, {"plan_key": "pro"})
    assert len(no_database) == 1  # written: nothing is refused yet
    # The warning points at the calling module, not the audit service.
    (warning,) = [w for w in caught if "ADR 0061" in str(w.message)]
    assert warning.filename == __file__
    (line,) = [r for r in caplog.records if r.getMessage() == "audit_system_row_unattributed"]
    assert line.calling_module == __name__  # type: ignore[attr-defined]
    assert line.levelno == logging.WARNING
    # The calling module only: no tenant, action or metadata.
    assert str(_TENANT) not in str(line.__dict__.values())
    assert "pro" not in {str(v) for v in line.__dict__.values()}


@pytest.mark.parametrize(
    ("outcome", "metadata"),
    [
        (AuditOutcome.DENIED, None),
        (AuditOutcome.FAILURE, None),
        (AuditOutcome.SUCCESS, {"system_authority": "billing_operations"}),
    ],
    ids=["denied", "failure", "with-purpose"],
)
def test_no_warning_for_denials_failures_or_rows_with_a_purpose(
    outcome: AuditOutcome,
    metadata: dict[str, object] | None,
    no_database: list[object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        _record_system(outcome, metadata)
    assert len(no_database) == 1
    assert "audit_system_row_unattributed" not in caplog.text


def test_no_warning_for_a_user_row(no_database: list[object]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        record(
            tenant_id=_TENANT,
            actor_type=ActorType.USER,
            actor_user_id=uuid.uuid4(),
            action="x.y",
            resource_type="x",
            outcome=AuditOutcome.SUCCESS,
        )
    assert len(no_database) == 1


# --- Job contexts: executor, initiator and correlation kept apart ------------------------

_CONFIG = JobsConfig(redis_url="redis://localhost:6379/0", max_tries=3)


def test_a_direct_tenant_job_has_an_executor_a_job_id_and_no_initiator() -> None:
    seen: list[TenantJobContext] = []

    async def _export_tenant_rows(context: TenantJobContext, payload: TenantJobPayload) -> None:
        seen.append(context)

    wrapped = _with_retry_and_dead_letter(_export_tenant_rows, config=_CONFIG, kind=JobKind.TENANT)
    payload = TenantJobPayload(tenant_id=str(_TENANT), correlation_id="req-3")
    asyncio.run(wrapped({"job_try": 1, "job_id": "arq-job-42"}, payload))
    (context,) = seen
    # Executor: the job itself. Correlation: the arq job id, apart from it.
    assert context.system_actor == JobActor(kind="worker_job", name="_export_tenant_rows")
    assert context.job_id == "arq-job-42"
    # A direct job has no recorded initiator: unavailable, never the job.
    assert context.initiated_by is None
    # The tenant comes from the validated payload; the actor has none.
    assert context.tenant_id == _TENANT
    assert SystemActor.from_job_actor(context.system_actor) == SystemActor(
        SystemActorKind.WORKER_JOB, "_export_tenant_rows"
    )
    entry = record_system_action_in_transaction(
        MagicMock(),
        tenant_id=context.tenant_id,
        actor=SystemActor.from_job_actor(context.system_actor),
        action="export.done",
        resource_type="export",
        initiated_by=Initiator.from_job_initiator(context.initiated_by),
        correlation=SystemCorrelation.from_job_context(context),
    )
    assert entry.entry_metadata == {
        "system_actor": {"kind": "worker_job", "name": "_export_tenant_rows"},
        "initiated_by": "unavailable",
        "correlation": {"arq_job_id": "arq-job-42", "request_id": "req-3"},
    }


def test_system_job_contexts_carry_worker_or_scheduled_actors() -> None:
    seen: list[SystemJobContext] = []

    async def _prune_things(context: SystemJobContext) -> None:
        seen.append(context)

    queued = _with_retry_and_dead_letter(_prune_things, config=_CONFIG, kind=JobKind.SYSTEM)
    scheduled = _with_retry_and_dead_letter(
        _prune_things, config=_CONFIG, kind=JobKind.SYSTEM, scheduled=True
    )
    asyncio.run(queued({"job_try": 1, "job_id": "abc123"}, None))
    asyncio.run(scheduled({"job_try": 1, "job_id": "cron:_prune_things:1700000000000"}, None))
    asyncio.run(queued({"job_try": 1}, None))  # arq supplied no job id
    assert [c.system_actor for c in seen] == [
        JobActor("worker_job", "_prune_things"),
        JobActor("scheduled_job", "_prune_things"),
        JobActor("worker_job", "_prune_things"),
    ]
    assert [c.job_id for c in seen] == ["abc123", "cron:_prune_things:1700000000000", None]
    assert [SystemActor.from_job_actor(c.system_actor).kind for c in seen] == [
        SystemActorKind.WORKER_JOB,
        SystemActorKind.SCHEDULED_JOB,
        SystemActorKind.WORKER_JOB,
    ]


@pytest.mark.parametrize(
    "job_actor",
    [
        None,
        JobActor("maintenance", "x"),
        JobActor("worker_job", "Bad Name"),
        {"kind": "worker_job", "name": "x"},
    ],
)
def test_converting_a_job_actor_fails_closed(job_actor: object) -> None:
    with pytest.raises(InvalidSystemActorError):
        SystemActor.from_job_actor(job_actor)


def test_a_job_initiator_converts_to_the_recorded_initiator() -> None:
    user_id = uuid.uuid4()
    assert Initiator.from_job_initiator(None) is None
    assert Initiator.from_job_initiator(JobInitiator("user", user_id=str(user_id))) == (
        Initiator.user(user_id)
    )
    assert Initiator.from_job_initiator(
        JobInitiator("system", kind="scheduled_job", name="trial_expiry")
    ) == Initiator.system(SystemActor(SystemActorKind.SCHEDULED_JOB, "trial_expiry"))


@pytest.mark.parametrize(
    "job_initiator",
    [
        JobInitiator("user"),
        JobInitiator("user", user_id="not-a-uuid"),
        JobInitiator("system", kind="worker_job", name="x", user_id=str(uuid.uuid4())),
        JobInitiator("system", kind="robot", name="x"),
        JobInitiator("root"),
    ],
)
def test_converting_an_invalid_job_initiator_fails_closed(job_initiator: JobInitiator) -> None:
    with pytest.raises(InvalidSystemActorError):
        Initiator.from_job_initiator(job_initiator)


def test_infrastructure_attribution_spellings_match_core() -> None:
    """Infra spells the job kinds and the initiator fields as plain strings
    (it does not import Core); they must stay Core's."""
    assert {"worker_job", "scheduled_job"} <= {kind.value for kind in SystemActorKind}
    fields = set(JobInitiator.__dataclass_fields__)
    for initiator in (
        Initiator.user(uuid.uuid4()),
        Initiator.service_account(uuid.uuid4()),
        Initiator.system(_LINK, record_type="unsubscribe_link", record_id="l-1"),
    ):
        assert set(initiator.as_metadata()) <= fields
