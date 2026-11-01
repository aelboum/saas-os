"""ADR 0061 step 1 -- `SystemActor` attribution, without a database.

- `SystemActor` validates every field at construction (closed kinds, short
  identifiers, no credential as an initiator).
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
import logging
import uuid
import warnings
from collections.abc import Iterator
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
from saas_os.core.authority import (
    CallerTypeError,
    InvalidSystemActorError,
    ServiceAccountCaller,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
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
from saas_os.infra.jobs import JobActor, JobKind, SystemJobContext, TenantJobContext
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


@pytest.mark.parametrize("initiator_type", ["", "Outbox", "a b", "y" * 101])
def test_a_bad_initiator_type_is_refused(initiator_type: str) -> None:
    with pytest.raises(InvalidSystemActorError):
        SystemActor(SystemActorKind.WORKER_JOB, "x", initiator_type, "id-1")


@pytest.mark.parametrize(
    ("initiator_type", "initiator_id"),
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
def test_a_token_like_initiator_is_refused(initiator_type: str, initiator_id: object) -> None:
    with pytest.raises(InvalidSystemActorError):
        SystemActor(SystemActorKind.PUBLIC_LINK, "unsubscribe", initiator_type, initiator_id)  # type: ignore[arg-type]


def test_the_initiator_is_given_whole_or_not_at_all() -> None:
    with pytest.raises(InvalidSystemActorError):
        SystemActor(SystemActorKind.WORKER_JOB, "x", initiator_type="outbox_event")
    with pytest.raises(InvalidSystemActorError):
        SystemActor(SystemActorKind.WORKER_JOB, "x", initiator_id=uuid.uuid4())


def test_a_valid_actor_and_its_fixed_metadata_shape() -> None:
    event_id = uuid.uuid4()
    actor = SystemActor(
        SystemActorKind.WEBHOOK_PROCESSOR, "product.delivery:v2", "outbox_event", event_id
    )
    assert actor.as_metadata() == {
        "kind": "webhook_processor",
        "name": "product.delivery:v2",
        "initiator_type": "outbox_event",
        "initiator_id": str(event_id),
    }
    assert _ACTOR.as_metadata() == {"kind": "worker_job", "name": "nightly_export"}
    opaque = SystemActor(SystemActorKind.WORKER_JOB, "x", "arq_job", "cron:job_x:1700000000000")
    assert opaque.as_metadata()["initiator_id"] == "cron:job_x:1700000000000"


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


@pytest.mark.parametrize("key", ["system_actor", "SYSTEM_ACTOR", " system_actor "])
def test_a_caller_supplied_system_actor_key_is_refused_before_any_write(
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
    session = MagicMock()
    other_tenant = uuid.uuid4()
    entry = record_system_action_in_transaction(
        session,
        tenant_id=other_tenant,
        actor=SystemActor(SystemActorKind.SCHEDULED_JOB, "digest", "arq_job", "j-1"),
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
        "system_actor": {
            "kind": "scheduled_job",
            "name": "digest",
            "initiator_type": "arq_job",
            "initiator_id": "j-1",
        },
    }


def test_record_in_transaction_writes_a_system_callers_actor_beside_its_purpose() -> None:
    session = MagicMock()
    entry = record_in_transaction(
        session,
        caller=SystemCaller(SystemAuthority.TENANT_PURGE, actor=_ACTOR),
        tenant_id=_TENANT,
        action="tenant.purge",
        resource_type="tenant",
        metadata={"step": "started"},
    )
    assert entry.entry_metadata == {
        "step": "started",
        "system_authority": "tenant_purge",
        "system_actor": {"kind": "worker_job", "name": "nightly_export"},
    }
    plain = record_in_transaction(
        MagicMock(),
        caller=SystemCaller(SystemAuthority.TENANT_PURGE),
        tenant_id=_TENANT,
        action="tenant.purge",
        resource_type="tenant",
    )
    assert plain.entry_metadata == {"system_authority": "tenant_purge"}


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


# --- Job contexts carry the derived actor -------------------------------------------

_CONFIG = JobsConfig(redis_url="redis://localhost:6379/0", max_tries=3)


def test_a_tenant_job_context_carries_a_worker_job_actor() -> None:
    seen: list[TenantJobContext] = []

    async def _export_tenant_rows(context: TenantJobContext, payload: TenantJobPayload) -> None:
        seen.append(context)

    wrapped = _with_retry_and_dead_letter(_export_tenant_rows, config=_CONFIG, kind=JobKind.TENANT)
    payload = TenantJobPayload(tenant_id=str(_TENANT))
    asyncio.run(wrapped({"job_try": 1, "job_id": "arq-job-42"}, payload))
    (context,) = seen
    assert context.system_actor == JobActor(
        kind="worker_job",
        name="_export_tenant_rows",
        initiator_type="arq_job",
        initiator_id="arq-job-42",
    )
    # The tenant comes from the validated payload; the actor has none.
    assert context.tenant_id == _TENANT
    assert SystemActor.from_job_actor(context.system_actor) == SystemActor(
        SystemActorKind.WORKER_JOB, "_export_tenant_rows", "arq_job", "arq-job-42"
    )


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
        JobActor("worker_job", "_prune_things", "arq_job", "abc123"),
        JobActor("scheduled_job", "_prune_things", "arq_job", "cron:_prune_things:1700000000000"),
        JobActor("worker_job", "_prune_things"),
    ]
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
        JobActor("worker_job", "x", "arq_job", "sok_" + "b" * 30),  # pragma: allowlist secret
        {"kind": "worker_job", "name": "x"},
    ],
)
def test_converting_a_job_actor_fails_closed(job_actor: object) -> None:
    with pytest.raises(InvalidSystemActorError):
        SystemActor.from_job_actor(job_actor)


def test_infrastructure_job_actor_kinds_match_core() -> None:
    """Infra spells the two job kinds as plain strings (it does not import
    Core); they must stay Core's values."""
    assert {"worker_job", "scheduled_job"} <= {kind.value for kind in SystemActorKind}
