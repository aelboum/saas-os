"""Owner decision D2 (2026-11-02) against a real PostgreSQL: no raw user
initiator reaches a new audit row, in `core.audit_log` or
`core.platform_audit_log`, by any path.

One user id is used as the initiator throughout and is never a row
anywhere, so any appearance of it in either audit table can only be a
leak. Every refusal scenario -- the typed argument and the metadata key,
top level and nested, tenant and platform writers, the refusal writers,
the refusal context manager, the oversight attempt and read, and a
caller-supplied platform change -- fails closed: it raises (or, for the
refusal writers, records the denial with the fixed marker in place of the
refused metadata), commits nothing else, and leaves both tables without the
id. Allowlisted initiators are still committed
exactly as given.

The outbox consumer path is in `tests/api/test_outbox_attribution_integration.py`.

Marked `integration`. Disposable databases only (the `platform` fixture
empties the platform tables before and after).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from platform_helpers import PlatformWorld

import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.core.audit_log import (
    ActorType,
    AuditOutcome,
    InvalidActorError,
    ReservedMetadataKeyError,
    record,
    record_in_transaction,
    record_system_action_in_transaction,
)
from saas_os.core.authority import (
    Initiator,
    InvalidSystemActorError,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    SystemCorrelation,
    UserCaller,
)
from saas_os.core.platform_authority import (
    PlatformChange,
    PlatformNotAuthorizedError,
    record_oversight_attempt,
    record_platform_event_in_transaction,
    record_platform_refusal,
    recording_platform_refusal,
    run_oversight_read,
    run_platform_change,
    run_tenant_oversight_read,
)
from saas_os.core.platform_authority.operations import (
    AI_USAGE_READ,
    FEATURE_FLAG_DEFINE,
    OPERATOR_READ,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import session_scope, tenant_session_scope
from saas_os.infra.jobs import JobInitiator

pytestmark = pytest.mark.integration

_ACTOR = SystemActor(SystemActorKind.MAINTENANCE, "d2_gate_test")


@pytest.fixture
def tenant(platform: PlatformWorld) -> Iterator[uuid.UUID]:
    """One fresh tenant. Every row written for it is removed afterwards with
    the migrations role, so later migration downgrades in a shared
    database are not blocked."""
    tenant_id = create_tenant(f"d2-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
    try:
        yield tenant_id
    finally:
        params = {"t": tenant_id}
        platform.execute(
            "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t", params
        )
        platform.execute("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
        platform.execute("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", params)
        platform.execute("DELETE FROM core.tenants WHERE id = :t", params)


def _leaks(platform: PlatformWorld, user_id: uuid.UUID) -> dict[str, int]:
    """Rows of either audit table that mention `user_id` anywhere a raw id
    could be stored: metadata (any spelling), the actor, the target or
    resource id."""
    params = {"u": str(user_id), "p": f"%{user_id}%", "h": f"%{user_id.hex}%"}
    tenant_rows = platform.scalar(
        "SELECT count(*) FROM core.audit_log WHERE metadata::text ILIKE :p "
        "OR metadata::text ILIKE :h OR actor_user_id::text = :u "
        "OR coalesce(resource_id, '') ILIKE :p",
        params,
    )
    platform_rows = platform.scalar(
        "SELECT count(*) FROM core.platform_audit_log WHERE metadata::text ILIKE :p "
        "OR metadata::text ILIKE :h OR actor_user_id::text = :u "
        "OR coalesce(target_id, '') ILIKE :p",
        params,
    )
    return {"core.audit_log": tenant_rows, "core.platform_audit_log": platform_rows}


def _counts(platform: PlatformWorld, tenant_id: uuid.UUID) -> tuple[int, int]:
    return (
        platform.scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t", {"t": tenant_id}
        ),
        platform.audit_count(),
    )


def _scenarios(
    tenant_id: uuid.UUID, operator: UserCaller, user_id: uuid.UUID
) -> dict[str, tuple[Callable[[], Any], type[BaseException] | None]]:
    """Each refusal scenario: what it runs, and the error it must raise
    (`None`: it must return `True` -- the best-effort refusal writer, which
    records the denial with the fixed marker in place of the metadata)."""
    shape = {"type": "user", "user_id": str(user_id)}
    system = SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR)

    def tenant_typed_system_caller() -> None:
        with tenant_session_scope(tenant_id) as session:
            # A change written earlier in the same transaction rolls back too.
            record_system_action_in_transaction(
                session,
                tenant_id=tenant_id,
                actor=_ACTOR,
                action="test.d2.change",
                resource_type="d2",
            )
            record_in_transaction(
                session,
                caller=system,
                tenant_id=tenant_id,
                action="test.d2.typed",
                resource_type="d2",
                initiated_by=Initiator.user(user_id),
            )

    def tenant_typed_from_outbox_context() -> None:
        initiator = Initiator.from_job_initiator(JobInitiator("user", user_id=str(user_id)))
        with tenant_session_scope(tenant_id) as session:
            record_system_action_in_transaction(
                session,
                tenant_id=tenant_id,
                actor=_ACTOR,
                action="test.d2.typed",
                resource_type="d2",
                initiated_by=initiator,
            )

    def tenant_record(metadata: dict[str, object]) -> Callable[[], Any]:
        return lambda: record(
            tenant_id=tenant_id,
            actor_type=ActorType.SYSTEM,
            action="test.d2.record",
            resource_type="d2",
            outcome=AuditOutcome.DENIED,
            metadata=metadata,
        )

    def tenant_user_caller_nested() -> None:
        with tenant_session_scope(tenant_id) as session:
            record_in_transaction(
                session,
                caller=operator,
                tenant_id=tenant_id,
                action="test.d2.nested",
                resource_type="d2",
                metadata={"items": [{"Initiated_By": shape}]},
            )

    def tenant_system_action_nested_string() -> None:
        with tenant_session_scope(tenant_id) as session:
            record_system_action_in_transaction(
                session,
                tenant_id=tenant_id,
                actor=_ACTOR,
                action="test.d2.nested",
                resource_type="d2",
                metadata={"context": {"initiated_by": str(user_id)}},
            )

    def platform_event(metadata: dict[str, object]) -> Callable[[], Any]:
        def run() -> None:
            with session_scope() as session:
                record_platform_event_in_transaction(
                    session,
                    caller=operator,
                    action="platform.test.initiator_gate",
                    target_type="d2",
                    metadata=metadata,
                )

        return run

    system_shape_naming_a_user = {
        "type": "system",
        **_ACTOR.as_metadata(),
        "record_type": "user",
        "record_id": str(user_id),
    }
    system_shape_embedding_the_id = {
        "type": "system",
        "kind": "maintenance",
        "name": f"user.{user_id}",
    }

    def tenant_system_initiator_naming_a_user() -> None:
        with tenant_session_scope(tenant_id) as session:
            record_system_action_in_transaction(
                session,
                tenant_id=tenant_id,
                actor=_ACTOR,
                action="test.d2.typed",
                resource_type="d2",
                initiated_by=Initiator.system(_ACTOR, record_type="user", record_id=user_id),
            )

    def platform_refusal() -> bool:
        return record_platform_refusal(
            caller=operator,
            action="platform.operator.read",
            target_type="platform_operator",
            code="not_authorized",
            metadata={"initiated_by": shape},
        )

    def refusal_context_manager() -> None:
        with recording_platform_refusal(
            caller=operator,
            operation=OPERATOR_READ,
            target_type="platform_operator",
            metadata={"request": {"initiated_by": shape}},
        ):
            raise PlatformNotAuthorizedError(OPERATOR_READ)

    def oversight_attempt() -> None:
        record_oversight_attempt(
            caller=operator,
            operation=OPERATOR_READ,
            target_type="platform_operator",
            metadata={"initiated_by": shape},
        )

    def nothing_may_be_read(session: object) -> Any:
        raise AssertionError("an oversight read ran after a refused attempt")

    def oversight_read() -> None:
        run_oversight_read(
            caller=operator,
            operation=OPERATOR_READ,
            target_type="platform_operator",
            read=nothing_may_be_read,
            request_metadata={"filters": {"initiated_by": shape}},
        )

    def tenant_oversight_read() -> None:
        run_tenant_oversight_read(
            caller=operator,
            operation=AI_USAGE_READ,
            tenant_id=tenant_id,
            target_type="tenant",
            read=nothing_may_be_read,
            request_metadata={"initiated_by": Initiator.user(user_id)},
        )

    def platform_change() -> None:
        run_platform_change(
            caller=operator,
            operation=FEATURE_FLAG_DEFINE,
            target_type="feature_flag",
            change=lambda session: PlatformChange(
                value=None, target_id="d2", metadata={"initiated_by": shape}
            ),
            reason="D2 gate integration test",
        )

    return {
        "tenant: typed argument, SystemCaller": (tenant_typed_system_caller, InvalidActorError),
        "tenant: typed argument from an outbox context": (
            tenant_typed_from_outbox_context,
            InvalidActorError,
        ),
        "tenant: top-level metadata key (reserved)": (
            tenant_record({"initiated_by": shape}),
            ReservedMetadataKeyError,
        ),
        "tenant: nested metadata key, record()": (
            tenant_record({"source": {"initiated_by": shape}}),
            InvalidActorError,
        ),
        "tenant: nested in a list, UserCaller": (tenant_user_caller_nested, InvalidActorError),
        "tenant: bare id, system action": (tenant_system_action_nested_string, InvalidActorError),
        "platform: top-level user shape": (
            platform_event({"initiated_by": shape}),
            InvalidActorError,
        ),
        "platform: Initiator object": (
            platform_event({"initiated_by": Initiator.user(user_id)}),
            InvalidActorError,
        ),
        "platform: nested, other spelling": (
            platform_event({"request": {" INITIATED_BY": shape}}),
            InvalidActorError,
        ),
        "platform: refusal writer (marker row)": (platform_refusal, None),
        "platform: refusal context manager (marker row)": (
            refusal_context_manager,
            PlatformNotAuthorizedError,
        ),
        "platform: system shape naming a user record": (
            platform_event({"initiated_by": system_shape_naming_a_user}),
            InvalidActorError,
        ),
        "platform: system shape whose actor name embeds the id": (
            platform_event({"initiated_by": system_shape_embedding_the_id}),
            InvalidActorError,
        ),
        "tenant: system initiator naming a user record": (
            tenant_system_initiator_naming_a_user,
            InvalidSystemActorError,
        ),
        "platform: oversight attempt": (oversight_attempt, InvalidActorError),
        "platform: oversight read": (oversight_read, InvalidActorError),
        "platform: tenant oversight read": (tenant_oversight_read, InvalidActorError),
        "platform: caller-supplied change": (platform_change, InvalidActorError),
    }


def test_no_refusal_scenario_leaves_a_user_initiator_in_any_new_audit_row(
    platform: PlatformWorld, tenant: uuid.UUID
) -> None:
    operator, _ = platform.owner()
    user_id = uuid.uuid4()
    before = _counts(platform, tenant)
    assert _leaks(platform, user_id) == {"core.audit_log": 0, "core.platform_audit_log": 0}

    outcomes: dict[str, str] = {}
    markers = 0
    for name, (scenario, expected) in _scenarios(tenant, operator, user_id).items():
        if expected is None:
            assert scenario() is True, name
            outcomes[name] = "returned True"
        else:
            with pytest.raises(expected) as refused:
                scenario()
            message = str(refused.value)
            assert str(user_id) not in message and user_id.hex not in message, name
            outcomes[name] = type(refused.value).__name__
        if "(marker row)" in name:
            markers += 1
        # Nothing else committed, in either table, after each scenario; the
        # refusal writers add exactly one marker row each.
        assert _counts(platform, tenant) == (before[0], before[1] + markers), name
        assert _leaks(platform, user_id) == {"core.audit_log": 0, "core.platform_audit_log": 0}

    assert len(outcomes) == 18
    assert markers == 2
    marker_rows = [
        row
        for row in platform.audit(outcome="denied")
        if row["metadata"] == {"metadata_refused": "d2"}
    ]
    assert len(marker_rows) == 2
    assert {row["reason"] for row in marker_rows} == {"not_authorized"}
    assert all(row["actor_user_id"] == operator.user_id for row in marker_rows)
    assert _leaks(platform, user_id) == {"core.audit_log": 0, "core.platform_audit_log": 0}


def test_allowlisted_initiators_are_committed_exactly_as_given(
    platform: PlatformWorld, tenant: uuid.UUID
) -> None:
    """D2 refuses the user type only. A service-account or system
    initiator's shape, `"unavailable"` and `None` are written to both
    tables unchanged (no conversion), wherever they stand."""
    operator, _ = platform.owner()
    account = Initiator.service_account(uuid.uuid4()).as_metadata()
    system = Initiator.system(_ACTOR, record_type="provider_event", record_id="evt_1").as_metadata()
    platform_metadata = {
        "initiated_by": account,
        "steps": [{"initiated_by": system}, {"initiated_by": "unavailable"}],
        "previous": {"initiated_by": None},
    }
    with session_scope() as session:
        record_platform_event_in_transaction(
            session,
            caller=operator,
            action="platform.test.initiator_accepted",
            target_type="d2",
            metadata=platform_metadata,
        )
    assert record_platform_refusal(
        caller=operator,
        action="platform.test.initiator_refused",
        target_type="d2",
        code="not_authorized",
        metadata={"initiated_by": "unavailable"},
    )
    (accepted,) = platform.audit(action="platform.test.initiator_accepted")
    assert accepted["metadata"] == platform_metadata
    (refusal,) = platform.audit(action="platform.test.initiator_refused")
    assert refusal["metadata"] == {"initiated_by": "unavailable"}

    tenant_metadata = {"source": {"initiated_by": system}, "n": 1}
    with tenant_session_scope(tenant) as session:
        row = record_system_action_in_transaction(
            session,
            tenant_id=tenant,
            actor=_ACTOR,
            action="test.d2.accepted",
            resource_type="d2",
            metadata=tenant_metadata,
            initiated_by=None,
        )
        row_id = row.id
    stored = platform.scalar("SELECT metadata FROM core.audit_log WHERE id = :i", {"i": row_id})
    assert stored == {
        **tenant_metadata,
        "system_actor": _ACTOR.as_metadata(),
        "initiated_by": "unavailable",
        "correlation": {},
    }


# --- Final closure (owner, 2026-11-03) -------------------------------------------
#
# Attribution values under any key spelling, correlation carrying identity,
# and forged typed correlation: refused by both writers against PostgreSQL,
# with nothing committed and the id in neither table; recorded shapes are
# stored rebuilt, equal to what was given, to the same `jsonb` text.


def _closure_scenarios(
    tenant_id: uuid.UUID, operator: UserCaller, user_id: uuid.UUID
) -> dict[str, tuple[Callable[[], Any], type[BaseException] | None]]:
    shape = {"type": "user", "user_id": str(user_id)}

    def platform_event(metadata: dict[str, object]) -> Callable[[], Any]:
        def run() -> None:
            with session_scope() as session:
                record_platform_event_in_transaction(
                    session,
                    caller=operator,
                    action="platform.test.closure",
                    target_type="d2",
                    metadata=metadata,
                )

        return run

    def tenant_record(metadata: dict[str, object]) -> Callable[[], Any]:
        return lambda: record(
            tenant_id=tenant_id,
            actor_type=ActorType.SYSTEM,
            action="test.d2.closure",
            resource_type="d2",
            outcome=AuditOutcome.DENIED,
            metadata=metadata,
        )

    def tenant_forged_typed_correlation() -> None:
        forged = SystemCorrelation(request_id="r-1")
        object.__setattr__(forged, "request_id", f"user:{user_id}")
        with tenant_session_scope(tenant_id) as session:
            record_in_transaction(
                session,
                caller=SystemCaller(SystemAuthority.PROVISIONING, actor=_ACTOR),
                tenant_id=tenant_id,
                action="test.d2.closure",
                resource_type="d2",
                correlation=forged,
            )

    def tenant_correlation_naming_a_user() -> None:
        with tenant_session_scope(tenant_id) as session:
            record_system_action_in_transaction(
                session,
                tenant_id=tenant_id,
                actor=_ACTOR,
                action="test.d2.closure",
                resource_type="d2",
                correlation=SystemCorrelation(request_id=f"user_{user_id.hex}"),
            )

    def tenant_nested_system_actor() -> None:
        with tenant_session_scope(tenant_id) as session:
            record_system_action_in_transaction(
                session,
                tenant_id=tenant_id,
                actor=_ACTOR,
                action="test.d2.closure",
                resource_type="d2",
                metadata={"steps": [{"System-Actor": {**_ACTOR.as_metadata(), "user": shape}}]},
            )

    def platform_refusal_correlation() -> bool:
        return record_platform_refusal(
            caller=operator,
            action="platform.operator.read",
            target_type="platform_operator",
            code="not_authorized",
            metadata={"correlation": {"user_id": str(user_id)}},
        )

    def oversight_attempt_correlation() -> None:
        record_oversight_attempt(
            caller=operator,
            operation=OPERATOR_READ,
            target_type="platform_operator",
            metadata={"page": {"correlation": {"request_id": f"user:{user_id}"}}},
        )

    def platform_change_spelling() -> None:
        run_platform_change(
            caller=operator,
            operation=FEATURE_FLAG_DEFINE,
            target_type="feature_flag",
            change=lambda session: PlatformChange(
                value=None, target_id="d2", metadata={"x": {"initiated-by": shape}}
            ),
            reason="D2 closure integration test",
        )

    return {
        "platform: camel-case key": (platform_event({"initiatedBy": shape}), InvalidActorError),
        "platform: dotted key in a list": (
            platform_event({"steps": [{"INITIATED.BY": shape}]}),
            InvalidActorError,
        ),
        "platform: correlation naming a user": (
            platform_event({"correlation": {"request_id": f"user:{user_id}"}}),
            InvalidActorError,
        ),
        "platform: system_actor with a user field": (
            platform_event({"system_actor": {**_ACTOR.as_metadata(), "user_id": str(user_id)}}),
            InvalidActorError,
        ),
        "platform: refusal writer, correlation (marker row)": (
            platform_refusal_correlation,
            None,
        ),
        "platform: oversight attempt, nested correlation": (
            oversight_attempt_correlation,
            InvalidActorError,
        ),
        "platform: caller-supplied change, hyphen key": (
            platform_change_spelling,
            InvalidActorError,
        ),
        "tenant: nested correlation with a user field": (
            tenant_record({"source": {"correlation": {"user_id": str(user_id)}}}),
            InvalidActorError,
        ),
        "tenant: top-level camel-case key (reserved)": (
            tenant_record({"initiatedBy": shape}),
            ReservedMetadataKeyError,
        ),
        "tenant: forged typed correlation": (tenant_forged_typed_correlation, InvalidActorError),
        "tenant: correlation naming a user": (
            tenant_correlation_naming_a_user,
            InvalidSystemActorError,
        ),
        "tenant: nested system_actor with a user": (
            tenant_nested_system_actor,
            InvalidActorError,
        ),
    }


def test_no_closure_scenario_leaves_an_identity_in_any_new_audit_row(
    platform: PlatformWorld, tenant: uuid.UUID
) -> None:
    operator, _ = platform.owner()
    user_id = uuid.uuid4()
    before = _counts(platform, tenant)
    assert _leaks(platform, user_id) == {"core.audit_log": 0, "core.platform_audit_log": 0}
    markers = 0
    scenarios = _closure_scenarios(tenant, operator, user_id)
    for name, (scenario, expected) in scenarios.items():
        if expected is None:
            assert scenario() is True, name
            markers += 1
        else:
            with pytest.raises(expected) as refused:
                scenario()
            message = str(refused.value)
            assert str(user_id) not in message and user_id.hex not in message, name
        assert _counts(platform, tenant) == (before[0], before[1] + markers), name
        assert _leaks(platform, user_id) == {"core.audit_log": 0, "core.platform_audit_log": 0}
    assert len(scenarios) == 12
    assert markers == 1
    (marker,) = [
        row
        for row in platform.audit(outcome="denied")
        if row["metadata"] == {"metadata_refused": "d2"}
    ]
    assert marker["actor_user_id"] == operator.user_id


def test_recorded_attribution_shapes_are_committed_rebuilt_to_the_same_jsonb(
    platform: PlatformWorld, tenant: uuid.UUID
) -> None:
    operator, _ = platform.owner()
    event_id = uuid.uuid4()
    correlation = SystemCorrelation(
        arq_job_id=uuid.uuid4().hex, outbox_event_id=event_id, request_id=str(uuid.uuid4())
    )
    platform_metadata: dict[str, object] = {
        "correlation": correlation.as_metadata(),
        "system_actor": _ACTOR.as_metadata(),
        "steps": [{"correlation": {"arq_job_id": "cron:digest:1730600000000"}}],
        "initiated_by": "unavailable",
        "values": ["Zoë", 0.5, True, None, 2**40],
    }
    with session_scope() as session:
        row = record_platform_event_in_transaction(
            session,
            caller=operator,
            action="platform.test.closure_accepted",
            target_type="d2",
            metadata=platform_metadata,
        )
        platform_row_id = row.id
    (accepted,) = platform.audit(action="platform.test.closure_accepted")
    assert accepted["metadata"] == platform_metadata
    assert platform.scalar(
        "SELECT metadata::text = CAST(:j AS jsonb)::text "
        "FROM core.platform_audit_log WHERE id = :i",
        {"i": platform_row_id, "j": json.dumps(platform_metadata)},
    )

    tenant_metadata: dict[str, object] = {"source": {"correlation": {}}, "n": 1}
    with tenant_session_scope(tenant) as session:
        tenant_row = record_system_action_in_transaction(
            session,
            tenant_id=tenant,
            actor=_ACTOR,
            action="test.d2.closure_accepted",
            resource_type="d2",
            metadata=tenant_metadata,
            correlation=correlation,
        )
        tenant_row_id = tenant_row.id
    expected = {
        **tenant_metadata,
        "system_actor": _ACTOR.as_metadata(),
        "initiated_by": "unavailable",
        "correlation": correlation.as_metadata(),
    }
    assert (
        platform.scalar("SELECT metadata FROM core.audit_log WHERE id = :i", {"i": tenant_row_id})
        == expected
    )
    assert platform.scalar(
        "SELECT metadata::text = CAST(:j AS jsonb)::text FROM core.audit_log WHERE id = :i",
        {"i": tenant_row_id, "j": json.dumps(expected)},
    )
