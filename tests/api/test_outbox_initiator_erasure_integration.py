"""User erasure of a stored outbox-event initiator (owner decision of
2026-11-02, ADR 0061) -- against a real PostgreSQL and Redis.

`erase_user_identity()` replaces, in each tenant it is given, every stored
`saas_os.initiated_by` that names the erased user as a user initiator with
the sentinel `"unavailable"`, in the transaction that locks the user's
membership and under that tenant's Row-Level Security
(`saas_os.core.outbox.initiator_erasure.erase_user_initiator()`: matched
rows locked and rewritten in Python, only the reserved key's value
replaced).
These tests prove:

- the business payload, event id, status, attempts, claim columns, next
  attempt time and `updated_at` are unchanged, for pending (claimed or
  not), dead-lettered and published events;
- erasure concurrent with a claim or a completion (two connections, row
  locks) neither loses the dispatcher's update nor brings the user id back;
- a repeat erases nothing and changes nothing;
- a retry after erasure hands the consumer `initiated_by=None` and its audit
  row records `"unavailable"`; an attempt that read the event before the
  erasure keeps the user id for that attempt only;
- other users', non-user and other tenants' initiators are untouched.

Marked `integration`.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.api.outbox_dispatcher as outbox_dispatcher
import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.api.outbox_dispatcher import OUTBOX_JOB_FUNCTIONS, dispatch_outbox_once
from saas_os.core.audit_log import AuditLogEntry, record_system_action_in_transaction
from saas_os.core.authority import (
    Initiator,
    SystemActor,
    SystemActorKind,
    SystemAuthority,
    SystemCaller,
    SystemCorrelation,
)
from saas_os.core.identity.erasure import erase_user_identity
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.outbox import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxDispatchConfig,
    append_event,
    begin_event_execution,
    claim_due_events,
    complete_event,
)
from saas_os.core.outbox.initiator_erasure import erase_user_initiator
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload, build_worker
from saas_os.infra.jobs.queue import get_redis_pool

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_CONFIG = OutboxDispatchConfig(
    max_attempts=3, retry_jitter_ratio=0, lease_seconds=300, retry_base_seconds=60
)
_EVENT_TYPE = "attribution.erasure_test_event"
_ACTION = "test.attribution.erasure_consumed"
_KEY = "saas_os.initiated_by"
# A business payload with nested values, a float, a null and non-ASCII text:
# all of it must come back with the same meaning after the initiator is erased.
_BUSINESS: dict[str, object] = {
    "n": 1,
    "amount": 12.5,
    "nested": {"items": [1, "two", {"three": 3}], "flag": True},
    "note": "café – résumé",
    "empty": None,
}
# The columns the dispatcher decides on and the replay selects by: erasure
# must leave every one of them exactly as it was.
_STATE_COLUMNS = (
    "id",
    "tenant_id",
    "event_type",
    "aggregate_type",
    "aggregate_id",
    "correlation_id",
    "status",
    "attempts",
    "claim_token",
    "next_attempt_at",
    "last_error",
    "published_at",
    "created_at",
    "updated_at",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
async def _require_database_and_redis() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT claim_token FROM core.outbox_events LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated to RE-2: {exc}")
    finally:
        probe.dispose()
    try:
        pool = await get_redis_pool()
        await pool.ping()
        await pool.aclose()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable: {exc}")


def _admin(sql: str, params: Mapping[str, object]) -> list[Any]:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            result: Any = session.execute(text(sql), params)
            return list(result.all()) if result.returns_rows else []
    finally:
        engine.dispose()


class _World:
    """Fresh tenants and users; the dispatcher only sees these tenants, and
    every row written for them is removed afterwards (rows left behind
    would block later migration downgrades in a shared database)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        monkeypatch.setattr(
            dispatch,
            "list_open_tenant_ids",
            lambda: [t for t in list_open_tenant_ids() if t in self.tenant_ids],
        )

    def tenant(self) -> uuid.UUID:
        tenant_id = create_tenant(f"erase-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
        self.tenant_ids.append(tenant_id)
        return tenant_id

    def user(self) -> uuid.UUID:
        user_id = create_user().id
        self.user_ids.append(user_id)
        return user_id

    def cleanup(self) -> None:
        for tenant_id in self.tenant_ids:
            params = {"t": str(tenant_id)}
            for table in (
                "outbox_consumptions",
                "outbox_events",
                "membership_roles",
                "tenant_memberships",
            ):
                _admin(f"DELETE FROM core.{table} WHERE tenant_id = :t", params)  # noqa: S608
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)
        for user_id in self.user_ids:
            params = {"u": str(user_id)}
            _admin("DELETE FROM core.audit_log WHERE actor_user_id = :u", params)
            _admin("DELETE FROM core.platform_audit_log WHERE actor_user_id = :u", params)
            _admin("DELETE FROM core.sessions WHERE user_id = :u", params)
            _admin("DELETE FROM core.external_identities WHERE user_id = :u", params)
            _admin("DELETE FROM core.users WHERE id = :u", params)


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[_World]:
    registry = _World(monkeypatch)
    try:
        yield registry
    finally:
        registry.cleanup()


class _Consumer:
    """Records what it was handed and writes one system audit row exactly
    as ADR 0061 tells a product to. `fail_first` makes its first call fail
    before writing anything, so the event is retried; `during` runs inside
    the first call, after the context was built (an erasure while the
    consumer is processing)."""

    def __init__(self) -> None:
        self.contexts: list[TenantJobContext] = []
        self.fail_first = False
        self.during: Any = None

    async def __call__(self, context: TenantJobContext, payload: TenantJobPayload) -> None:
        self.contexts.append(context)
        if self.during is not None and len(self.contexts) == 1:
            self.during()
        if self.fail_first and len(self.contexts) == 1:
            raise RuntimeError("first attempt fails")
        with tenant_session_scope(context.tenant_id) as session:
            record_system_action_in_transaction(
                session,
                tenant_id=context.tenant_id,
                actor=SystemActor.from_job_actor(context.system_actor),
                action=_ACTION,
                resource_type="attribution_test",
                initiated_by=Initiator.from_job_initiator(context.initiated_by),
                correlation=SystemCorrelation.from_job_context(context),
            )


@pytest.fixture
def consumer(monkeypatch: pytest.MonkeyPatch) -> _Consumer:
    handler = _Consumer()
    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {_EVENT_TYPE: handler})
    return handler


def _append(tenant_id: uuid.UUID, initiated_by: Initiator | None) -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        return append_event(
            session,
            tenant_id=tenant_id,
            event_type=_EVENT_TYPE,
            aggregate_type="attribution_test",
            aggregate_id="a-1",
            payload=dict(_BUSINESS),
            initiated_by=initiated_by,
        )


def _erase(tenant_id: uuid.UUID, user_id: uuid.UUID) -> int:
    with tenant_session_scope(tenant_id) as session:
        return erase_user_initiator(session, tenant_id=tenant_id, user_id=user_id)


def _row(event_id: uuid.UUID) -> dict[str, Any]:
    """The stored row, read with the migrations role: every state column,
    the payload as parsed JSON and its exact stored text."""
    (row,) = _admin(
        f"SELECT {', '.join(_STATE_COLUMNS)}, payload, payload::text "  # noqa: S608
        "FROM core.outbox_events WHERE id = :i",
        {"i": str(event_id)},
    )
    columns: tuple[str, ...] = (*_STATE_COLUMNS, "payload", "payload_text")
    return dict(zip(columns, row, strict=True))


def _state(row: Mapping[str, Any]) -> dict[str, Any]:
    return {column: row[column] for column in _STATE_COLUMNS}


def _user(user_id: uuid.UUID) -> dict[str, str]:
    return {"type": "user", "user_id": str(user_id)}


def _erased_text(stored_text: str, user_id: uuid.UUID) -> str:
    """The stored JSON text with only the user initiator's object replaced
    by the sentinel -- what an in-place erasure must produce."""
    initiator = json.dumps(_user(user_id))
    assert stored_text.count(initiator) == 1
    return stored_text.replace(initiator, '"unavailable"')


def _audit_rows(tenant_id: uuid.UUID) -> list[AuditLogEntry]:
    with tenant_session_scope(tenant_id) as session:
        rows = (
            session.execute(
                select(AuditLogEntry)
                .where(AuditLogEntry.tenant_id == tenant_id)
                .where(AuditLogEntry.action == _ACTION)
                .order_by(AuditLogEntry.created_at)
            )
            .scalars()
            .all()
        )
        for row in rows:
            session.expunge(row)
        return list(rows)


async def _dispatch_and_run(*, now: datetime | None = None) -> None:
    queue_name = f"erase-outbox-{uuid.uuid4().hex[:8]}"
    report = await dispatch_outbox_once(config=_CONFIG, queue_name=queue_name, now=now)
    assert report.enqueued >= 1
    worker = build_worker(OUTBOX_JOB_FUNCTIONS, burst=True, queue_name=queue_name)
    try:
        await worker.main()
    finally:
        await worker.close()


# --- Normal erasure through erase_user_identity ----------------------------------------


async def test_erase_user_identity_replaces_the_users_stored_initiator_only(
    world: _World,
) -> None:
    tenant_id = world.tenant()
    actor, user = world.user(), world.user()
    add_tenant_membership(tenant_id, user, caller=SystemCaller(SystemAuthority.PROVISIONING))
    event_id = _append(tenant_id, Initiator.user(user))
    before = _row(event_id)
    assert before["payload"] == {**_BUSINESS, _KEY: _user(user)}

    result = erase_user_identity(user, [tenant_id], actor_user_id=actor)

    after = _row(event_id)
    assert result.outbox_initiators_erased == 1
    # Only the initiator changed, to the documented sentinel ...
    assert after["payload"] == {**_BUSINESS, _KEY: "unavailable"}
    assert str(user) not in after["payload_text"]
    # ... in place: every other key keeps its value, its position and its
    # exact stored text (review of b6a7f07: no jsonb reordering).
    assert list(after["payload"]) == list(before["payload"])
    assert after["payload_text"] == _erased_text(before["payload_text"], user)
    # ... and the event's identity, status and schedule did not.
    assert _state(after) == _state(before)
    assert after["status"] == OUTBOX_STATUS_PENDING and after["claim_token"] is None
    # The erasure's own audit row reports the count (a number, no event id).
    (metadata,) = _admin(
        "SELECT metadata FROM core.audit_log WHERE tenant_id = :t "
        "AND action = 'identity.erasure_membership_removed'",
        {"t": str(tenant_id)},
    )
    assert metadata[0]["outbox_initiators_erased"] == 1


async def test_a_claimed_event_keeps_its_claim_and_completes_after_erasure(
    world: _World,
) -> None:
    tenant_id = world.tenant()
    user = uuid.uuid4()
    event_id = _append(tenant_id, Initiator.user(user))
    (claim,) = claim_due_events(config=_CONFIG)
    before = _row(event_id)
    assert before["claim_token"] == claim.claim_token and before["attempts"] == 1

    assert _erase(tenant_id, user) == 1

    after = _row(event_id)
    assert _state(after) == _state(before)
    assert after["payload"] == {**_BUSINESS, _KEY: "unavailable"}
    # The dispatcher's claim-token transitions still succeed ...
    execution = begin_event_execution(tenant_id, event_id, claim.claim_token, config=_CONFIG)
    assert execution is not None
    # ... and an attempt that reads the row after erasure sees no initiator.
    assert execution.initiated_by is None
    assert execution.payload == _BUSINESS
    assert complete_event(tenant_id, event_id, claim.claim_token)
    final = _row(event_id)
    assert final["status"] == OUTBOX_STATUS_PUBLISHED and final["claim_token"] is None
    assert final["payload"] == {**_BUSINESS, _KEY: "unavailable"}


@pytest.mark.parametrize("status", [OUTBOX_STATUS_DEAD_LETTERED, OUTBOX_STATUS_PUBLISHED])
async def test_dead_lettered_and_published_events_are_erased_too(
    world: _World, status: str
) -> None:
    """A dead-lettered event can be replayed; a published one never runs
    again but is kept until the tenant is purged, holding the same
    reference. Both are erased; status and timestamps stay."""
    tenant_id = world.tenant()
    user = uuid.uuid4()
    event_id = _append(tenant_id, Initiator.user(user))
    _admin(
        "UPDATE core.outbox_events SET status = CAST(:s AS text), attempts = 3, "
        "last_error = 'X: y', "
        "published_at = CASE WHEN CAST(:s AS text) = 'published' THEN now() END WHERE id = :i",
        {"s": status, "i": str(event_id)},
    )
    before = _row(event_id)

    assert _erase(tenant_id, user) == 1

    after = _row(event_id)
    assert _state(after) == _state(before)
    assert after["status"] == status
    assert after["payload"] == {**_BUSINESS, _KEY: "unavailable"}


async def test_repeated_erasure_is_idempotent(world: _World) -> None:
    tenant_id = world.tenant()
    user = uuid.uuid4()
    event_id = _append(tenant_id, Initiator.user(user))
    assert _erase(tenant_id, user) == 1
    once = _row(event_id)

    assert _erase(tenant_id, user) == 0

    assert _row(event_id) == once  # not even the stored text changed


# --- Isolation ------------------------------------------------------------------------


async def test_other_users_non_user_initiators_and_other_tenants_are_untouched(
    world: _World,
) -> None:
    tenant_id, other_tenant = world.tenant(), world.tenant()
    user, other_user = uuid.uuid4(), uuid.uuid4()
    target = _append(tenant_id, Initiator.user(user))
    untouched = [
        _append(tenant_id, Initiator.user(other_user)),
        # A service account whose id happens to equal the user's id: only a
        # *user* initiator naming the user is the user.
        _append(tenant_id, Initiator.service_account(user)),
        _append(
            tenant_id,
            Initiator.system(
                SystemActor(SystemActorKind.PUBLIC_LINK, "erase_test.link"),
                record_type="link",
                record_id=str(user),
            ),
        ),
        _append(tenant_id, None),
        # The same user initiated an event in a tenant this erasure is not for.
        _append(other_tenant, Initiator.user(user)),
    ]
    before = {event_id: _row(event_id) for event_id in untouched}

    assert _erase(tenant_id, user) == 1

    assert _row(target)["payload"][_KEY] == "unavailable"
    for event_id, row in before.items():
        # Byte-for-byte: not even the stored JSON text was rewritten.
        assert _row(event_id) == row


async def test_rls_confines_the_erasure_to_the_sessions_tenant(world: _World) -> None:
    """Naming another tenant from a tenant's session reaches nothing: the
    statement's own tenant predicate and Row-Level Security both confine
    it."""
    tenant_id, other_tenant = world.tenant(), world.tenant()
    user = uuid.uuid4()
    other_event = _append(other_tenant, Initiator.user(user))
    before = _row(other_event)

    with tenant_session_scope(tenant_id) as session:
        assert erase_user_initiator(session, tenant_id=other_tenant, user_id=user) == 0

    assert _row(other_event) == before


# --- Concurrency (two connections, row locks) -----------------------------------------


async def test_erasure_waits_for_a_claim_in_progress_and_loses_nothing(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dispatcher holds the row lock (claim transaction not yet
    committed); the erasure waits on it, then applies on top of the
    committed claim: claim token and attempt survive, the user id is gone."""
    tenant_id = world.tenant()
    user = uuid.uuid4()
    event_id = _append(tenant_id, Initiator.user(user))
    paused, release = threading.Event(), threading.Event()

    def _hold(session: object) -> None:
        if threading.current_thread().name == "dispatcher":
            paused.set()
            assert release.wait(timeout=30), "dispatcher never released"

    monkeypatch.setattr(dispatch, "_claim_hook", _hold)
    outcome: dict[str, Any] = {}
    dispatcher = threading.Thread(
        target=lambda: outcome.setdefault("claims", claim_due_events(config=_CONFIG)),
        name="dispatcher",
    )
    eraser = threading.Thread(
        target=lambda: outcome.setdefault("erased", _erase(tenant_id, user)), name="eraser"
    )
    dispatcher.start()
    try:
        assert paused.wait(timeout=30), "dispatcher never reached its claim"
        eraser.start()
        eraser.join(timeout=1)
        assert eraser.is_alive(), "erasure did not wait for the claim's row lock"
    finally:
        release.set()
        dispatcher.join(timeout=30)
        eraser.join(timeout=30)

    (claim,) = outcome["claims"]
    assert outcome["erased"] == 1
    row = _row(event_id)
    assert row["claim_token"] == claim.claim_token and row["attempts"] == 1
    assert row["status"] == OUTBOX_STATUS_PENDING
    assert row["payload"] == {**_BUSINESS, _KEY: "unavailable"}


async def test_a_completion_waits_for_an_erasure_in_progress_and_still_succeeds(
    world: _World,
) -> None:
    """The erasure holds the row lock (its transaction not yet committed);
    the dispatcher's claim-token completion waits on it, then succeeds on
    the erased row: the status update is not lost and does not bring the
    user id back."""
    tenant_id = world.tenant()
    user = uuid.uuid4()
    event_id = _append(tenant_id, Initiator.user(user))
    (claim,) = claim_due_events(config=_CONFIG)
    updated, release = threading.Event(), threading.Event()
    outcome: dict[str, Any] = {}

    def _erase_and_hold() -> None:
        with tenant_session_scope(tenant_id) as session:
            outcome["erased"] = erase_user_initiator(session, tenant_id=tenant_id, user_id=user)
            updated.set()
            assert release.wait(timeout=30), "eraser never released"

    eraser = threading.Thread(target=_erase_and_hold, name="eraser")
    completer = threading.Thread(
        target=lambda: outcome.setdefault(
            "completed", complete_event(tenant_id, event_id, claim.claim_token)
        ),
        name="completer",
    )
    eraser.start()
    try:
        assert updated.wait(timeout=30), "eraser never ran its update"
        completer.start()
        completer.join(timeout=1)
        assert completer.is_alive(), "completion did not wait for the erasure's row lock"
    finally:
        release.set()
        eraser.join(timeout=30)
        completer.join(timeout=30)

    assert outcome == {"erased": 1, "completed": True}
    row = _row(event_id)
    assert row["status"] == OUTBOX_STATUS_PUBLISHED and row["claim_token"] is None
    assert row["published_at"] is not None
    assert row["payload"] == {**_BUSINESS, _KEY: "unavailable"}


async def test_erasure_while_the_consumer_runs_completes_without_resurrecting_the_user(
    world: _World, consumer: _Consumer
) -> None:
    """The documented limit: this attempt read the event before the
    erasure, so its consumer sees the user id once and its audit row (a
    completed record, never changed by erasure) holds it. The completion
    still succeeds and the stored event stays erased."""
    tenant_id = world.tenant()
    user = uuid.uuid4()
    event_id = _append(tenant_id, Initiator.user(user))
    consumer.during = lambda: _erase(tenant_id, user)

    await _dispatch_and_run()

    (context,) = consumer.contexts
    assert context.initiated_by is not None and context.initiated_by.user_id == str(user)
    (audit,) = _audit_rows(tenant_id)
    assert audit.entry_metadata is not None
    assert audit.entry_metadata["initiated_by"] == _user(user)
    row = _row(event_id)
    assert row["status"] == OUTBOX_STATUS_PUBLISHED and row["claim_token"] is None
    assert row["payload"] == {**_BUSINESS, _KEY: "unavailable"}


# --- Retry after erasure --------------------------------------------------------------


async def test_a_retry_after_erasure_hands_the_consumer_an_unavailable_initiator(
    world: _World, consumer: _Consumer
) -> None:
    tenant_id = world.tenant()
    user = uuid.uuid4()
    event_id = _append(tenant_id, Initiator.user(user))
    consumer.fail_first = True

    await _dispatch_and_run()  # attempt 1 fails before writing anything
    failed = _row(event_id)
    assert failed["status"] == OUTBOX_STATUS_PENDING and failed["attempts"] == 1
    assert _audit_rows(tenant_id) == []

    assert _erase(tenant_id, user) == 1
    assert _state(_row(event_id)) == _state(failed)

    # The retry is due at its scheduled time; dispatch as of then.
    await _dispatch_and_run(now=failed["next_attempt_at"] + timedelta(seconds=1))

    first, retry = consumer.contexts
    assert first.initiated_by is not None  # read before the erasure
    assert retry.initiated_by is None
    assert retry.event_id == first.event_id == event_id  # same idempotency identity
    (audit,) = _audit_rows(tenant_id)
    assert audit.entry_metadata is not None
    assert audit.entry_metadata["initiated_by"] == "unavailable"
    assert str(user) not in json.dumps(audit.entry_metadata)
    final = _row(event_id)
    assert final["status"] == OUTBOX_STATUS_PUBLISHED and final["attempts"] == 2
    assert final["payload"] == {**_BUSINESS, _KEY: "unavailable"}


# --- Review of b6a7f07 ------------------------------------------------------------------


async def test_a_payload_with_a_nul_escape_is_erased_and_otherwise_unchanged(
    world: _World,
) -> None:
    """MEDIUM: the `json` column accepts a `\\u0000` escape, `jsonb` refuses
    it. The erasure must neither fail on such a row (failing every rerun and
    leaving the user's erasure half done) nor touch the rest of its
    payload."""
    tenant_id = world.tenant()
    actor, user = world.user(), world.user()
    business: dict[str, object] = {"z": "a\x00b", "a": ["\x00", {"k": "x\x00"}], "n": 1}
    with tenant_session_scope(tenant_id) as session:
        event_id = append_event(
            session,
            tenant_id=tenant_id,
            event_type=_EVENT_TYPE,
            aggregate_type="attribution_test",
            aggregate_id="a-1",
            payload=business,
            initiated_by=Initiator.user(user),
        )
    before = _row(event_id)
    assert "\\u0000" in before["payload_text"]

    result = erase_user_identity(user, [tenant_id], actor_user_id=actor)

    after = _row(event_id)
    assert result.outbox_initiators_erased == 1
    assert after["payload"] == {**business, _KEY: "unavailable"}
    assert list(after["payload"]) == list(before["payload"])
    assert after["payload_text"] == _erased_text(before["payload_text"], user)
    assert _state(after) == _state(before)


async def test_a_retried_body_keeps_its_key_order_after_erasure(
    world: _World, consumer: _Consumer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reviewer's point: a jsonb round trip reorders keys, so a webhook
    retried after erasure could send a body in another order. The consumer
    gets the payload in exactly the producer's key order."""
    tenant_id = world.tenant()
    user = uuid.uuid4()
    ordered: dict[str, object] = {"zeta": 1, "alpha": {"y": 2, "b": 3}, "mid": [3, 2, 1]}
    with tenant_session_scope(tenant_id) as session:
        event_id = append_event(
            session,
            tenant_id=tenant_id,
            event_type=_EVENT_TYPE,
            aggregate_type="attribution_test",
            aggregate_id="a-1",
            payload=ordered,
            initiated_by=Initiator.user(user),
        )
    received: list[list[str]] = []

    async def _record_order(context: TenantJobContext, payload: TenantJobPayload) -> None:
        received.append(list(payload.data))
        alpha = payload.data["alpha"]
        assert isinstance(alpha, dict)
        received.append(list(alpha))
        await consumer(context, payload)

    monkeypatch.setattr(
        outbox_dispatcher, "outbox_event_handlers", lambda: {_EVENT_TYPE: _record_order}
    )
    assert _erase(tenant_id, user) == 1
    await _dispatch_and_run()

    assert received == [["zeta", "alpha", "mid"], ["y", "b"]]
    assert _row(event_id)["status"] == OUTBOX_STATUS_PUBLISHED


async def test_a_non_canonical_stored_user_id_is_still_erased(world: _World) -> None:
    """A stored id spelled otherwise (only possible by editing the row: the
    producer side writes the canonical form) is delivered as unavailable by
    the dispatcher, and erasure still finds and replaces it."""
    tenant_id = world.tenant()
    user = uuid.uuid4()
    spellings = [str(user).upper(), "{" + str(user) + "}", "urn:uuid:" + str(user), user.hex]
    events = []
    for spelling in spellings:
        event_id = _append(tenant_id, None)
        stored = json.dumps({"n": 1, _KEY: {"type": "user", "user_id": spelling}})
        _admin(
            "UPDATE core.outbox_events SET payload = CAST(:p AS json) WHERE id = :i",
            {"p": stored, "i": str(event_id)},
        )
        events.append(event_id)
    bystander = _append(tenant_id, Initiator.user(uuid.uuid4()))
    before = _row(bystander)

    assert _erase(tenant_id, user) == len(spellings)

    for event_id in events:
        assert _row(event_id)["payload"] == {"n": 1, _KEY: "unavailable"}
    assert _row(bystander) == before


async def test_initiators_erased_without_a_membership_are_still_audited(
    world: _World,
) -> None:
    """LOW: a tenant the user is no longer a member of (no
    `identity.erasure_membership_removed` row) still gets a row recording
    the count, in the erasure's transaction -- a count only."""
    tenant_id = world.tenant()
    actor, user = world.user(), world.user()
    _append(tenant_id, Initiator.user(user))
    _append(tenant_id, Initiator.user(user))

    result = erase_user_identity(user, [tenant_id], actor_user_id=actor)

    assert result.outbox_initiators_erased == 2
    assert result.tenants_with_membership_removed == ()
    query = (
        "SELECT action, actor_type, actor_user_id, resource_type, resource_id, metadata "
        "FROM core.audit_log WHERE tenant_id = :t AND action LIKE 'identity.erasure%'"
    )
    rows = _admin(query, {"t": str(tenant_id)})
    assert [tuple(r) for r in rows] == [
        (
            "identity.erasure_outbox_initiators_erased",
            "user",
            actor,
            "user",
            str(user),
            {"outbox_initiators_erased": 2},
        )
    ]
    # A repeat erases nothing and records nothing more.
    assert erase_user_identity(user, [tenant_id], actor_user_id=actor).outbox_initiators_erased == 0
    assert len(_admin(query, {"t": str(tenant_id)})) == 1
