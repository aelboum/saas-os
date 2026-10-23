"""RA-12-2 -- the Product-owned tenant purge participant contract
(`saas_os.core.tenancy.purge_participants`), against a real PostgreSQL instance.

Proves the contract end to end using `reference_consumer`'s own
`WidgetPurgeParticipant` (`examples/reference-consumer/reference_consumer/
purge.py`) as the Product proof implementation: a registered participant's
tenant-owned data is purged alongside Core's own `PURGE_STEPS`, purging
one tenant never touches a sibling's data, a failing participant keeps
the tenant `PURGING` (never `PURGED`) with bounded audit metadata, a
fixed participant succeeds on retry, no participant runs against a live
or already-purged tenant, and two concurrent purge attempts on one
tenant with a registered participant are still safe.

Every test uses its own isolated `TenantPurgeParticipantRegistry`
(`saas_os.core.tenancy.purge_participants` module docstring: "so a test can
construct its own isolated registry ... instead of mutating the one
shared process-wide registry") -- never the process-wide
`default_registry()` `reference_consumer/app.py::create_app()` registers
into, so this file has no order dependency on any other test module.

Marked `integration`, excluded from the default `pytest` run, mirroring
`tests/core/tenancy/test_tenant_purge_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/tenancy/test_purge_participants_integration.py
"""

from __future__ import annotations

import sys
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

import saas_os.core.identity.models  # noqa: F401 -- registers core.users, which saas_os.core.audit_log FKs onto
import saas_os.core.rbac  # noqa: F401 -- registers support_access_requests/delegation_grants for audit_log's FKs
from saas_os.core.tenancy import (
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    register_purge_participant,
    registered_purge_participant_names,
    transition_tenant_status,
)
from saas_os.core.tenancy import purge_participants as participants_module
from saas_os.core.tenancy.errors import InvalidTenantTransitionError, TenantPurgeIncompleteError
from saas_os.core.tenancy.purge_participants import TenantPurgeParticipantRegistry
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope

_REFERENCE_CONSUMER_ROOT = Path(__file__).resolve().parents[3] / "examples" / "reference-consumer"
if str(_REFERENCE_CONSUMER_ROOT) not in sys.path:
    sys.path.insert(0, str(_REFERENCE_CONSUMER_ROOT))

from reference_consumer.models import Widget  # noqa: E402
from reference_consumer.purge import WidgetPurgeParticipant  # noqa: E402

from lifecycle_callers import PROVISIONING, platform_operator  # noqa: E402
from lifecycle_callers import TENANT_PURGE as PURGE_AUTHORITY  # noqa: E402


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from sqlalchemy import text

    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine
    from saas_os.infra.db.session import build_session_factory, session_scope

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
            # ADR-0045 Phase C: lifecycle changes also write platform audit
            # rows, which reference the tenant or the acting user and which
            # the runtime role can never delete.
            platform_where = (
                "target_tenant_id::text = ANY(:v)"
                if table == "tenants"
                else "actor_user_id::text = ANY(:v)"
            )
            # A migration test may be cleaning up below the revision that
            # creates the table.
            if session.execute(text("SELECT to_regclass('core.platform_audit_log')")).scalar():
                session.execute(
                    text(f"DELETE FROM core.platform_audit_log WHERE {platform_where}"),  # noqa: S608
                    {"v": values},
                )
    finally:
        engine.dispose()


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")
    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.tenants LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at DATABASE_URL: {exc}")
    finally:
        probe_engine.dispose()
    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    """The privileged migrations role -- used only to observe true row
    counts regardless of RLS and to tear fixtures down."""
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def _uniq(prefix: str) -> str:
    return f"ra12-p2-{prefix}-{uuid.uuid4().hex[:8]}"


def _new_active_tenant() -> uuid.UUID:
    tenant = create_tenant(_uniq("tenant"), caller=PROVISIONING)
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE, caller=platform_operator())
    return tenant.id


def _seed_widget(tenant_id: uuid.UUID) -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        widget = Widget(tenant_id=tenant_id, name=_uniq("widget"), status="active")
        session.add(widget)
        session.flush()
        widget_id = widget.id
    return widget_id


def _widget_count(admin: sessionmaker[Session], tenant_id: uuid.UUID) -> int:
    with session_scope(session_factory=admin) as session:
        return session.execute(
            text("SELECT COUNT(*) FROM reference_consumer.widgets WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        ).scalar_one()


def _teardown(admin: sessionmaker[Session], *tenant_ids: uuid.UUID) -> None:
    with session_scope(session_factory=admin) as session:
        for tenant_id in tenant_ids:
            session.execute(
                text("DELETE FROM reference_consumer.widgets WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


class _CountingParticipant:
    """A fake `TenantPurgeParticipant` that records every call, optionally
    raising instead of succeeding -- used to prove Core's own orchestration
    (when it calls a participant, when it does not, how a failure is
    classified) without depending on `reference_consumer`'s own table."""

    def __init__(self, participant_name: str = "test.counting-participant") -> None:
        self._name = participant_name
        self.calls: list[uuid.UUID] = []
        self.should_raise: Exception | None = None

    @property
    def name(self) -> str:
        return self._name

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None:
        self.calls.append(tenant_id)
        if self.should_raise is not None:
            raise self.should_raise


def _lifecycle_event_metadata(
    admin: sessionmaker[Session], tenant_id: uuid.UUID, action: str
) -> list[dict]:
    with session_scope(session_factory=admin) as session:
        rows = session.execute(
            text(
                "SELECT metadata FROM core.audit_log "
                "WHERE tenant_id = :t AND action = :a ORDER BY created_at"
            ),
            {"t": str(tenant_id), "a": action},
        ).all()
    return [row[0] for row in rows]


# --- No participant registered: unchanged behavior --------------------------


def test_no_participants_registered_purges_core_data_exactly_as_before(
    admin: sessionmaker[Session],
) -> None:
    tenant_id = _new_active_tenant()
    try:
        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
        result = purge_tenant(
            tenant_id, caller=PURGE_AUTHORITY, registry=TenantPurgeParticipantRegistry()
        )
        assert get_tenant(tenant_id).status == TenantStatus.PURGED.value
        assert result.participant_names == ()
    finally:
        _teardown(admin, tenant_id)


# --- Successful purge: a real Product-owned table ----------------------------


def test_registered_participant_purges_only_the_target_tenants_widgets(
    admin: sessionmaker[Session],
) -> None:
    target_id = _new_active_tenant()
    sibling_id = _new_active_tenant()
    try:
        _seed_widget(target_id)
        _seed_widget(target_id)
        _seed_widget(sibling_id)
        assert _widget_count(admin, target_id) == 2
        assert _widget_count(admin, sibling_id) == 1

        registry = TenantPurgeParticipantRegistry()
        registry.register(WidgetPurgeParticipant())

        transition_tenant_status(target_id, TenantStatus.DELETED, caller=platform_operator())
        result = purge_tenant(target_id, caller=PURGE_AUTHORITY, registry=registry)

        assert get_tenant(target_id).status == TenantStatus.PURGED.value
        assert result.participant_names == ("reference_consumer.widgets",)
        assert _widget_count(admin, target_id) == 0
        # The sibling tenant's own widgets are completely untouched.
        assert _widget_count(admin, sibling_id) == 1
    finally:
        _teardown(admin, target_id, sibling_id)


def test_participant_purge_is_idempotent(admin: sessionmaker[Session]) -> None:
    """The participant's own contract: calling it again after it already
    ran (either directly, or via a `purge_tenant()` retry) finds nothing
    left and does not raise."""
    tenant_id = _new_active_tenant()
    try:
        _seed_widget(tenant_id)
        participant = WidgetPurgeParticipant()

        participant.purge_tenant_data(tenant_id)
        assert _widget_count(admin, tenant_id) == 0
        participant.purge_tenant_data(tenant_id)  # already empty -- must not raise
        assert _widget_count(admin, tenant_id) == 0

        registry = TenantPurgeParticipantRegistry()
        registry.register(participant)
        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
        first = purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=registry)
        second = purge_tenant(
            tenant_id, caller=PURGE_AUTHORITY, registry=registry
        )  # already PURGED
        assert first.participant_names == ("reference_consumer.widgets",)
        assert second.already_purged is True
        assert second.participant_names == ()  # short-circuited before the registry is consulted
    finally:
        _teardown(admin, tenant_id)


# --- Failure semantics --------------------------------------------------------


def test_failing_participant_prevents_purged_and_records_bounded_metadata(
    admin: sessionmaker[Session],
) -> None:
    tenant_id = _new_active_tenant()
    try:
        fake = _CountingParticipant("test.failing-participant")
        forbidden_detail = "raw-customer-content-should-never-be-stored-SECRET-XYZ"
        fake.should_raise = RuntimeError(forbidden_detail)
        registry = TenantPurgeParticipantRegistry()
        registry.register(fake)

        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
        with pytest.raises(RuntimeError, match=forbidden_detail):
            purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=registry)

        assert fake.calls == [tenant_id]
        refreshed = get_tenant(tenant_id)
        assert refreshed.status == TenantStatus.PURGING.value
        assert refreshed.name != f"purged-{tenant_id}"  # never tombstoned

        (metadata,) = _lifecycle_event_metadata(admin, tenant_id, "tenant.purge_failed")
        assert metadata["failure_class"] == "participant_error"
        assert metadata["failed_step"] == "participant:test.failing-participant"
        assert metadata["error_type"] == "RuntimeError"
        assert isinstance(metadata["passes_completed"], int)
        # Bounded: the exception's own message never reaches durable storage.
        assert forbidden_detail not in str(metadata)
    finally:
        _teardown(admin, tenant_id)


@pytest.mark.parametrize(
    "raised",
    [
        InvalidTenantTransitionError(TenantStatus.PURGING, TenantStatus.PURGED),
        TenantPurgeIncompleteError(uuid.uuid4(), {"product.rows": 1}),
    ],
    ids=["invalid-transition", "purge-incomplete"],
)
def test_a_participant_raising_a_core_exception_type_is_still_a_participant_error(
    admin: sessionmaker[Session], raised: Exception
) -> None:
    """The failure class follows the step, not the exception's type: a
    participant that raises one of Core's own purge exceptions is reported
    as `participant_error`, not as a Core transition or convergence failure."""
    tenant_id = _new_active_tenant()
    try:
        fake = _CountingParticipant("test.core-typed-failure")
        fake.should_raise = raised
        registry = TenantPurgeParticipantRegistry()
        registry.register(fake)

        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
        with pytest.raises(type(raised)):
            purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=registry)

        assert get_tenant(tenant_id).status == TenantStatus.PURGING.value
        (metadata,) = _lifecycle_event_metadata(admin, tenant_id, "tenant.purge_failed")
        assert metadata["failure_class"] == "participant_error"
        assert metadata["failed_step"] == "participant:test.core-typed-failure"
        assert metadata["error_type"] == type(raised).__name__
    finally:
        _teardown(admin, tenant_id)


def test_retry_after_participant_fix_reaches_purged(admin: sessionmaker[Session]) -> None:
    tenant_id = _new_active_tenant()
    try:
        _seed_widget(tenant_id)
        failing = _CountingParticipant("reference_consumer.widgets")
        failing.should_raise = RuntimeError("transient failure")
        failing_registry = TenantPurgeParticipantRegistry()
        failing_registry.register(failing)

        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
        with pytest.raises(RuntimeError, match="transient failure"):
            purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=failing_registry)
        assert get_tenant(tenant_id).status == TenantStatus.PURGING.value
        assert _widget_count(admin, tenant_id) == 1  # untouched by the failed attempt

        working_registry = TenantPurgeParticipantRegistry()
        working_registry.register(WidgetPurgeParticipant())
        result = purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=working_registry)

        assert get_tenant(tenant_id).status == TenantStatus.PURGED.value
        assert result.participant_names == ("reference_consumer.widgets",)
        assert _widget_count(admin, tenant_id) == 0
    finally:
        _teardown(admin, tenant_id)


# --- Lifecycle fencing ---------------------------------------------------------


@pytest.mark.parametrize("status", [TenantStatus.ACTIVE, TenantStatus.SUSPENDED])
def test_participant_is_not_invoked_for_a_live_tenant(
    status: TenantStatus, admin: sessionmaker[Session]
) -> None:
    tenant_id = _new_active_tenant()
    try:
        if status is TenantStatus.SUSPENDED:
            transition_tenant_status(tenant_id, TenantStatus.SUSPENDED, caller=platform_operator())
        fake = _CountingParticipant()
        registry = TenantPurgeParticipantRegistry()
        registry.register(fake)

        with pytest.raises(InvalidTenantTransitionError):
            purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=registry)

        assert fake.calls == []
        assert get_tenant(tenant_id).status == status.value
    finally:
        _teardown(admin, tenant_id)


def test_participant_is_not_invoked_for_an_already_purged_tenant(
    admin: sessionmaker[Session],
) -> None:
    tenant_id = _new_active_tenant()
    try:
        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
        purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=TenantPurgeParticipantRegistry())
        assert get_tenant(tenant_id).status == TenantStatus.PURGED.value

        fake = _CountingParticipant()
        registry = TenantPurgeParticipantRegistry()
        registry.register(fake)
        result = purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=registry)

        assert result.already_purged is True
        assert fake.calls == []
    finally:
        _teardown(admin, tenant_id)


def test_participant_cannot_purge_an_unrelated_tenant(admin: sessionmaker[Session]) -> None:
    """A registered participant only ever receives the tenant actually
    being purged -- proven by purging tenant A and confirming tenant B's
    id never appears among the participant's own recorded calls."""
    target_id = _new_active_tenant()
    unrelated_id = _new_active_tenant()
    try:
        fake = _CountingParticipant()
        registry = TenantPurgeParticipantRegistry()
        registry.register(fake)

        transition_tenant_status(target_id, TenantStatus.DELETED, caller=platform_operator())
        purge_tenant(target_id, caller=PURGE_AUTHORITY, registry=registry)

        assert fake.calls == [target_id]
        assert unrelated_id not in fake.calls
        assert get_tenant(unrelated_id).status == TenantStatus.ACTIVE.value
    finally:
        _teardown(admin, target_id, unrelated_id)


# --- Concurrency: reuses the existing Core purge locking guarantee ------------


def test_concurrent_purge_attempts_with_a_registered_participant_are_safe(
    admin: sessionmaker[Session],
) -> None:
    """Mirrors `test_tenant_purge_integration.py::test_concurrent_purge_attempts_are_safe`
    with a registered participant added: two racing `purge_tenant()` calls
    on the same tenant must not error, corrupt state, or leave the
    participant's own data behind, relying on the same tenant-row locking
    Core's own steps already use -- no second locking mechanism is
    introduced for participants."""
    tenant_id = _new_active_tenant()
    try:
        _seed_widget(tenant_id)
        registry = TenantPurgeParticipantRegistry()
        registry.register(WidgetPurgeParticipant())
        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())

        errors: list[BaseException] = []
        results: list[object] = []

        def _run() -> None:
            try:
                results.append(purge_tenant(tenant_id, caller=PURGE_AUTHORITY, registry=registry))
            except BaseException as exc:  # noqa: BLE001 -- collected and asserted below
                errors.append(exc)

        threads = [threading.Thread(target=_run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == [], errors
        assert len(results) == 2
        assert get_tenant(tenant_id).status == TenantStatus.PURGED.value
        assert _widget_count(admin, tenant_id) == 0
    finally:
        _teardown(admin, tenant_id)


# --- The public registration API: the process-wide registry ------------------
#
# The tests above isolate themselves with `registry=`. These use the path a
# real product takes -- `saas_os.core.tenancy.register_purge_participant()`
# and a `purge_tenant()` call with no override -- against a fresh process-wide
# registry swapped in for the test (`process_registry`), so nothing leaks into
# any other test.


@pytest.fixture
def process_registry(monkeypatch: pytest.MonkeyPatch) -> TenantPurgeParticipantRegistry:
    fresh = TenantPurgeParticipantRegistry()
    monkeypatch.setattr(participants_module, "_default_registry", fresh)
    return fresh


class _OrderedParticipant(_CountingParticipant):
    def __init__(self, participant_name: str, order: list[str]) -> None:
        super().__init__(participant_name)
        self._order = order

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None:
        self._order.append(self.name)
        super().purge_tenant_data(tenant_id)


def test_publicly_registered_participants_run_in_registration_order_without_an_override(
    admin: sessionmaker[Session], process_registry: TenantPurgeParticipantRegistry
) -> None:
    target_id = _new_active_tenant()
    sibling_id = _new_active_tenant()
    try:
        _seed_widget(target_id)
        _seed_widget(sibling_id)
        order: list[str] = []
        last = _OrderedParticipant("test.zz-registered-second", order)
        widgets = WidgetPurgeParticipant()
        register_purge_participant(widgets)
        register_purge_participant(last)
        register_purge_participant(widgets)  # the same object again: no-op
        assert registered_purge_participant_names() == (
            "reference_consumer.widgets",
            "test.zz-registered-second",
        )

        transition_tenant_status(target_id, TenantStatus.DELETED, caller=platform_operator())
        result = purge_tenant(target_id, caller=PURGE_AUTHORITY)

        assert result.participant_names == (
            "reference_consumer.widgets",
            "test.zz-registered-second",
        )
        assert order == ["test.zz-registered-second"]
        assert last.calls == [target_id]
        assert get_tenant(target_id).status == TenantStatus.PURGED.value
        assert _widget_count(admin, target_id) == 0
        assert _widget_count(admin, sibling_id) == 1  # never another tenant's rows
        (completed,) = _lifecycle_event_metadata(admin, target_id, "tenant.purge_completed")
        assert completed["participants_run"] == 2
    finally:
        _teardown(admin, target_id, sibling_id)


def test_a_later_participant_failure_keeps_purging_and_a_retry_reruns_every_participant(
    admin: sessionmaker[Session], process_registry: TenantPurgeParticipantRegistry
) -> None:
    """Partial failure: the first participant succeeded, the second raised.
    The tenant must stay PURGING with no completion record; the retry runs
    both again (the first must be idempotent) and only then reaches PURGED,
    with exactly one `tenant.purge_completed`; a further call is a no-op."""
    tenant_id = _new_active_tenant()
    try:
        _seed_widget(tenant_id)
        order: list[str] = []
        first = _OrderedParticipant("test.first", order)
        second = _OrderedParticipant("test.second", order)
        second.should_raise = RuntimeError("second participant down")
        register_purge_participant(first)
        register_purge_participant(WidgetPurgeParticipant())
        register_purge_participant(second)

        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
        with pytest.raises(RuntimeError, match="second participant down"):
            purge_tenant(tenant_id, caller=PURGE_AUTHORITY)

        assert order == ["test.first", "test.second"]
        assert get_tenant(tenant_id).status == TenantStatus.PURGING.value
        assert get_tenant(tenant_id).name != f"purged-{tenant_id}"
        assert _widget_count(admin, tenant_id) == 0  # the widget participant had run
        assert _lifecycle_event_metadata(admin, tenant_id, "tenant.purge_completed") == []
        (failed,) = _lifecycle_event_metadata(admin, tenant_id, "tenant.purge_failed")
        assert failed["failure_class"] == "participant_error"
        assert failed["failed_step"] == "participant:test.second"

        second.should_raise = None
        result = purge_tenant(tenant_id, caller=PURGE_AUTHORITY)

        assert order == ["test.first", "test.second", "test.first", "test.second"]
        assert result.participant_names == (
            "test.first",
            "reference_consumer.widgets",
            "test.second",
        )
        assert get_tenant(tenant_id).status == TenantStatus.PURGED.value
        started = _lifecycle_event_metadata(admin, tenant_id, "tenant.purge_started")
        assert [row["resumed"] for row in started] == [False, True]
        assert len(_lifecycle_event_metadata(admin, tenant_id, "tenant.purge_completed")) == 1
        assert len(_lifecycle_event_metadata(admin, tenant_id, "tenant.purge_failed")) == 1

        again = purge_tenant(tenant_id, caller=PURGE_AUTHORITY)
        assert again.already_purged is True
        assert len(order) == 4  # no participant ran against the tombstone
        assert len(_lifecycle_event_metadata(admin, tenant_id, "tenant.purge_started")) == 2
    finally:
        _teardown(admin, tenant_id)


def test_a_participant_registered_in_another_registry_does_not_run(
    admin: sessionmaker[Session], process_registry: TenantPurgeParticipantRegistry
) -> None:
    """The registry is per process: a participant registered somewhere else
    (here, a separate registry standing in for another process's) is not
    part of this process's purge."""
    tenant_id = _new_active_tenant()
    try:
        _seed_widget(tenant_id)
        TenantPurgeParticipantRegistry().register(WidgetPurgeParticipant())
        assert registered_purge_participant_names() == ()

        transition_tenant_status(tenant_id, TenantStatus.DELETED, caller=platform_operator())
        result = purge_tenant(tenant_id, caller=PURGE_AUTHORITY)

        assert result.participant_names == ()
        # Core cannot know a product exists: the product row stays behind.
        # This is why the operator command refuses a --setup that registers
        # nothing (tests/core/platform_authority/test_operator_cli_integration.py).
        assert _widget_count(admin, tenant_id) == 1
    finally:
        _teardown(admin, tenant_id)
