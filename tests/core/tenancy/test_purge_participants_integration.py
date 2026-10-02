"""RA-12-2 -- the Product-owned tenant purge participant contract
(`core.tenancy.purge_participants`), against a real PostgreSQL instance.

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
(`core.tenancy.purge_participants` module docstring: "so a test can
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

import core.identity.models  # noqa: F401 -- registers core.users, which core.audit_log FKs onto
import pytest
from core.tenancy.errors import InvalidTenantTransitionError
from core.tenancy.purge_participants import TenantPurgeParticipantRegistry
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

import core.rbac  # noqa: F401 -- registers support_access_requests/delegation_grants for audit_log's FKs
from core.tenancy import (
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)

_REFERENCE_CONSUMER_ROOT = Path(__file__).resolve().parents[3] / "examples" / "reference-consumer"
if str(_REFERENCE_CONSUMER_ROOT) not in sys.path:
    sys.path.insert(0, str(_REFERENCE_CONSUMER_ROOT))

from reference_consumer.models import Widget  # noqa: E402
from reference_consumer.purge import WidgetPurgeParticipant  # noqa: E402


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from infra.db.config import get_migrations_database_config
    from infra.db.engine import build_engine
    from infra.db.session import build_session_factory, session_scope
    from sqlalchemy import text

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
    tenant = create_tenant(_uniq("tenant"))
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
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
        transition_tenant_status(tenant_id, TenantStatus.DELETED)
        result = purge_tenant(tenant_id, registry=TenantPurgeParticipantRegistry())
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

        transition_tenant_status(target_id, TenantStatus.DELETED)
        result = purge_tenant(target_id, registry=registry)

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
        transition_tenant_status(tenant_id, TenantStatus.DELETED)
        first = purge_tenant(tenant_id, registry=registry)
        second = purge_tenant(tenant_id, registry=registry)  # already PURGED
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

        transition_tenant_status(tenant_id, TenantStatus.DELETED)
        with pytest.raises(RuntimeError, match=forbidden_detail):
            purge_tenant(tenant_id, registry=registry)

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


def test_retry_after_participant_fix_reaches_purged(admin: sessionmaker[Session]) -> None:
    tenant_id = _new_active_tenant()
    try:
        _seed_widget(tenant_id)
        failing = _CountingParticipant("reference_consumer.widgets")
        failing.should_raise = RuntimeError("transient failure")
        failing_registry = TenantPurgeParticipantRegistry()
        failing_registry.register(failing)

        transition_tenant_status(tenant_id, TenantStatus.DELETED)
        with pytest.raises(RuntimeError, match="transient failure"):
            purge_tenant(tenant_id, registry=failing_registry)
        assert get_tenant(tenant_id).status == TenantStatus.PURGING.value
        assert _widget_count(admin, tenant_id) == 1  # untouched by the failed attempt

        working_registry = TenantPurgeParticipantRegistry()
        working_registry.register(WidgetPurgeParticipant())
        result = purge_tenant(tenant_id, registry=working_registry)

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
            transition_tenant_status(tenant_id, TenantStatus.SUSPENDED)
        fake = _CountingParticipant()
        registry = TenantPurgeParticipantRegistry()
        registry.register(fake)

        with pytest.raises(InvalidTenantTransitionError):
            purge_tenant(tenant_id, registry=registry)

        assert fake.calls == []
        assert get_tenant(tenant_id).status == status.value
    finally:
        _teardown(admin, tenant_id)


def test_participant_is_not_invoked_for_an_already_purged_tenant(
    admin: sessionmaker[Session],
) -> None:
    tenant_id = _new_active_tenant()
    try:
        transition_tenant_status(tenant_id, TenantStatus.DELETED)
        purge_tenant(tenant_id, registry=TenantPurgeParticipantRegistry())
        assert get_tenant(tenant_id).status == TenantStatus.PURGED.value

        fake = _CountingParticipant()
        registry = TenantPurgeParticipantRegistry()
        registry.register(fake)
        result = purge_tenant(tenant_id, registry=registry)

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

        transition_tenant_status(target_id, TenantStatus.DELETED)
        purge_tenant(target_id, registry=registry)

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
        transition_tenant_status(tenant_id, TenantStatus.DELETED)

        errors: list[BaseException] = []
        results: list[object] = []

        def _run() -> None:
            try:
                results.append(purge_tenant(tenant_id, registry=registry))
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
