"""PRIV-03 Phase P4 -- tenant lifecycle audit evidence, against a real
PostgreSQL instance: `tenant.delete_requested`, `tenant.purge_started`,
`tenant.purge_completed`, and `tenant.purge_failed` are written through
the existing `core.audit_log` at genuine lifecycle boundaries only, carry
opaque/bounded metadata, survive the purge they describe, cannot be
edited or deleted by the application role, and add no new retention
linkage. Every observation goes through the privileged migrations role so
RLS cannot hide anything; every action under test runs as the ordinary
application role.

Marked `integration`, excluded from the default `pytest` run, mirroring
`tests/core/tenancy/test_tenant_purge_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/tenancy/test_purge_audit_integration.py
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from core.api_keys.service import (
    create_api_key,
    create_service_account_api_key,
    revoke_api_key,
)
from core.billing.provider import FakeBillingProvider
from core.billing.service import create_plan
from core.billing.service import subscribe as billing_subscribe
from core.identity.service import (
    add_tenant_membership,
    create_invitation,
    create_service_account,
    create_user,
)
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    create_support_access_request,
    grant_permission,
    register_permission,
)
from core.usage.models import UsageEvent
from core.webhooks.service import subscribe as webhook_subscribe
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.tenancy import (
    PURGE_STEPS,
    InvalidTenantTransitionError,
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_LIFECYCLE_ACTIONS = frozenset(
    {
        "tenant.delete_requested",
        "tenant.purge_started",
        "tenant.purge_completed",
        "tenant.purge_failed",
    }
)
# The complete, closed set of metadata keys a lifecycle event may carry.
_ALLOWED_METADATA_KEYS = frozenset(
    {
        "from_status",
        "to_status",
        "resumed",
        "passes",
        "deleted_total",
        "retained_service_accounts",
        "retained_delegation_grants",
        "failure_class",
        "failed_step",
        "error_type",
        "passes_completed",
    }
    | {f"deleted_{step}" for step in PURGE_STEPS}
)


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
            conn.execute(text("SELECT 1 FROM core.audit_log LIMIT 1"))
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
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def _uniq(prefix: str) -> str:
    return f"priv03-p4-{prefix}-{uuid.uuid4().hex[:8]}"


@dataclass(frozen=True)
class Row:
    id: uuid.UUID
    action: str
    actor_type: str
    actor_user_id: uuid.UUID | None
    actor_service_account_id: uuid.UUID | None
    delegation_grant_id: uuid.UUID | None
    support_access_id: uuid.UUID | None
    resource_type: str
    resource_id: str | None
    outcome: str
    metadata: dict
    created_at: datetime


def _lifecycle_rows(admin: sessionmaker[Session], tenant_id: uuid.UUID) -> list[Row]:
    """Every lifecycle audit row for `tenant_id`, oldest first -- read
    with the privileged role so RLS cannot hide anything."""
    with session_scope(session_factory=admin) as session:
        rows = session.execute(
            text(
                "SELECT id, action, actor_type, actor_user_id, actor_service_account_id, "
                "delegation_grant_id, support_access_id, resource_type, resource_id, outcome, "
                "metadata, created_at FROM core.audit_log "
                "WHERE tenant_id = :t AND resource_type = 'tenant' "
                "ORDER BY created_at, id"
            ),
            {"t": str(tenant_id)},
        ).all()
    return [
        Row(
            id=r[0],
            action=r[1],
            actor_type=r[2],
            actor_user_id=r[3],
            actor_service_account_id=r[4],
            delegation_grant_id=r[5],
            support_access_id=r[6],
            resource_type=r[7],
            resource_id=r[8],
            outcome=r[9],
            metadata=r[10] or {},
            created_at=r[11],
        )
        for r in rows
    ]


def _actions(rows: list[Row]) -> list[str]:
    return [r.action for r in rows]


def _count(admin: sessionmaker[Session], table: str, tenant_id: uuid.UUID) -> int:
    with session_scope(session_factory=admin) as session:
        return session.execute(
            text(f"SELECT count(*) FROM {table} WHERE tenant_id = :t"),
            {"t": str(tenant_id)},  # noqa: S608 -- fixed table names
        ).scalar_one()


@dataclass
class Rig:
    tenant_id: uuid.UUID
    tenant_name: str
    admin_user_id: uuid.UUID
    support_user_id: uuid.UUID
    invited_email: str
    raw_api_key: str
    webhook_url: str
    audited_service_account_id: uuid.UUID
    plan_key: str


def _build_rig() -> Rig:
    """An ACTIVE tenant whose customer-identifying values (name, invitee
    email, API key, webhook URL) are all known so the tests can prove none
    of them leaks into lifecycle audit metadata; plus one retained row of
    each retained kind and an audit-referenced service account."""
    tenant_name = f"Acme Corp {uuid.uuid4().hex[:8]}"
    tenant = create_tenant(tenant_name)
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    t = tenant.id
    admin_user = create_user()
    support_user = create_user()
    membership = add_tenant_membership(t, admin_user.id)
    role = create_role(t, "admin")
    for resource, action in (("invitation", "create"), ("api_key", "create")):
        grant_permission(t, role.id, register_permission(resource, action).id)
    assign_first_role_for_new_tenant(t, membership.id, role.id)

    invited_email = f"alice-{uuid.uuid4().hex[:8]}@example.com"
    create_invitation(t, admin_user.id, invited_email)
    _, raw_api_key = create_api_key(t, admin_user.id, "user-key")
    webhook_url = f"https://hooks.example.com/{uuid.uuid4().hex}"
    webhook_subscribe(t, webhook_url, actor_user_id=admin_user.id)

    audited_sa = create_service_account(t, "audited-sa")
    sa_key, _ = create_service_account_api_key(
        actor_user_id=admin_user.id, tenant_id=t, service_account_id=audited_sa.id, name="sa-key"
    )
    revoke_api_key(t, sa_key.id)  # SERVICE_ACCOUNT-actor audit row -> SA retained by purge

    with tenant_session_scope(t) as session:
        session.add(
            UsageEvent(
                tenant_id=t,
                metric="api_calls",
                quantity=Decimal("1"),
                occurred_at=datetime.now(UTC),
            )
        )
    plan_key = _uniq("plan").replace("-", "_")
    create_plan(plan_key, "Plan")
    billing_subscribe(t, plan_key, provider=FakeBillingProvider(), actor_user_id=admin_user.id)
    create_support_access_request(
        requester_user_id=support_user.id,
        tenant_id=t,
        reason="forensics",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    return Rig(
        tenant_id=t,
        tenant_name=tenant_name,
        admin_user_id=admin_user.id,
        support_user_id=support_user.id,
        invited_email=invited_email,
        raw_api_key=raw_api_key,
        webhook_url=webhook_url,
        audited_service_account_id=audited_sa.id,
        plan_key=plan_key,
    )


def _teardown(admin: sessionmaker[Session], rigs: list[Rig]) -> None:
    tables = (
        "core.audit_log",
        "core.api_keys",
        "core.notifications",
        "core.webhook_replay_records",
        "core.webhook_subscriptions",
        "core.membership_roles",
        "core.role_permissions",
        "core.service_account_roles",
        "core.deny_grants",
        "core.delegation_grants",
        "core.roles",
        "core.invitations",
        "core.service_accounts",
        "core.tenant_memberships",
        "core.feature_flag_tenant_overrides",
        "core.idempotency_records",
        "core.usage_events",
        "core.billing_subscriptions",
        "core.support_access_requests",
    )
    with session_scope(session_factory=admin) as session:
        for rig in rigs:
            for table in tables:
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :t"), {"t": str(rig.tenant_id)}
                )  # noqa: S608
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)}
            )
            for uid in (rig.admin_user_id, rig.support_user_id):
                session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(uid)})
            session.execute(
                text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": rig.plan_key}
            )


@pytest.fixture
def rig(admin: sessionmaker[Session]) -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(admin, [built])


def _fail_step(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    """Make the `authorization` purge step raise with an attacker-shaped
    message -- the kind of text that must never reach an audit row."""
    import core.rbac.service as rbac_service

    def _boom(tenant_id: uuid.UUID):
        raise RuntimeError(message)

    monkeypatch.setattr(rbac_service, "purge_tenant_authorization", _boom)


# --- 1. delete_requested ------------------------------------------------------


def test_delete_requested_is_emitted_only_on_the_deleted_transition(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.SUSPENDED, actor_user_id=rig.admin_user_id)
    assert _lifecycle_rows(admin, rig.tenant_id) == []  # not a deletion boundary
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED, actor_user_id=rig.admin_user_id)
    rows = _lifecycle_rows(admin, rig.tenant_id)
    assert _actions(rows) == ["tenant.delete_requested"]
    (row,) = rows
    assert row.actor_type == ActorType.USER.value
    assert row.actor_user_id == rig.admin_user_id
    assert row.outcome == AuditOutcome.SUCCESS.value
    assert row.resource_id == str(rig.tenant_id)
    assert row.metadata == {"from_status": "suspended", "to_status": "deleted"}


def test_actorless_lifecycle_events_use_the_existing_system_actor(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    (row,) = _lifecycle_rows(admin, rig.tenant_id)
    assert row.actor_type == ActorType.SYSTEM.value
    assert row.actor_user_id is None and row.actor_service_account_id is None


# --- 2/3. purge_started / purge_completed at genuine transitions ---------------


def test_purge_started_and_completed_only_at_genuine_transitions(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED, actor_user_id=rig.admin_user_id)
    # Moving into PURGING by hand is a lifecycle transition, not a purge:
    # no purge_started is manufactured for it.
    transition_tenant_status(rig.tenant_id, TenantStatus.PURGING)
    assert _actions(_lifecycle_rows(admin, rig.tenant_id)) == ["tenant.delete_requested"]

    result = purge_tenant(rig.tenant_id, actor_user_id=rig.admin_user_id)
    rows = _lifecycle_rows(admin, rig.tenant_id)
    assert _actions(rows) == [
        "tenant.delete_requested",
        "tenant.purge_started",
        "tenant.purge_completed",
    ]
    started, completed = rows[1], rows[2]
    assert started.metadata == {"from_status": "purging", "to_status": "purging", "resumed": True}
    assert completed.metadata["from_status"] == "purging"
    assert completed.metadata["to_status"] == "purged"
    assert completed.metadata["passes"] == result.passes
    assert {s: completed.metadata[f"deleted_{s}"] for s in PURGE_STEPS} == result.deleted
    assert completed.metadata["deleted_total"] == result.total_deleted
    assert completed.metadata["retained_service_accounts"] == 1
    assert started.created_at <= completed.created_at
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGED.value
    assert all(r.actor_user_id == rig.admin_user_id for r in rows)


def test_open_tenant_purge_attempt_writes_no_lifecycle_evidence(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    with pytest.raises(InvalidTenantTransitionError):
        purge_tenant(rig.tenant_id)
    assert _lifecycle_rows(admin, rig.tenant_id) == []


def test_already_purged_tenant_records_nothing_more(rig: Rig, admin: sessionmaker[Session]) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    purge_tenant(rig.tenant_id)
    before = _lifecycle_rows(admin, rig.tenant_id)
    assert purge_tenant(rig.tenant_id).already_purged is True
    assert _lifecycle_rows(admin, rig.tenant_id) == before


# --- 4/5/6/21. failure, no false completion, retry chronology -----------------


def test_failed_purge_records_purge_failed_and_never_completed(
    rig: Rig, admin: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    _fail_step(monkeypatch, "boom")
    with pytest.raises(RuntimeError):
        purge_tenant(rig.tenant_id)
    rows = _lifecycle_rows(admin, rig.tenant_id)
    assert _actions(rows) == [
        "tenant.delete_requested",
        "tenant.purge_started",
        "tenant.purge_failed",
    ]
    failed = rows[-1]
    assert failed.outcome == AuditOutcome.FAILURE.value
    assert failed.metadata == {
        "failure_class": "step_error",
        "failed_step": "authorization",
        "error_type": "RuntimeError",
        "passes_completed": 0,
    }
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGING.value


def test_retry_after_failure_appends_coherent_history_without_rewriting_it(
    rig: Rig, admin: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    _fail_step(monkeypatch, "first attempt fails")
    with pytest.raises(RuntimeError):
        purge_tenant(rig.tenant_id)
    first_attempt = _lifecycle_rows(admin, rig.tenant_id)

    monkeypatch.undo()
    purge_tenant(rig.tenant_id)
    history = _lifecycle_rows(admin, rig.tenant_id)
    assert _actions(history) == [
        "tenant.delete_requested",
        "tenant.purge_started",
        "tenant.purge_failed",
        "tenant.purge_started",
        "tenant.purge_completed",
    ]
    # The earlier rows are byte-for-byte the ones written before the retry.
    assert history[: len(first_attempt)] == first_attempt
    assert history[3].metadata["resumed"] is True
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGED.value


# --- 7-12. privacy of lifecycle metadata --------------------------------------


def test_lifecycle_metadata_is_opaque_bounded_and_free_of_pii_and_secrets(
    rig: Rig, admin: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail once with an attacker-shaped message that embeds every
    sensitive value the tenant holds, then complete; no lifecycle row may
    contain any of them, and metadata must stay within the closed key set."""
    poison = (
        f"SECRET-{rig.raw_api_key} name={rig.tenant_name} email={rig.invited_email} "
        f"url={rig.webhook_url} " + "A" * 20000
    )
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED, actor_user_id=rig.admin_user_id)
    _fail_step(monkeypatch, poison)
    with pytest.raises(RuntimeError):
        purge_tenant(rig.tenant_id, actor_user_id=rig.admin_user_id)
    monkeypatch.undo()
    purge_tenant(rig.tenant_id, actor_user_id=rig.admin_user_id)

    rows = _lifecycle_rows(admin, rig.tenant_id)
    assert len(rows) == 5
    key_hash = hashlib.sha256(rig.raw_api_key.encode()).hexdigest()
    forbidden = (
        rig.tenant_name,
        rig.invited_email,
        rig.raw_api_key,
        key_hash,
        rig.webhook_url,
        "SECRET-",
        "AAAAAAAA",
        "boom",
    )
    for row in rows:
        serialized = json.dumps(row.metadata, sort_keys=True) + (row.resource_id or "")
        for value in forbidden:
            assert value not in serialized, (row.action, value)
        assert set(row.metadata) <= _ALLOWED_METADATA_KEYS, row.metadata
        assert len(serialized) < 2048
        assert row.resource_id == str(rig.tenant_id)
        assert row.resource_type == "tenant"
        assert row.action in _LIFECYCLE_ACTIONS
    failed = next(r for r in rows if r.action == "tenant.purge_failed")
    assert failed.metadata["error_type"] == "RuntimeError"  # class name only, never the message


# --- 13/14. immutability under the application role ----------------------------


def test_lifecycle_audit_rows_cannot_be_updated_or_deleted_by_the_application_role(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    (row,) = _lifecycle_rows(admin, rig.tenant_id)
    with pytest.raises(ProgrammingError):  # InsufficientPrivilege
        with tenant_session_scope(rig.tenant_id) as session:
            session.execute(
                text("UPDATE core.audit_log SET action = 'tenant.purge_completed' WHERE id = :id"),
                {"id": str(row.id)},
            )
    with pytest.raises(ProgrammingError):
        with tenant_session_scope(rig.tenant_id) as session:
            session.execute(text("DELETE FROM core.audit_log WHERE id = :id"), {"id": str(row.id)})
    assert _lifecycle_rows(admin, rig.tenant_id) == [row]


# --- 15. retained references: no new linkage, existing linkage still binds ----


def test_lifecycle_events_add_no_retention_linkage_and_existing_linkage_still_binds(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    result = purge_tenant(rig.tenant_id)
    for row in _lifecycle_rows(admin, rig.tenant_id):
        assert row.delegation_grant_id is None
        assert row.support_access_id is None
        assert row.actor_service_account_id is None
    # The SA the earlier SERVICE_ACCOUNT-actor audit row names was retained
    # (disabled) and still cannot be deleted -- the audit FK binds.
    assert result.retained_service_account_ids == {rig.audited_service_account_id}
    with pytest.raises(IntegrityError):
        with tenant_session_scope(rig.tenant_id) as session:
            session.execute(
                text("DELETE FROM core.service_accounts WHERE id = :s"),
                {"s": str(rig.audited_service_account_id)},
            )


# --- 16-20/23. evidence and retained data survive; tombstone unchanged --------


def test_evidence_and_retained_data_survive_the_purge_they_describe(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    t = rig.tenant_id
    before = {
        table: _count(admin, table, t)
        for table in (
            "core.support_access_requests",
            "core.billing_subscriptions",
            "core.usage_events",
        )
    }
    audit_before = _count(admin, "core.audit_log", t)
    transition_tenant_status(t, TenantStatus.DELETED)
    purge_tenant(t)
    after = {table: _count(admin, table, t) for table in before}
    assert after == before
    assert (
        _count(admin, "core.audit_log", t) == audit_before + 3
    )  # delete_requested, started, completed
    assert _actions(_lifecycle_rows(admin, t))[-1] == "tenant.purge_completed"
    with session_scope(session_factory=admin) as session:
        for uid in (rig.admin_user_id, rig.support_user_id):
            assert (
                session.execute(
                    text("SELECT count(*) FROM core.users WHERE id = :u"), {"u": str(uid)}
                ).scalar_one()
                == 1
            )
    tombstone = get_tenant(t)
    assert tombstone.status == TenantStatus.PURGED.value
    assert tombstone.name == f"purged-{t}"


# --- 22. concurrency: exactly one completion event ------------------------------


def test_concurrent_purges_record_exactly_one_completion(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    errors: list[BaseException] = []

    def _run() -> None:
        try:
            purge_tenant(rig.tenant_id)
        except BaseException as exc:  # noqa: BLE001 -- asserted below
            errors.append(exc)

    threads = [threading.Thread(target=_run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == [], errors
    actions = _actions(_lifecycle_rows(admin, rig.tenant_id))
    assert actions.count("tenant.purge_completed") == 1
    assert actions.count("tenant.purge_failed") == 0
    assert 1 <= actions.count("tenant.purge_started") <= 2
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGED.value


# --- Security: evidence cannot be manufactured through the lifecycle API -----


def test_a_forged_completion_row_does_not_move_the_lifecycle_and_is_distinguishable(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    """Core services trust their callers by design, so any in-process
    caller can write an audit row with any action string through
    `record()`. What P4 guarantees is that lifecycle *state* is never
    derived from audit rows and genuine evidence is only ever written after
    the transition it describes committed -- so a forged 'completed' row
    for an ACTIVE tenant leaves it ACTIVE, and the mismatch is visible."""
    record_audit_event(
        tenant_id=rig.tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=rig.admin_user_id,
        action="tenant.purge_completed",
        resource_type="tenant",
        resource_id=str(rig.tenant_id),
        outcome=AuditOutcome.SUCCESS,
    )
    assert get_tenant(rig.tenant_id).status == TenantStatus.ACTIVE.value
    # The lifecycle API still refuses to purge an open tenant and writes no
    # evidence of its own.
    with pytest.raises(InvalidTenantTransitionError):
        purge_tenant(rig.tenant_id)
    assert _actions(_lifecycle_rows(admin, rig.tenant_id)) == ["tenant.purge_completed"]


def test_no_privileged_bypass_is_involved(admin: sessionmaker[Session]) -> None:
    from sqlalchemy.engine import make_url

    app_role_name = make_url(get_database_config().url).username
    with session_scope(session_factory=admin) as session:
        secdef = session.execute(
            text("SELECT count(*) FROM pg_proc WHERE prosecdef = true")
        ).scalar_one()
        app_role = session.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = :r"),
            {"r": app_role_name},
        ).one()
        audit_grants = session.execute(
            text(
                "SELECT string_agg(privilege_type, ',' ORDER BY privilege_type) "
                "FROM information_schema.role_table_grants "
                "WHERE grantee = :r AND table_schema = 'core' AND table_name = 'audit_log'"
            ),
            {"r": app_role_name},
        ).scalar_one()
    assert secdef == 0
    assert (app_role[0], app_role[1]) == (False, False)
    assert audit_grants == "INSERT,SELECT"
