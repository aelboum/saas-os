"""RA-12-3 -- individual identity erasure (`saas_os.core.identity.erasure`),
against a real PostgreSQL instance.

Proves the erasure contract end to end: an external identity and a
session actually stop being usable afterward, a user's own membership
(and only what exists solely because of it) is removed from each given
tenant while a sibling member's own data is untouched, the operation is
idempotent and safe under concurrency, erasing a nonexistent identity is
indistinguishable from erasing an already-erased one, an unattributable
call fails closed, and every retained record (`saas_os.core.audit_log`, the
user's own `core.users` tombstone row, another tenant's roles) survives
exactly as the architecture already requires.

Marked `integration`, excluded from the default `pytest` run, mirroring
`tests/core/tenancy/test_tenant_purge_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/identity/test_erasure_integration.py
"""

from __future__ import annotations

import dataclasses
import threading
import uuid
from collections.abc import Iterator
from decimal import Decimal

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

import saas_os.core.rbac  # noqa: F401 -- registers support_access_requests/delegation_grants for audit_log's FKs
from lifecycle_callers import PROVISIONING
from saas_os.core.api_keys.service import create_api_key, validate_api_key
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity.erasure import erase_user_identity
from saas_os.core.identity.errors import (
    SessionNotFoundError,
    UserNotFoundError,
)
from saas_os.core.identity.service import (
    add_tenant_membership,
    create_user,
    find_external_identity,
    get_membership,
    get_or_create_user_for_external_identity,
    link_external_identity,
)
from saas_os.core.identity.sessions import issue_session, validate_session
from saas_os.core.notifications.service import dispatch_notification
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import create_tenant
from saas_os.core.usage.service import ingest_event
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope


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


_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

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
            conn.execute(text("SELECT 1 FROM core.users LIMIT 1"))
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
    return f"ra12-p3-{prefix}-{uuid.uuid4().hex[:8]}"


def _issuer_subject() -> tuple[str, str]:
    return "https://issuer.example.test", f"subject-{uuid.uuid4().hex}"


def _teardown(
    admin: sessionmaker[Session], tenant_ids: list[uuid.UUID], user_ids: list[uuid.UUID]
) -> None:
    with session_scope(session_factory=admin) as session:
        for tenant_id in tenant_ids:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
        for tenant_id in tenant_ids:
            session.execute(
                text("DELETE FROM core.notifications WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.outbox_events WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.membership_roles WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.role_permissions WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})
        for user_id in user_ids:
            session.execute(
                text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(user_id)}
            )
            session.execute(
                text("DELETE FROM core.external_identities WHERE user_id = :u"), {"u": str(user_id)}
            )
            _admin_clear_audit_references({"u": str(user_id)}, table="users")
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(user_id)})


def _seed_notification(tenant_id: uuid.UUID, recipient_user_id: uuid.UUID) -> None:
    """A minimal `core.notifications` row addressed to `recipient_user_id`
    -- proves `purge_user_notifications_in_tenant()`'s own composite-FK
    ordering (`(tenant_id, recipient_user_id)` onto `tenant_memberships`)
    without needing the full email-dispatch machinery."""
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text(
                "INSERT INTO core.notifications "
                "(id, tenant_id, recipient_user_id, channel, subject, body, status) "
                "VALUES (:id, :tid, :uid, 'in_app', 'test', 'test body', 'sent')"
            ),
            {"id": str(uuid.uuid4()), "tid": str(tenant_id), "uid": str(recipient_user_id)},
        )


def _member_with_capability(tenant_id: uuid.UUID, resource: str, action: str) -> uuid.UUID:
    user = create_user()
    membership = add_tenant_membership(tenant_id, user.id, caller=_PROVISIONING)
    role = create_role(tenant_id, _uniq("role"), caller=_PROVISIONING)
    permission = register_permission(resource, action)
    grant_permission(tenant_id, role.id, permission.id, caller=_PROVISIONING)
    assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=_PROVISIONING)
    return user.id


# --- Basic erasure ------------------------------------------------------------


def test_basic_erasure_removes_external_identity_session_and_membership(
    admin: sessionmaker[Session],
) -> None:
    actor = create_user()
    tenant = create_tenant(_uniq("tenant"), caller=PROVISIONING)
    user = create_user()
    issuer, subject = _issuer_subject()
    link_external_identity(user.id, issuer, subject)
    add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
    _, raw_token = issue_session(user.id)

    try:
        result = erase_user_identity(user.id, [tenant.id], actor_user_id=actor.id)

        assert result.external_identities_deleted == 1
        assert result.sessions_deleted == 1
        assert result.tenants_with_membership_removed == (tenant.id,)
        assert find_external_identity(issuer, subject) is None
        assert get_membership(tenant.id, user.id) is None
        with pytest.raises(SessionNotFoundError):
            validate_session(raw_token)
    finally:
        _teardown(admin, [tenant.id], [actor.id, user.id])


# --- Multi-tenant safety -------------------------------------------------------


def test_multi_tenant_membership_is_removed_without_touching_other_tenant_data(
    admin: sessionmaker[Session],
) -> None:
    actor = create_user()
    tenant_a = create_tenant(_uniq("tenant-a"), caller=PROVISIONING)
    tenant_b = create_tenant(_uniq("tenant-b"), caller=PROVISIONING)
    user = create_user()
    add_tenant_membership(tenant_a.id, user.id, caller=_PROVISIONING)
    add_tenant_membership(tenant_b.id, user.id, caller=_PROVISIONING)
    create_api_key(tenant_a.id, _uniq("key-a"), caller=UserCaller(user.id))
    create_api_key(tenant_b.id, _uniq("key-b"), caller=UserCaller(user.id))
    _seed_notification(tenant_a.id, user.id)

    # A sibling member of tenant A, whose own data must survive untouched.
    sibling = create_user()
    add_tenant_membership(tenant_a.id, sibling.id, caller=_PROVISIONING)
    sibling_key, sibling_raw = create_api_key(
        tenant_a.id, _uniq("sibling-key"), caller=UserCaller(sibling.id)
    )

    try:
        result = erase_user_identity(user.id, [tenant_a.id, tenant_b.id], actor_user_id=actor.id)

        assert set(result.tenants_with_membership_removed) == {tenant_a.id, tenant_b.id}
        assert result.api_keys_deleted == 2
        assert result.notifications_deleted == 1
        assert get_membership(tenant_a.id, user.id) is None
        assert get_membership(tenant_b.id, user.id) is None

        # The sibling's own membership and API key are completely untouched.
        assert get_membership(tenant_a.id, sibling.id) is not None
        validated = validate_api_key(sibling_raw)
        assert validated.id == sibling_key.id
    finally:
        _teardown(admin, [tenant_a.id, tenant_b.id], [actor.id, user.id, sibling.id])


def test_erasure_removes_the_users_undispatched_notification_events_only(
    admin: sessionmaker[Session],
) -> None:
    """RE-1: an undispatched `notification.dispatch` outbox event carries the
    user's notification content and (encrypted) address -- erasure deletes
    it, and leaves every other event (another recipient's, other types)."""
    actor = create_user()
    tenant = create_tenant(_uniq("tenant"), caller=PROVISIONING)
    user, other = create_user(), create_user()
    add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
    add_tenant_membership(tenant.id, other.id, caller=_PROVISIONING)
    with tenant_session_scope(tenant.id) as session:
        dispatch_notification(
            session, tenant.id, user.id, "email", "b", recipient_email="erased@example.com"
        )
        dispatch_notification(session, tenant.id, user.id, "in_app", "b")
        dispatch_notification(session, tenant.id, other.id, "in_app", "b")
        ingest_event(session, tenant.id, "api_calls", Decimal("1"))

    try:
        result = erase_user_identity(user.id, [tenant.id], actor_user_id=actor.id)

        assert result.notification_events_deleted == 2
        with tenant_session_scope(tenant.id) as session:
            remaining = session.execute(
                text(
                    "SELECT event_type, aggregate_id FROM core.outbox_events "
                    "WHERE tenant_id = :t ORDER BY event_type"
                ),
                {"t": str(tenant.id)},
            ).all()
        assert [tuple(r) for r in remaining] == [
            ("notification.dispatch", str(other.id)),
            ("usage.ingestion", "api_calls"),
        ]
    finally:
        _teardown(admin, [tenant.id], [actor.id, user.id, other.id])


# --- External identity ---------------------------------------------------------


def test_erased_external_identity_cannot_resurrect_the_old_user(
    admin: sessionmaker[Session],
) -> None:
    actor = create_user()
    user = create_user()
    issuer, subject = _issuer_subject()
    link_external_identity(user.id, issuer, subject)

    try:
        erase_user_identity(user.id, [], actor_user_id=actor.id)
        assert find_external_identity(issuer, subject) is None

        # A fresh login with the exact same (issuer, subject) provisions a
        # brand-new, unrelated user -- never the erased one.
        resolved = get_or_create_user_for_external_identity(issuer, subject)
        assert resolved.id != user.id

        with session_scope(session_factory=admin) as session:
            session.execute(
                text("DELETE FROM core.external_identities WHERE user_id = :u"),
                {"u": str(resolved.id)},
            )
            _admin_clear_audit_references({"u": str(resolved.id)}, table="users")
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(resolved.id)})
    finally:
        _teardown(admin, [], [actor.id, user.id])


# --- Sessions --------------------------------------------------------------------


def test_erased_sessions_cannot_authenticate_and_a_fresh_session_is_independent(
    admin: sessionmaker[Session],
) -> None:
    actor = create_user()
    user = create_user()
    _, raw_token = issue_session(user.id)

    try:
        erase_user_identity(user.id, [], actor_user_id=actor.id)
        with pytest.raises(SessionNotFoundError):
            validate_session(raw_token)

        # Issuing a fresh session for the same (still-existing, tombstoned)
        # user_id afterward is a distinct, independent operation this
        # module does not forbid -- but it is a NEW session, not the erased one.
        _, new_raw_token = issue_session(user.id)
        assert new_raw_token != raw_token
        new_session = validate_session(new_raw_token)
        assert new_session.user_id == user.id
        with session_scope(session_factory=admin) as session:
            session.execute(
                text("DELETE FROM core.sessions WHERE id = :i"), {"i": str(new_session.id)}
            )
    finally:
        _teardown(admin, [], [actor.id, user.id])


# --- Authorization / attribution -------------------------------------------------


def test_unattributable_erasure_is_rejected_and_nothing_is_deleted() -> None:
    fake_actor_id = uuid.uuid4()
    user = create_user()
    issuer, subject = _issuer_subject()
    link_external_identity(user.id, issuer, subject)

    try:
        with pytest.raises(UserNotFoundError):
            erase_user_identity(user.id, [], actor_user_id=fake_actor_id)
        # Fails closed *before* any deletion: the identity survives.
        assert find_external_identity(issuer, subject) is not None
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.external_identities WHERE user_id = :u"),
                {"u": str(user.id)},
            )
            _admin_clear_audit_references({"u": str(user.id)}, table="users")
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(user.id)})


# --- Unknown identity / non-enumeration ------------------------------------------


def test_erasing_a_nonexistent_identity_matches_an_already_erased_one(
    admin: sessionmaker[Session],
) -> None:
    actor = create_user()
    tenant = create_tenant(_uniq("tenant"), caller=PROVISIONING)
    real_user = create_user()

    try:
        nonexistent_result = erase_user_identity(uuid.uuid4(), [tenant.id], actor_user_id=actor.id)
        first_pass = erase_user_identity(real_user.id, [tenant.id], actor_user_id=actor.id)
        second_pass = erase_user_identity(real_user.id, [tenant.id], actor_user_id=actor.id)

        # A never-existing id and an id that was never a member of `tenant`
        # produce the identical, all-zero shape -- no distinguishing signal.
        assert nonexistent_result.external_identities_deleted == 0
        assert nonexistent_result.sessions_deleted == 0
        assert nonexistent_result.tenants_with_membership_removed == ()
        assert second_pass.external_identities_deleted == 0
        assert second_pass.sessions_deleted == 0
        assert second_pass.tenants_with_membership_removed == ()
        # Identical in every way except the (opaque, non-enumerating) id
        # itself -- the shape a caller actually observes is the same.
        assert dataclasses.replace(
            nonexistent_result, user_id=uuid.UUID(int=0)
        ) == dataclasses.replace(second_pass, user_id=uuid.UUID(int=0))
        assert (
            first_pass.tenants_with_membership_removed == ()
        )  # real_user was never a member either
    finally:
        _teardown(admin, [tenant.id], [actor.id, real_user.id])


# --- Idempotency -----------------------------------------------------------------


def test_erasure_is_idempotent(admin: sessionmaker[Session]) -> None:
    actor = create_user()
    tenant = create_tenant(_uniq("tenant"), caller=PROVISIONING)
    user = create_user()
    issuer, subject = _issuer_subject()
    link_external_identity(user.id, issuer, subject)
    add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
    issue_session(user.id)

    try:
        first = erase_user_identity(user.id, [tenant.id], actor_user_id=actor.id)
        second = erase_user_identity(user.id, [tenant.id], actor_user_id=actor.id)

        assert first.external_identities_deleted == 1
        assert first.sessions_deleted == 1
        assert first.tenants_with_membership_removed == (tenant.id,)
        assert second.external_identities_deleted == 0
        assert second.sessions_deleted == 0
        assert second.tenants_with_membership_removed == ()
    finally:
        _teardown(admin, [tenant.id], [actor.id, user.id])


# --- Concurrency -----------------------------------------------------------------


def test_concurrent_erasure_attempts_are_safe(admin: sessionmaker[Session]) -> None:
    actor = create_user()
    tenant = create_tenant(_uniq("tenant"), caller=PROVISIONING)
    user = create_user()
    issuer, subject = _issuer_subject()
    link_external_identity(user.id, issuer, subject)
    add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
    issue_session(user.id)

    errors: list[BaseException] = []
    results: list[object] = []

    def _run() -> None:
        try:
            results.append(erase_user_identity(user.id, [tenant.id], actor_user_id=actor.id))
        except BaseException as exc:  # noqa: BLE001 -- collected and asserted below
            errors.append(exc)

    try:
        threads = [threading.Thread(target=_run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == [], errors
        assert len(results) == 2
        assert find_external_identity(issuer, subject) is None
        assert get_membership(tenant.id, user.id) is None
        # Exactly one of the two calls actually removed the membership;
        # the other found it already gone -- never both, never neither.
        removed_counts = [len(r.tenants_with_membership_removed) for r in results]  # type: ignore[attr-defined]
        assert sorted(removed_counts) == [0, 1]
    finally:
        _teardown(admin, [tenant.id], [actor.id, user.id])


# --- Retained records --------------------------------------------------------------


def test_audit_log_and_the_user_tombstone_row_survive_and_carry_no_pii(
    admin: sessionmaker[Session],
) -> None:
    actor = create_user()
    tenant = create_tenant(_uniq("tenant"), caller=PROVISIONING)
    user = create_user()
    add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)

    try:
        erase_user_identity(user.id, [tenant.id], actor_user_id=actor.id)

        # core.users itself is never deleted -- the retained, PII-free anchor
        # every FK to it (invitations, support_access_requests, audit_log,
        # ...) relies on.
        with session_scope(session_factory=admin) as session:
            still_exists = session.execute(
                text("SELECT 1 FROM core.users WHERE id = :u"), {"u": str(user.id)}
            ).first()
        assert still_exists is not None

        with session_scope(session_factory=admin) as session:
            rows = session.execute(
                text(
                    "SELECT metadata FROM core.audit_log WHERE tenant_id = :t "
                    "AND action = 'identity.erasure_membership_removed'"
                ),
                {"t": str(tenant.id)},
            ).all()
        assert len(rows) == 1
        metadata = rows[0][0]
        assert set(metadata) == {
            "api_keys_deleted",
            "notifications_deleted",
            "membership_roles_deleted",
            "notification_events_deleted",
        }
        assert all(isinstance(v, int) for v in metadata.values())
    finally:
        _teardown(admin, [tenant.id], [actor.id, user.id])


def test_tenant_owned_role_and_other_members_survive(admin: sessionmaker[Session]) -> None:
    actor = create_user()
    tenant = create_tenant(_uniq("tenant"), caller=PROVISIONING)
    user = create_user()
    membership = add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
    role = create_role(tenant.id, _uniq("shared-role"), caller=_PROVISIONING)
    permission = register_permission(*(_uniq("resource"), "read"))
    grant_permission(tenant.id, role.id, permission.id, caller=_PROVISIONING)
    assign_first_role_for_new_tenant(tenant.id, membership.id, role.id, caller=_PROVISIONING)

    other_member_id = _member_with_capability(tenant.id, *(_uniq("resource2"), "read"))

    try:
        erase_user_identity(user.id, [tenant.id], actor_user_id=actor.id)

        # The role itself (tenant-owned configuration) survives -- only the
        # erased user's own assignment to it is gone.
        with session_scope(session_factory=admin) as session:
            role_row = session.execute(
                text("SELECT 1 FROM core.roles WHERE id = :r"), {"r": str(role.id)}
            ).first()
        assert role_row is not None
        assert get_membership(tenant.id, other_member_id) is not None
    finally:
        _teardown(admin, [tenant.id], [actor.id, user.id, other_member_id])
