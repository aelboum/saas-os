"""PRIV-03 Phase P13 -- the tenant lifecycle fence inside invitation
acceptance (privacy re-audit finding RA-09, finding 1), against real
PostgreSQL.

`accept_invitation()`'s untenanted token lookup is dormant by design
(PRIV-01, migration `cb7120cfa806`: `core.invitations` is under FORCE RLS,
so that lookup returns nothing and every acceptance fails closed). These
tests therefore do NOT claim end-to-end acceptance. They exercise the
*transactional phase* the function delegates to --
`core.identity.service._consume_locked_invitation()` -- exactly the way
`accept_invitation()` calls it: inside a real
`infra.db.tenant_session_scope(tenant_id)` transaction, with the invitation
id and token hash a future ingress would already have resolved. RLS is
neither bypassed nor weakened (the runtime role, the tenant-scoped
session and the locked invitation row are all real); only the dormant
tenant-resolution step is supplied by the test.

What is proven: a SUSPENDED, DELETED, PURGING or PURGED tenant's invitation
is rejected with the generic `InvitationInvalidError` (never a lifecycle
error) and no membership is written; PENDING/ACTIVE tenants still accept;
a closure racing an in-flight acceptance blocks on the acceptance's share
lock instead of landing between the fence and the membership write; and
the public `accept_invitation()` itself still fails closed for a valid
token today.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/identity/test_invitation_lifecycle_guard_integration.py
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

import core.identity.service as identity_service
import pytest
from core.identity.errors import InvitationInvalidError
from core.identity.service import (
    accept_invitation,
    add_tenant_membership,
    create_invitation,
    create_user,
    get_membership,
)
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

import core.rbac  # noqa: F401 -- registers the mappers core.audit_log references by name
from core.tenancy import (
    Tenant,
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_INACCESSIBLE = [
    TenantStatus.SUSPENDED,
    TenantStatus.DELETED,
    TenantStatus.PURGING,
    TenantStatus.PURGED,
]


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.invitations LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.invitations not reachable: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


@dataclass
class Rig:
    tenant_id: uuid.UUID
    inviter_id: uuid.UUID
    invitee_id: uuid.UUID
    invitation_id: uuid.UUID
    token_hash: str
    raw_token: str


def _build_rig(status: TenantStatus = TenantStatus.ACTIVE) -> Rig:
    tenant = create_tenant(f"priv03-p13-{uuid.uuid4().hex[:8]}")
    if status is TenantStatus.ACTIVE:
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    inviter, invitee = create_user(), create_user()
    membership = add_tenant_membership(tenant.id, inviter.id)
    role = create_role(tenant.id, "inviter")
    grant_permission(tenant.id, role.id, register_permission("invitation", "create").id)
    assign_first_role_for_new_tenant(tenant.id, membership.id, role.id)
    invitation, raw_token = create_invitation(tenant.id, inviter.id, "invitee@example.com")
    return Rig(
        tenant_id=tenant.id,
        inviter_id=inviter.id,
        invitee_id=invitee.id,
        invitation_id=invitation.id,
        token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        raw_token=raw_token,
    )


def _teardown(admin: sessionmaker[Session], rig: Rig) -> None:
    with session_scope(session_factory=admin) as session:
        for table in (
            "core.audit_log",
            "core.invitations",
            "core.membership_roles",
            "core.role_permissions",
            "core.roles",
            "core.tenant_memberships",
            "core.tenant_ancestry",
        ):
            session.execute(
                text(f"DELETE FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
                {"t": str(rig.tenant_id)},
            )
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)})
        for user_id in (rig.inviter_id, rig.invitee_id):
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(user_id)})


@pytest.fixture
def rig(admin: sessionmaker[Session]) -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(admin, built)


def _close(tenant_id: uuid.UUID, status: TenantStatus) -> None:
    if status is TenantStatus.SUSPENDED:
        transition_tenant_status(tenant_id, TenantStatus.SUSPENDED)
        return
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    if status is TenantStatus.PURGING:
        transition_tenant_status(tenant_id, TenantStatus.PURGING)
    elif status is TenantStatus.PURGED:
        purge_tenant(tenant_id)


def _consume(rig: Rig):
    """Exactly what `accept_invitation()` does once the token has been
    resolved to `(tenant_id, invitation_id)`: the locked phase inside a
    real tenant-scoped transaction."""
    with tenant_session_scope(rig.tenant_id) as session:
        return identity_service._consume_locked_invitation(
            session,
            tenant_id=rig.tenant_id,
            invitation_id=rig.invitation_id,
            token_hash=rig.token_hash,
            accepting_user_id=rig.invitee_id,
            now=datetime.now(UTC),
        )


def _invitation_state(admin: sessionmaker[Session], rig: Rig) -> tuple[bool, object, object]:
    """`(exists, accepted_at, accepted_by_user_id)` through the privileged
    role, so RLS cannot hide a row from the assertion."""
    with session_scope(session_factory=admin) as session:
        row = session.execute(
            text("SELECT accepted_at, accepted_by_user_id FROM core.invitations WHERE id = :i"),
            {"i": str(rig.invitation_id)},
        ).first()
    return (row is not None, row[0] if row else None, row[1] if row else None)


def _membership_count(admin: sessionmaker[Session], rig: Rig) -> int:
    with session_scope(session_factory=admin) as session:
        return session.execute(
            text(
                "SELECT count(*) FROM core.tenant_memberships WHERE tenant_id = :t AND user_id = :u"
            ),
            {"t": str(rig.tenant_id), "u": str(rig.invitee_id)},
        ).scalar_one()


# --- the fence ----------------------------------------------------------------


@pytest.mark.parametrize("status", _INACCESSIBLE)
def test_inaccessible_tenant_invitation_is_refused_generically_and_writes_nothing(
    status: TenantStatus, rig: Rig, admin: sessionmaker[Session]
) -> None:
    _close(rig.tenant_id, status)
    assert get_tenant(rig.tenant_id).status == status.value

    with pytest.raises(InvitationInvalidError) as excinfo:
        _consume(rig)

    # The generic error, with nothing about the tenant in it.
    assert type(excinfo.value) is InvitationInvalidError
    assert str(rig.tenant_id) not in str(excinfo.value)
    assert status.value not in str(excinfo.value).lower()
    assert _membership_count(admin, rig) == 0
    exists, accepted_at, accepted_by = _invitation_state(admin, rig)
    if status is TenantStatus.PURGED:
        assert not exists  # purge removed the row; nothing was resurrected
    else:
        assert exists and accepted_at is None and accepted_by is None  # not consumed


@pytest.mark.parametrize("status", [TenantStatus.PENDING, TenantStatus.ACTIVE])
def test_accessible_tenant_invitation_still_activates_a_membership_once(
    status: TenantStatus, admin: sessionmaker[Session]
) -> None:
    built = _build_rig(status)
    try:
        assert get_tenant(built.tenant_id).status == status.value
        membership = _consume(built)
        assert membership.tenant_id == built.tenant_id
        assert membership.user_id == built.invitee_id
        assert membership.status == "active"
        assert _membership_count(admin, built) == 1
        exists, accepted_at, accepted_by = _invitation_state(admin, built)
        assert exists and accepted_at is not None and accepted_by == built.invitee_id

        with pytest.raises(InvitationInvalidError):  # consumed: one-time use holds
            _consume(built)
        assert _membership_count(admin, built) == 1
    finally:
        _teardown(admin, built)


# --- concurrency: the fence holds the tenant's share lock until commit ---------


def test_closure_waits_for_an_in_flight_acceptance_and_later_acceptance_is_refused(
    rig: Rig, admin: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Acceptance first: after `lock_accessible_tenant()` the transaction
    holds the tenant row FOR SHARE, so a SUSPENDED transition (FOR UPDATE)
    blocks until the membership write commits -- a closure can never land
    between the fence and the write. Once it lands, a fresh invitation for
    the same tenant is refused."""
    real = identity_service.lock_accessible_tenant
    paused, release = threading.Event(), threading.Event()

    def _locked_then_paused(session: Session, tenant_id: uuid.UUID) -> Tenant:
        tenant = real(session, tenant_id)
        paused.set()
        assert release.wait(timeout=30)
        return tenant

    monkeypatch.setattr(identity_service, "lock_accessible_tenant", _locked_then_paused)
    outcome: dict[str, object] = {}

    def _accept() -> None:
        try:
            outcome["membership"] = _consume(rig)
        except BaseException as exc:  # noqa: BLE001 -- asserted below
            outcome["error"] = exc

    acceptor = threading.Thread(target=_accept)
    acceptor.start()
    assert paused.wait(timeout=30), "acceptance never reached the lifecycle fence"

    closer = threading.Thread(
        target=transition_tenant_status, args=(rig.tenant_id, TenantStatus.SUSPENDED)
    )
    closer.start()
    closer.join(timeout=2)
    assert closer.is_alive(), "the closure must block on the acceptance's share lock"
    assert get_tenant(rig.tenant_id).status == TenantStatus.ACTIVE.value

    release.set()
    acceptor.join(timeout=30)
    closer.join(timeout=30)
    assert "error" not in outcome, outcome
    assert _membership_count(admin, rig) == 1  # decided while ACTIVE, committed first
    assert get_tenant(rig.tenant_id).status == TenantStatus.SUSPENDED.value

    monkeypatch.setattr(identity_service, "lock_accessible_tenant", real)
    # A second invitee for the now-SUSPENDED tenant: refused, nothing written.
    second = create_user()
    try:
        with tenant_session_scope(rig.tenant_id) as session:
            with pytest.raises(InvitationInvalidError):
                identity_service._consume_locked_invitation(
                    session,
                    tenant_id=rig.tenant_id,
                    invitation_id=rig.invitation_id,
                    token_hash=rig.token_hash,
                    accepting_user_id=second.id,
                    now=datetime.now(UTC),
                )
        assert get_membership(rig.tenant_id, second.id) is None
    finally:
        with session_scope(session_factory=admin) as session:
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(second.id)})


# --- the public entrypoint is still dormant (PRIV-01), unchanged ---------------


def test_public_accept_invitation_still_fails_closed_for_a_valid_token(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    """Not a claim of acceptance coverage: documents that the untenanted
    token lookup remains dormant under FORCE RLS (PRIV-01), so the public
    function still rejects even a genuinely valid token and writes nothing
    -- the fence above is defense in depth for when that design is
    resolved, not a revival of the path."""
    with pytest.raises(InvitationInvalidError):
        accept_invitation(rig.raw_token, rig.invitee_id)
    assert _membership_count(admin, rig) == 0
    exists, accepted_at, _ = _invitation_state(admin, rig)
    assert exists and accepted_at is None
