"""Invitation / membership-lifecycle integration tests against a real
PostgreSQL instance (architecture research: universal multi-tenant
tenancy, Phase G -- "Invitation / Membership Lifecycle").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_support_access_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/identity/test_invitation_integration.py
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.errors import (
    DuplicateInvitationError,
    InvalidMembershipTransitionError,
    InvitationAlreadyAcceptedError,
    InvitationInvalidError,
    InvitationNotAuthorizedError,
    MembershipNotFoundError,
)
from core.identity.invitation_status import InvitationStatus, compute_invitation_status
from core.identity.models import MembershipStatus
from core.identity.service import (
    accept_invitation,
    add_tenant_membership,
    create_invitation,
    create_user,
    get_invitation,
    get_membership,
    list_invitations_for_tenant,
    reactivate_membership,
    revoke_invitation,
    revoke_membership,
    suspend_membership,
)
from core.rbac.scope import RoleScope
from core.rbac.service import assign_role, create_role, grant_permission, register_permission
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_invitations_table() -> None:
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
            conn.execute(text("SELECT 1 FROM core.invitations LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.invitations does not exist yet -- run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


def _new_tenant() -> uuid.UUID:
    return create_tenant(_unique_name("tenant")).id


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with _admin_session() as session:
        session.execute(
            text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.invitations WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.membership_roles WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.role_permissions WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant_id)})
    with session_scope() as session:
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_permission(resource: str, action: str) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
            {"r": resource, "a": action},
        )


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


def _inviter_with_invitation_capability(tenant_id: uuid.UUID) -> uuid.UUID:
    """A human user holding the "manage invitations in this tenant"
    capability (create/revoke) -- has no other special power."""
    user_id = create_user().id
    membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, _unique_name("invite-admin-role"))
    for action in ("create", "revoke"):
        permission = register_permission("invitation", action)
        grant_permission(tenant_id, role.id, permission.id)
    assign_role(tenant_id, membership.id, role.id, scope=RoleScope.SELF)
    return user_id


# --- Invitation creation ----------------------------------------------------


def test_create_invitation_persists_and_returns_raw_token() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        email = _unique_email("invitee")
        invitation, raw_token = create_invitation(tenant_id, inviter, email)

        assert invitation.tenant_id == tenant_id
        assert invitation.invited_email == email
        assert invitation.token_hash != raw_token
        assert len(raw_token) > 20
        assert compute_invitation_status(invitation) == InvitationStatus.PENDING

        fetched = get_invitation(tenant_id, invitation.id)
        assert fetched is not None
        assert fetched.id == invitation.id
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_create_invitation_normalizes_email_case_and_whitespace() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        raw_email = f"  Invitee-{uuid.uuid4().hex[:8]}@Example.COM  "
        invitation, _ = create_invitation(tenant_id, inviter, raw_email)
        assert invitation.invited_email == raw_email.strip().casefold()
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_create_invitation_requires_authorization() -> None:
    tenant_id = _new_tenant()
    try:
        unauthorized_user = create_user().id
        with pytest.raises(InvitationNotAuthorizedError):
            create_invitation(tenant_id, unauthorized_user, _unique_email("invitee"))
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(unauthorized_user)


def test_duplicate_pending_invitation_for_same_email_raises() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        email = _unique_email("invitee")
        create_invitation(tenant_id, inviter, email)
        with pytest.raises(DuplicateInvitationError):
            create_invitation(tenant_id, inviter, email)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_create_invitation_writes_audit_entry() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, _ = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        entries = list_audit_entries(tenant_id)
        matching = [e for e in entries if e.action == "invitation.create"]
        assert len(matching) == 1
        assert matching[0].resource_id == str(invitation.id)
        assert matching[0].actor_user_id == inviter
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


# --- Invitation acceptance ---------------------------------------------------


def test_accept_invitation_activates_membership_for_new_user() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        _, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        invitee = create_user().id

        membership = accept_invitation(raw_token, invitee)

        assert membership.tenant_id == tenant_id
        assert membership.user_id == invitee
        assert membership.status == MembershipStatus.ACTIVE.value

        resolved = get_membership(tenant_id, invitee)
        assert resolved is not None
        assert resolved.status == MembershipStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_writes_audit_entry() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        invitee = create_user().id
        accept_invitation(raw_token, invitee)

        entries = list_audit_entries(tenant_id)
        matching = [e for e in entries if e.action == "invitation.accept"]
        assert len(matching) == 1
        assert matching[0].resource_id == str(invitation.id)
        assert matching[0].actor_user_id == invitee
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_is_one_time_use() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        _, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        invitee = create_user().id
        accept_invitation(raw_token, invitee)

        with pytest.raises(InvitationInvalidError):
            accept_invitation(raw_token, invitee)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_with_unknown_token_raises() -> None:
    invitee = create_user().id
    try:
        with pytest.raises(InvitationInvalidError):
            accept_invitation("not-a-real-token", invitee)
    finally:
        _cleanup_user(invitee)


def test_accept_expired_invitation_raises() -> None:
    """`ck_invitations_valid_time_range` (`expires_at > created_at`)
    prevents ever creating an already-expired invitation -- so expiry is
    exercised via `accept_invitation()`'s own `now=` test-injection point
    (mirrors `core/identity/login_transactions.py::consume_login_transaction()`'s
    identical `now=` parameter), not by constructing a past `expires_at`."""
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        soon = datetime.now(UTC) + timedelta(seconds=1)
        _, raw_token = create_invitation(
            tenant_id, inviter, _unique_email("invitee"), expires_at=soon
        )
        invitee = create_user().id
        after_expiry = soon + timedelta(minutes=1)
        with pytest.raises(InvitationInvalidError):
            accept_invitation(raw_token, invitee, now=after_expiry)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_revoked_invitation_raises() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        revoke_invitation(tenant_id, invitation.id, actor_user_id=inviter)
        invitee = create_user().id
        with pytest.raises(InvitationInvalidError):
            accept_invitation(raw_token, invitee)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_does_not_verify_accepting_identity_matches_invited_email() -> None:
    """architecture research Phase G section 10: Core does not verify that
    the accepting user's own identity corresponds to `invited_email` --
    `core.users` stores no email to compare against. This is a deliberate,
    reviewed boundary (Phase 8 ingress layer's own job), not an oversight
    -- this test documents that boundary explicitly."""
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        _, raw_token = create_invitation(tenant_id, inviter, _unique_email("intended-recipient"))
        someone_else = create_user().id
        membership = accept_invitation(raw_token, someone_else)
        assert membership.user_id == someone_else
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_is_tenant_bound() -> None:
    tenant_a = _new_tenant()
    tenant_b = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_a)
        _, raw_token = create_invitation(tenant_a, inviter, _unique_email("invitee"))
        invitee = create_user().id
        membership = accept_invitation(raw_token, invitee)

        assert membership.tenant_id == tenant_a
        assert get_membership(tenant_a, invitee) is not None
        assert get_membership(tenant_b, invitee) is None
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_with_existing_active_membership_is_idempotent() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitee = create_user().id
        add_tenant_membership(tenant_id, invitee)

        _, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        membership = accept_invitation(raw_token, invitee)
        assert membership.status == MembershipStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_with_suspended_existing_membership_fails_closed() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitee = create_user().id
        membership = add_tenant_membership(tenant_id, invitee)
        suspend_membership(tenant_id, membership.id, actor_user_id=inviter)

        _, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        with pytest.raises(InvalidMembershipTransitionError):
            accept_invitation(raw_token, invitee)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_with_revoked_existing_membership_fails_closed() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitee = create_user().id
        membership = add_tenant_membership(tenant_id, invitee)
        revoke_membership(tenant_id, membership.id, actor_user_id=inviter)

        _, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        with pytest.raises(InvalidMembershipTransitionError):
            accept_invitation(raw_token, invitee)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_cannot_produce_duplicate_membership_row() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitee = create_user().id
        add_tenant_membership(tenant_id, invitee)

        _, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        accept_invitation(raw_token, invitee)

        with tenant_session_scope(tenant_id) as session:
            count = session.execute(
                text(
                    "SELECT COUNT(*) FROM core.tenant_memberships "
                    "WHERE tenant_id = :t AND user_id = :u"
                ),
                {"t": str(tenant_id), "u": str(invitee)},
            ).scalar_one()
        assert count == 1
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


# --- Invitation revocation ---------------------------------------------------


def test_revoke_invitation_requires_authorization() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, _ = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        unauthorized_user = create_user().id
        with pytest.raises(InvitationNotAuthorizedError):
            revoke_invitation(tenant_id, invitation.id, actor_user_id=unauthorized_user)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(unauthorized_user)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_revoke_invitation_is_idempotent() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, _ = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        revoke_invitation(tenant_id, invitation.id, actor_user_id=inviter)
        revoked_again = revoke_invitation(tenant_id, invitation.id, actor_user_id=inviter)
        assert revoked_again.revoked_at is not None
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_revoke_already_accepted_invitation_raises() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        invitee = create_user().id
        accept_invitation(raw_token, invitee)

        with pytest.raises(InvitationAlreadyAcceptedError):
            revoke_invitation(tenant_id, invitation.id, actor_user_id=inviter)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_revoke_invitation_writes_audit_entry() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, _ = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        revoke_invitation(tenant_id, invitation.id, actor_user_id=inviter)

        entries = list_audit_entries(tenant_id)
        matching = [e for e in entries if e.action == "invitation.revoke"]
        assert len(matching) == 1
        assert matching[0].resource_id == str(invitation.id)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_list_invitations_for_tenant_is_tenant_scoped() -> None:
    tenant_a = _new_tenant()
    tenant_b = _new_tenant()
    try:
        inviter_a = _inviter_with_invitation_capability(tenant_a)
        create_invitation(tenant_a, inviter_a, _unique_email("invitee"))

        invitations_a = list_invitations_for_tenant(tenant_a)
        invitations_b = list_invitations_for_tenant(tenant_b)
        assert len(invitations_a) == 1
        assert len(invitations_b) == 0
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


# --- Concurrency / race conditions ------------------------------------------


def test_concurrent_acceptance_attempts_only_one_succeeds() -> None:
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        _, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        invitee = create_user().id

        results: list[str] = []
        barrier = threading.Barrier(2)

        def _attempt() -> None:
            barrier.wait()
            try:
                accept_invitation(raw_token, invitee)
                results.append("success")
            except InvitationInvalidError:
                results.append("invalid")

        threads = [threading.Thread(target=_attempt) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count("success") == 1
        assert results.count("invalid") == 1

        with tenant_session_scope(tenant_id) as session:
            count = session.execute(
                text(
                    "SELECT COUNT(*) FROM core.tenant_memberships "
                    "WHERE tenant_id = :t AND user_id = :u"
                ),
                {"t": str(tenant_id), "u": str(invitee)},
            ).scalar_one()
        assert count == 1
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_acceptance_versus_revocation_race_is_fail_closed() -> None:
    """Whichever of accept/revoke wins the row lock first determines the
    outcome; the loser must never both "succeed" and leave the invitation
    usable again -- exactly one of the two effects (accepted, or revoked)
    is ever true afterward, never both."""
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        invitee = create_user().id

        outcomes: list[str] = []
        barrier = threading.Barrier(2)

        def _accept() -> None:
            barrier.wait()
            try:
                accept_invitation(raw_token, invitee)
                outcomes.append("accepted")
            except InvitationInvalidError:
                outcomes.append("accept-failed")

        def _revoke() -> None:
            barrier.wait()
            try:
                revoke_invitation(tenant_id, invitation.id, actor_user_id=inviter)
                outcomes.append("revoke-ran")
            except InvitationAlreadyAcceptedError:
                outcomes.append("revoke-blocked")

        t1 = threading.Thread(target=_accept)
        t2 = threading.Thread(target=_revoke)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        refreshed = get_invitation(tenant_id, invitation.id)
        assert refreshed is not None
        # Never both accepted and revoked (the database CHECK constraint
        # makes this structurally impossible; this assertion is the
        # end-to-end proof, not just a schema-level one).
        assert not (refreshed.accepted_at is not None and refreshed.revoked_at is not None)
        assert "accepted" in outcomes or "revoke-ran" in outcomes
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


# --- Membership lifecycle ----------------------------------------------------


def test_suspend_then_reactivate_membership() -> None:
    tenant_id = _new_tenant()
    try:
        admin = create_user().id
        member = create_user().id
        membership = add_tenant_membership(tenant_id, member)
        assert membership.status == MembershipStatus.ACTIVE.value

        suspended = suspend_membership(tenant_id, membership.id, actor_user_id=admin)
        assert suspended.status == MembershipStatus.SUSPENDED.value

        reactivated = reactivate_membership(tenant_id, membership.id, actor_user_id=admin)
        assert reactivated.status == MembershipStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_id)


def test_revoke_membership_is_terminal() -> None:
    tenant_id = _new_tenant()
    try:
        admin = create_user().id
        member = create_user().id
        membership = add_tenant_membership(tenant_id, member)

        revoked = revoke_membership(tenant_id, membership.id, actor_user_id=admin)
        assert revoked.status == MembershipStatus.REVOKED.value

        with pytest.raises(InvalidMembershipTransitionError):
            reactivate_membership(tenant_id, membership.id, actor_user_id=admin)
        with pytest.raises(InvalidMembershipTransitionError):
            suspend_membership(tenant_id, membership.id, actor_user_id=admin)
    finally:
        _cleanup_tenant(tenant_id)


def test_suspend_and_revoke_are_idempotent() -> None:
    tenant_id = _new_tenant()
    try:
        admin = create_user().id
        member = create_user().id
        membership = add_tenant_membership(tenant_id, member)

        suspend_membership(tenant_id, membership.id, actor_user_id=admin)
        again = suspend_membership(tenant_id, membership.id, actor_user_id=admin)
        assert again.status == MembershipStatus.SUSPENDED.value

        revoke_membership(tenant_id, membership.id, actor_user_id=admin)
        again = revoke_membership(tenant_id, membership.id, actor_user_id=admin)
        assert again.status == MembershipStatus.REVOKED.value
    finally:
        _cleanup_tenant(tenant_id)


def test_membership_transition_on_unknown_membership_raises_not_found() -> None:
    tenant_id = _new_tenant()
    try:
        admin = create_user().id
        with pytest.raises(MembershipNotFoundError):
            suspend_membership(tenant_id, uuid.uuid4(), actor_user_id=admin)
    finally:
        _cleanup_tenant(tenant_id)


def test_membership_lifecycle_writes_audit_entries() -> None:
    tenant_id = _new_tenant()
    try:
        admin = create_user().id
        member = create_user().id
        membership = add_tenant_membership(tenant_id, member)

        suspend_membership(tenant_id, membership.id, actor_user_id=admin)
        reactivate_membership(tenant_id, membership.id, actor_user_id=admin)
        revoke_membership(tenant_id, membership.id, actor_user_id=admin)

        entries = list_audit_entries(tenant_id)
        actions = [e.action for e in entries]
        assert "membership.suspend" in actions
        assert "membership.reactivate" in actions
        assert "membership.revoke" in actions
    finally:
        _cleanup_tenant(tenant_id)
