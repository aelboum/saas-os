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

import hashlib
import threading
import uuid
from datetime import UTC, datetime, timedelta

import core.identity.service as identity_service
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
from core.identity.models import MembershipStatus, TenantMembership
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
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import Session

from core.tenancy import Tenant, create_tenant

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
    with tenant_session_scope(tenant_id) as session:
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
    assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, scope=RoleScope.SELF)
    return user_id


def _token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _consume_locked(
    tenant_id: uuid.UUID,
    invitation_id: uuid.UUID,
    raw_token: str,
    accepting_user_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> TenantMembership:
    """The transactional phase of `accept_invitation()`, called exactly the
    way that function calls it -- inside a real `tenant_session_scope()`
    transaction, with the `(tenant_id, invitation_id)` its own tenant-scoped
    token-hash lookup would already have resolved (PRIV-01, FORCE RLS on
    `core.invitations`, migration `cb7120cfa806`). Exercised directly here
    (rather than only through the public `accept_invitation()`) so tests
    can inject a specific `now` for expiry, or race the row lock against a
    concurrent revocation, without needing a second acceptance attempt
    (RA-11-F5; the same pattern as
    tests/core/identity/test_invitation_lifecycle_guard_integration.py).
    RLS is neither bypassed nor weakened: the runtime role, the
    tenant-scoped session and the locked row are all real."""
    with tenant_session_scope(tenant_id) as session:
        return identity_service._consume_locked_invitation(
            session,
            tenant_id=tenant_id,
            invitation_id=invitation_id,
            token_hash=_token_hash(raw_token),
            accepting_user_id=accepting_user_id,
            now=now if now is not None else datetime.now(UTC),
        )


def _membership_count(tenant_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """Through the privileged role, so RLS cannot hide a row from the assertion."""
    with _admin_session() as session:
        return session.execute(
            text(
                "SELECT COUNT(*) FROM core.tenant_memberships WHERE tenant_id = :t AND user_id = :u"
            ),
            {"t": str(tenant_id), "u": str(user_id)},
        ).scalar_one()


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

        membership = accept_invitation(raw_token, invitee, tenant_id)

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
        accept_invitation(raw_token, invitee, tenant_id)

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
        accept_invitation(raw_token, invitee, tenant_id)

        with pytest.raises(InvitationInvalidError):
            accept_invitation(raw_token, invitee, tenant_id)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_invitation_with_unknown_token_raises() -> None:
    tenant_id = _new_tenant()
    invitee = create_user().id
    try:
        with pytest.raises(InvitationInvalidError):
            accept_invitation("not-a-real-token", invitee, tenant_id)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(invitee)


def test_accept_invitation_with_wrong_tenant_raises_and_discloses_nothing() -> None:
    """The wrong-tenant regression proof (real PostgreSQL, real FORCE RLS):
    a genuinely valid, unexpired, unrevoked invitation for `tenant_a` must
    be neither readable nor acceptable when the caller supplies `tenant_b`
    -- not because of an application-level `tenant_id` equality check
    alone, but because `tenant_session_scope(tenant_b)` sets `app.tenant_id`
    to `tenant_b`, and `core.invitations`'s own RLS policy makes tenant_a's
    row structurally invisible to that session, regardless of how correct
    the token hash is. The rejection is the identical generic
    `InvitationInvalidError` an unknown token would raise -- a caller
    cannot learn that a valid invitation exists in some other tenant --
    and nothing is written: the invitation is untouched and no membership
    is created in either tenant."""
    tenant_a = _new_tenant()
    tenant_b = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_a)
        invitation, raw_token = create_invitation(tenant_a, inviter, _unique_email("invitee"))
        invitee = create_user().id

        with pytest.raises(InvitationInvalidError) as excinfo:
            accept_invitation(raw_token, invitee, tenant_b)

        message = str(excinfo.value)
        assert raw_token not in message
        assert str(tenant_a) not in message
        assert str(invitation.id) not in message

        assert _membership_count(tenant_a, invitee) == 0
        assert _membership_count(tenant_b, invitee) == 0
        untouched = get_invitation(tenant_a, invitation.id)
        assert untouched is not None
        assert untouched.accepted_at is None and untouched.accepted_by_user_id is None

        # Control: the identical token, correctly tenant-scoped, still works.
        membership = accept_invitation(raw_token, invitee, tenant_a)
        assert membership.tenant_id == tenant_a
        assert membership.status == MembershipStatus.ACTIVE.value
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_expired_invitation_raises() -> None:
    """`ck_invitations_valid_time_range` (`expires_at > created_at`)
    prevents ever creating an already-expired invitation -- so expiry is
    exercised via the `now=` test-injection point (mirrors
    `core/identity/login_transactions.py::consume_login_transaction()`'s
    identical `now=` parameter), not by constructing a past `expires_at`.

    RA-11-F5: exercised directly at `_consume_locked_invitation()` (the
    transactional phase `accept_invitation()` itself delegates to) with a
    known `(tenant_id, invitation_id)`, skipping the redundant token-hash
    lookup `accept_invitation()` would otherwise repeat -- `expires_at <=
    now` is enforced there regardless of which entrypoint calls it. The
    same invitation is then consumed with a `now` inside its window,
    proving the rejection was the expiry and nothing
    else."""
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        invitation, raw_token = create_invitation(
            tenant_id, inviter, _unique_email("invitee"), expires_at=expires_at
        )
        invitee = create_user().id

        with pytest.raises(InvitationInvalidError):
            _consume_locked(
                tenant_id,
                invitation.id,
                raw_token,
                invitee,
                now=expires_at + timedelta(minutes=1),
            )
        refreshed = get_invitation(tenant_id, invitation.id)
        assert refreshed is not None
        assert refreshed.accepted_at is None and refreshed.accepted_by_user_id is None
        assert _membership_count(tenant_id, invitee) == 0

        # Control: inside the window, the identical inputs are accepted.
        membership = _consume_locked(
            tenant_id,
            invitation.id,
            raw_token,
            invitee,
            now=expires_at - timedelta(minutes=1),
        )
        assert membership.status == MembershipStatus.ACTIVE.value
        assert _membership_count(tenant_id, invitee) == 1
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


def test_accept_revoked_invitation_raises() -> None:
    """RA-11-F5: exercised at `_consume_locked_invitation()` directly (see
    `test_accept_expired_invitation_raises` for why -- the same
    known-`(tenant_id, invitation_id)` shortcut). Revocation itself goes
    through the real, authorized `revoke_invitation()`."""
    tenant_id = _new_tenant()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        revoke_invitation(tenant_id, invitation.id, actor_user_id=inviter)
        invitee = create_user().id

        with pytest.raises(InvitationInvalidError):
            _consume_locked(tenant_id, invitation.id, raw_token, invitee)
        refreshed = get_invitation(tenant_id, invitation.id)
        assert refreshed is not None
        assert refreshed.revoked_at is not None  # still revoked ...
        assert (
            refreshed.accepted_at is None and refreshed.accepted_by_user_id is None
        )  # ... unconsumed
        assert _membership_count(tenant_id, invitee) == 0
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
        membership = accept_invitation(raw_token, someone_else, tenant_id)
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
        membership = accept_invitation(raw_token, invitee, tenant_a)

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
        membership = accept_invitation(raw_token, invitee, tenant_id)
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
            accept_invitation(raw_token, invitee, tenant_id)
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
            accept_invitation(raw_token, invitee, tenant_id)
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
        accept_invitation(raw_token, invitee, tenant_id)

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
        accept_invitation(raw_token, invitee, tenant_id)

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
                accept_invitation(raw_token, invitee, tenant_id)
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


def test_acceptance_versus_revocation_race_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance and revocation race for the same invitation at the locked
    transactional phase (RA-11-F5 -- staged directly against
    `_consume_locked_invitation()` with a known `(tenant_id, invitation_id)`
    so the race begins exactly at the row lock, without the token-hash
    lookup `accept_invitation()` itself would first perform). Acceptance
    locks the invitation row
    `FOR UPDATE` and is paused at the lifecycle fence (the pause-hook
    pattern of test_invitation_lifecycle_guard_integration.py); revocation
    then starts and must block on that lock rather than proceed on a
    pre-acceptance snapshot. Afterwards exactly one transition has
    happened: the invitation is accepted and not revoked, exactly one
    membership exists, and the revocation failed closed.

    The loser's exception type is deliberately not asserted:
    `revoke_invitation()` currently reads the row without a lock, so its
    losing UPDATE surfaces the database CHECK
    (`ck_invitations_not_accepted_and_revoked`) rather than the documented
    `InvitationAlreadyAcceptedError`. That lock gap is a separate finding;
    this test pins the invariant, not the loser's error class."""
    tenant_id = _new_tenant()
    paused, release = threading.Event(), threading.Event()
    try:
        inviter = _inviter_with_invitation_capability(tenant_id)
        invitation, raw_token = create_invitation(tenant_id, inviter, _unique_email("invitee"))
        invitee = create_user().id

        real_fence = identity_service.lock_accessible_tenant

        def _locked_then_paused(session: Session, locked_tenant_id: uuid.UUID) -> Tenant:
            tenant = real_fence(session, locked_tenant_id)  # row already locked FOR UPDATE
            paused.set()
            assert release.wait(timeout=30)
            return tenant

        monkeypatch.setattr(identity_service, "lock_accessible_tenant", _locked_then_paused)
        outcome: dict[str, object] = {}

        def _accept() -> None:
            try:
                outcome["membership"] = _consume_locked(
                    tenant_id, invitation.id, raw_token, invitee
                )
            except BaseException as exc:  # noqa: BLE001 -- asserted below
                outcome["accept_error"] = exc

        def _revoke() -> None:
            try:
                revoke_invitation(tenant_id, invitation.id, actor_user_id=inviter)
                outcome["revoked"] = True
            except BaseException as exc:  # noqa: BLE001 -- asserted below
                outcome["revoke_error"] = exc

        acceptor = threading.Thread(target=_accept)
        acceptor.start()
        assert paused.wait(timeout=30), "acceptance never reached the locked phase"

        revoker = threading.Thread(target=_revoke)
        revoker.start()
        revoker.join(timeout=2)
        assert revoker.is_alive(), "revocation must block on the acceptance's row lock"

        release.set()
        acceptor.join(timeout=30)
        revoker.join(timeout=30)
        assert not acceptor.is_alive() and not revoker.is_alive()

        # Exactly one transition -- the lock holder's; the loser failed closed.
        assert "membership" in outcome, outcome
        assert "revoked" not in outcome, outcome
        assert isinstance(outcome.get("revoke_error"), Exception), outcome
        refreshed = get_invitation(tenant_id, invitation.id)
        assert refreshed is not None
        assert refreshed.accepted_at is not None and refreshed.accepted_by_user_id == invitee
        assert refreshed.revoked_at is None and refreshed.revoked_by_user_id is None
        assert _membership_count(tenant_id, invitee) == 1
    finally:
        release.set()  # never leave a paused acceptance holding the row lock
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
