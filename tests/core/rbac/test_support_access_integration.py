"""Support-access authorization integration tests against a real
PostgreSQL instance (architecture research: universal multi-tenant
tenancy, Phase F -- "Audit + Support Access").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_deny_authorization_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_support_access_integration.py

Covers, per the Phase F checkpoint's own testing requirements (1-20):
request creation, approval, denial, expiration, revocation, explicit
target tenant, authorization through `can()`, explicit deny overriding
support access, no implicit parent/child/sibling access, bounded scope,
privilege-amplification prevention, audit linkage, acting tenant context,
real actor preservation, delegation/service-account/hierarchy
non-interference, RLS isolation, and multi-tenant negative cases.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_service_account, create_user
from core.rbac.errors import (
    DelegationNotAuthorizedError,
    DuplicateSupportAccessRequestError,
    InvalidPrincipalError,
    InvalidSupportAccessTimeRangeError,
    SupportAccessAlreadyDecidedError,
    SupportAccessNotApprovedError,
    SupportAccessNotAuthorizedError,
    SupportAccessSelfApprovalError,
)
from core.rbac.principal import PrincipalType
from core.rbac.service import (
    approve_support_access,
    assign_role,
    assign_service_account_role,
    create_delegation,
    create_deny,
    create_role,
    create_support_access_request,
    deny_support_access,
    get_support_access_request,
    grant_permission,
    register_permission,
    revoke_support_access,
)
from core.rbac.support_status import SupportAccessStatus, compute_support_access_status
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.rbac import RoleScope, can
from core.tenancy import create_tenant, move_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_support_access_table() -> None:
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
            conn.execute(text("SELECT 1 FROM core.support_access_requests LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            "core.support_access_requests does not exist yet -- run `alembic upgrade head` "
            f"first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _new_tenant() -> uuid.UUID:
    return create_tenant(_unique_name("tenant")).id


def _future_window(*, hours: float = 1.0) -> tuple[datetime, datetime]:
    starts = datetime.now(UTC)
    return starts, starts + timedelta(hours=hours)


def _past_window() -> tuple[datetime, datetime]:
    """An already-expired, but internally valid (expires > starts),
    window -- lets expiration be tested deterministically, with no sleep."""
    starts = datetime.now(UTC) - timedelta(hours=2)
    expires = datetime.now(UTC) - timedelta(minutes=30)
    return starts, expires


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with _admin_session() as session:
        session.execute(
            text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.support_access_requests WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        )
        session.execute(
            text("DELETE FROM core.delegation_grants WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.service_account_roles WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        )
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
        session.execute(
            text("DELETE FROM core.service_accounts WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t OR ancestor_id = :t"),
            {"t": str(tenant_id)},
        )
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


def _admin_user_with_support_capability(tenant_id: uuid.UUID) -> uuid.UUID:
    """A human user holding the "manage support access in this tenant"
    capability (approve/deny/revoke) -- has no other special power."""
    user_id = create_user().id
    membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, _unique_name("support-admin-role"))
    for action in ("approve", "deny", "revoke"):
        permission = register_permission("support_access_request", action)
        grant_permission(tenant_id, role.id, permission.id)
    assign_role(tenant_id, membership.id, role.id, scope=RoleScope.SELF)
    return user_id


def _approved_request(
    tenant_id: uuid.UUID,
    *,
    scope_mode: RoleScope = RoleScope.SELF,
    window: tuple[datetime, datetime] | None = None,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Create a fresh requester + admin, request support access, approve
    it. Returns (requester_user_id, admin_user_id, request_id)."""
    requester = create_user().id
    admin = _admin_user_with_support_capability(tenant_id)
    starts, expires = window if window is not None else _future_window()
    request = create_support_access_request(
        requester_user_id=requester,
        tenant_id=tenant_id,
        reason="investigating a customer-reported bug",
        requested_starts_at=starts,
        requested_expires_at=expires,
        scope_mode=scope_mode,
    )
    approve_support_access(approver_user_id=admin, tenant_id=tenant_id, request_id=request.id)
    return requester, admin, request.id


# --- 1. Request creation -----------------------------------------------


def test_create_support_access_request_returns_pending_request() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="onboarding assistance",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        assert request.tenant_id == tenant_id
        assert request.requester_user_id == requester
        assert request.approved_at is None
        assert request.denied_at is None
        assert request.revoked_at is None
        assert compute_support_access_status(request) == SupportAccessStatus.REQUESTED
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)


def test_create_support_access_request_rejects_unknown_requester() -> None:
    tenant_id = _new_tenant()
    try:
        starts, expires = _future_window()
        with pytest.raises(InvalidPrincipalError):
            create_support_access_request(
                requester_user_id=uuid.uuid4(),
                tenant_id=tenant_id,
                reason="x",
                requested_starts_at=starts,
                requested_expires_at=expires,
            )
    finally:
        _cleanup_tenant(tenant_id)


def test_create_support_access_request_rejects_empty_reason() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        with pytest.raises(InvalidSupportAccessTimeRangeError):
            create_support_access_request(
                requester_user_id=requester,
                tenant_id=tenant_id,
                reason="   ",
                requested_starts_at=starts,
                requested_expires_at=expires,
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)


def test_create_support_access_request_rejects_expiry_before_start() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        with pytest.raises(InvalidSupportAccessTimeRangeError):
            create_support_access_request(
                requester_user_id=requester,
                tenant_id=tenant_id,
                reason="x",
                requested_starts_at=expires,
                requested_expires_at=starts,
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)


def test_create_support_access_request_rejects_window_exceeding_max_duration() -> None:
    """architecture research Phase F: "have a bounded expiration" --
    bounded means a real, enforced maximum, not merely "any finite
    value"."""
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        starts = datetime.now(UTC)
        with pytest.raises(InvalidSupportAccessTimeRangeError):
            create_support_access_request(
                requester_user_id=requester,
                tenant_id=tenant_id,
                reason="x",
                requested_starts_at=starts,
                requested_expires_at=starts + timedelta(days=30),
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)


def test_create_support_access_request_rejects_duplicate_live_request() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="first request",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        with pytest.raises(DuplicateSupportAccessRequestError):
            create_support_access_request(
                requester_user_id=requester,
                tenant_id=tenant_id,
                reason="second, overlapping request",
                requested_starts_at=starts,
                requested_expires_at=expires,
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)


# --- 2/6/7. Approval, explicit target tenant, can() integration ---------


def test_approved_support_access_satisfies_can_at_target_tenant() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, _request_id = _approved_request(tenant_id)
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything") is True
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_unapproved_support_access_request_grants_nothing() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="pending review",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything")
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)


def test_support_access_approved_in_tenant_a_does_not_grant_tenant_b() -> None:
    """Explicit target tenant: approval in one tenant has zero effect
    anywhere else."""
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        requester, admin, _request_id = _approved_request(tenant_a)
        assert (
            can(actor_id=requester, tenant_id=tenant_b, action="read", resource="anything") is False
        )
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_approve_support_access_requires_authorization() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        unauthorized = create_user().id
        add_tenant_membership(tenant_id, unauthorized)
        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="x",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        with pytest.raises(SupportAccessNotAuthorizedError):
            approve_support_access(
                approver_user_id=unauthorized, tenant_id=tenant_id, request_id=request.id
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(unauthorized)


def test_approve_support_access_rejects_self_approval() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        membership = add_tenant_membership(tenant_id, requester)
        role = create_role(tenant_id, _unique_name("self-approver-role"))
        for action in ("approve",):
            permission = register_permission("support_access_request", action)
            grant_permission(tenant_id, role.id, permission.id)
        assign_role(tenant_id, membership.id, role.id, scope=RoleScope.SELF)

        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="x",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        with pytest.raises(SupportAccessSelfApprovalError):
            approve_support_access(
                approver_user_id=requester, tenant_id=tenant_id, request_id=request.id
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_permission("support_access_request", "approve")


def test_approve_already_decided_request_raises() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, request_id = _approved_request(tenant_id)
        with pytest.raises(SupportAccessAlreadyDecidedError):
            approve_support_access(
                approver_user_id=admin, tenant_id=tenant_id, request_id=request_id
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


# --- 3. Denial ------------------------------------------------------------


def test_denied_support_access_grants_nothing() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        admin = _admin_user_with_support_capability(tenant_id)
        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="x",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        denied = deny_support_access(
            approver_user_id=admin, tenant_id=tenant_id, request_id=request.id
        )
        assert compute_support_access_status(denied) == SupportAccessStatus.DENIED
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything")
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_deny_already_decided_request_raises() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, request_id = _approved_request(tenant_id)
        with pytest.raises(SupportAccessAlreadyDecidedError):
            deny_support_access(approver_user_id=admin, tenant_id=tenant_id, request_id=request_id)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


# --- 4. Expiration ----------------------------------------------------


def test_expired_support_access_denies_can() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, request_id = _approved_request(tenant_id, window=_past_window())
        request = get_support_access_request(tenant_id, request_id)
        assert compute_support_access_status(request) == SupportAccessStatus.EXPIRED
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything")
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_not_yet_started_support_access_denies_can() -> None:
    """`requested_starts_at` in the future -- approved, but not yet
    ACTIVE."""
    tenant_id = _new_tenant()
    try:
        starts = datetime.now(UTC) + timedelta(minutes=30)
        expires = starts + timedelta(hours=1)
        requester, admin, request_id = _approved_request(tenant_id, window=(starts, expires))
        request = get_support_access_request(tenant_id, request_id)
        assert compute_support_access_status(request) == SupportAccessStatus.APPROVED
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything")
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


# --- 5. Revocation ----------------------------------------------------


def test_revoke_support_access_denies_can_immediately() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, request_id = _approved_request(tenant_id)
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything") is True
        )
        revoke_support_access(revoker_user_id=admin, tenant_id=tenant_id, request_id=request_id)
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything")
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_revoke_support_access_requires_authorization() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, request_id = _approved_request(tenant_id)
        unauthorized = create_user().id
        add_tenant_membership(tenant_id, unauthorized)
        with pytest.raises(SupportAccessNotAuthorizedError):
            revoke_support_access(
                revoker_user_id=unauthorized, tenant_id=tenant_id, request_id=request_id
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_user(unauthorized)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_revoke_unapproved_request_raises() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        admin = _admin_user_with_support_capability(tenant_id)
        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="x",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        with pytest.raises(SupportAccessNotApprovedError):
            revoke_support_access(revoker_user_id=admin, tenant_id=tenant_id, request_id=request.id)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_revoke_support_access_is_idempotent() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, request_id = _approved_request(tenant_id)
        revoke_support_access(revoker_user_id=admin, tenant_id=tenant_id, request_id=request_id)
        # Must not raise.
        revoke_support_access(revoker_user_id=admin, tenant_id=tenant_id, request_id=request_id)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


# --- 8. Explicit deny overrides support access -----------------------


def test_explicit_deny_overrides_active_support_access() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, request_id = _approved_request(tenant_id)
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything") is True
        )

        deny_admin = create_user().id
        deny_membership = add_tenant_membership(tenant_id, deny_admin)
        deny_role = create_role(tenant_id, _unique_name("deny-admin-role"))
        deny_permission = register_permission("deny_grant", "create")
        grant_permission(tenant_id, deny_role.id, deny_permission.id)
        assign_role(tenant_id, deny_membership.id, deny_role.id, scope=RoleScope.SELF)

        target_permission = register_permission("anything", "read")
        create_deny(
            grantor_user_id=deny_admin,
            principal_user_id=requester,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=target_permission.id,
        )
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything")
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_user(deny_admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")
        _cleanup_permission("deny_grant", "create")
        _cleanup_permission("anything", "read")


# --- 9. No implicit parent/child/sibling access ------------------------


def test_support_access_self_scope_does_not_reach_child() -> None:
    parent_id, child_id = _new_tenant(), _new_tenant()
    try:
        move_tenant(child_id, new_parent_id=parent_id)
        requester, admin, _request_id = _approved_request(parent_id, scope_mode=RoleScope.SELF)
        assert (
            can(actor_id=requester, tenant_id=child_id, action="read", resource="anything") is False
        )
    finally:
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_support_access_subtree_scope_reaches_child() -> None:
    """Explicit, approved SUBTREE scope -- never implicit hierarchy
    access, but explicitly and safely covered when the approved scope
    says so (architectural decision from this phase's own approved
    design)."""
    parent_id, child_id = _new_tenant(), _new_tenant()
    try:
        move_tenant(child_id, new_parent_id=parent_id)
        requester, admin, _request_id = _approved_request(parent_id, scope_mode=RoleScope.SUBTREE)
        assert (
            can(actor_id=requester, tenant_id=child_id, action="read", resource="anything") is True
        )
    finally:
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_support_access_does_not_reach_parent_from_child() -> None:
    parent_id, child_id = _new_tenant(), _new_tenant()
    try:
        move_tenant(child_id, new_parent_id=parent_id)
        requester, admin, _request_id = _approved_request(child_id, scope_mode=RoleScope.SUBTREE)
        assert (
            can(actor_id=requester, tenant_id=parent_id, action="read", resource="anything")
            is False
        )
    finally:
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_support_access_does_not_reach_sibling_tenant() -> None:
    parent_id, child_a, child_b = _new_tenant(), _new_tenant(), _new_tenant()
    try:
        move_tenant(child_a, new_parent_id=parent_id)
        move_tenant(child_b, new_parent_id=parent_id)
        requester, admin, _request_id = _approved_request(child_a, scope_mode=RoleScope.SUBTREE)
        assert (
            can(actor_id=requester, tenant_id=child_b, action="read", resource="anything") is False
        )
    finally:
        _cleanup_tenant(child_a)
        _cleanup_tenant(child_b)
        _cleanup_tenant(parent_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


# --- 10/11. Bounded scope / privilege amplification prevention ---------


@pytest.mark.parametrize(
    "excluded_resource",
    [
        "delegation_grant",
        "deny_grant",
        "service_account_role",
        "support_access_request",
        "api_key",
        "service_account",
    ],
)
def test_support_access_cannot_satisfy_excluded_resources(excluded_resource: str) -> None:
    """architecture research Phase F: "a support grant must never itself
    be able to create: delegation grants, deny grants, service-account
    roles, unrestricted support grants" -- extended here to API keys and
    service accounts (the identical persistent-artifact-amplification
    principle)."""
    tenant_id = _new_tenant()
    try:
        requester, admin, _request_id = _approved_request(tenant_id, scope_mode=RoleScope.SUBTREE)
        assert (
            can(
                actor_id=requester, tenant_id=tenant_id, action="create", resource=excluded_resource
            )
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_support_access_cannot_be_used_to_create_a_real_delegation_grant() -> None:
    """End-to-end proof, not just a `can()` probe: an active support
    grant cannot actually be used to call `create_delegation()` --
    `create_delegation()`'s own can() gate rejects the support-authorized
    actor."""
    tenant_id = _new_tenant()
    try:
        requester, admin, _request_id = _approved_request(tenant_id, scope_mode=RoleScope.SUBTREE)
        target_user = create_user().id
        permission = register_permission(_unique_name("resource"), "read")
        with pytest.raises(DelegationNotAuthorizedError):
            create_delegation(
                delegator_user_id=requester,
                delegate_user_id=target_user,
                tenant_id=tenant_id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_user(target_user)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")
        _cleanup_permission("delegation_grant", "create")


# --- 12/13/14. Audit linkage, acting tenant context, real actor --------


def test_create_support_access_request_writes_audit_entry_with_linkage() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="x",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        entries = list_audit_entries(tenant_id, resource_type="support_access_request")
        matching = [e for e in entries if e.action == "support_access.request"]
        assert len(matching) == 1
        entry = matching[0]
        assert entry.outcome == "success"
        assert entry.actor_type == "user"
        assert entry.actor_user_id == requester  # real actor preserved, never impersonated
        assert entry.acting_as_tenant_id == tenant_id
        assert entry.support_access_id == request.id
        assert entry.delegation_grant_id is None
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)


def test_approve_deny_revoke_each_write_a_distinct_audit_entry() -> None:
    tenant_id = _new_tenant()
    try:
        requester, admin, request_id = _approved_request(tenant_id)
        revoke_support_access(revoker_user_id=admin, tenant_id=tenant_id, request_id=request_id)

        entries = list_audit_entries(tenant_id, resource_type="support_access_request")
        actions = {e.action for e in entries}
        assert {
            "support_access.request",
            "support_access.approve",
            "support_access.revoke",
        } <= actions

        approve_entry = next(e for e in entries if e.action == "support_access.approve")
        assert approve_entry.actor_user_id == admin
        assert approve_entry.support_access_id == request_id
        assert approve_entry.acting_as_tenant_id == tenant_id

        revoke_entry = next(e for e in entries if e.action == "support_access.revoke")
        assert revoke_entry.actor_user_id == admin
        assert revoke_entry.support_access_id == request_id
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_denial_audit_entry_records_the_real_denying_actor() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        admin = _admin_user_with_support_capability(tenant_id)
        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="x",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        deny_support_access(approver_user_id=admin, tenant_id=tenant_id, request_id=request.id)
        entries = list_audit_entries(tenant_id, resource_type="support_access_request")
        deny_entry = next(e for e in entries if e.action == "support_access.deny")
        assert deny_entry.actor_user_id == admin
        assert deny_entry.actor_user_id != requester
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


# --- 15/16/17. Existing delegation/service-account/hierarchy unaffected -


def test_delegation_and_support_access_do_not_interfere() -> None:
    """An active `DelegationGrant` and an active `SupportAccessRequest`
    for the SAME actor/tenant coexist correctly -- each is evaluated
    through the identical `can()` chokepoint, neither masking the
    other."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        # Delegation, unrelated permission.
        delegator = create_user().id
        delegator_membership = add_tenant_membership(tenant_id, delegator)
        delegator_role = create_role(tenant_id, _unique_name("delegator-role"))
        delegated_permission = register_permission(resource, action)
        grant_permission(tenant_id, delegator_role.id, delegated_permission.id)
        dg_permission = register_permission("delegation_grant", "create")
        grant_permission(tenant_id, delegator_role.id, dg_permission.id)
        assign_role(tenant_id, delegator_membership.id, delegator_role.id, scope=RoleScope.SELF)

        delegate_user = create_user().id
        create_delegation(
            delegator_user_id=delegator,
            delegate_user_id=delegate_user,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=delegated_permission.id,
        )
        assert (
            can(actor_id=delegate_user, tenant_id=tenant_id, action=action, resource=resource)
            is True
        )

        # Support access, for a completely different requester.
        requester, admin, _request_id = _approved_request(tenant_id)
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action="read", resource="anything") is True
        )

        # Neither leaks into the other's identity.
        assert (
            can(actor_id=delegate_user, tenant_id=tenant_id, action="read", resource="anything")
            is False
        )
        assert (
            can(actor_id=requester, tenant_id=tenant_id, action=action, resource=resource) is True
        )  # blanket support access DOES cover this resource too
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(delegator)
        _cleanup_user(delegate_user)
        _cleanup_user(requester)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)
        _cleanup_permission("delegation_grant", "create")
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


def test_service_account_authorization_unaffected_by_support_access_existing() -> None:
    """A `ServiceAccountRole`-authorized service account keeps working
    exactly as before, regardless of whether an unrelated support request
    exists in the same tenant."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        admin = create_user().id
        admin_membership = add_tenant_membership(tenant_id, admin)
        admin_role = create_role(tenant_id, _unique_name("sa-admin-role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_id, admin_role.id, permission.id)
        sa_role_permission = register_permission("service_account_role", "create")
        grant_permission(tenant_id, admin_role.id, sa_role_permission.id)
        assign_role(tenant_id, admin_membership.id, admin_role.id, scope=RoleScope.SELF)

        sa = create_service_account(tenant_id, _unique_name("svc"))
        sa_role = create_role(tenant_id, _unique_name("sa-role"))
        grant_permission(tenant_id, sa_role.id, permission.id)
        assign_service_account_role(
            actor_user_id=admin,
            tenant_id=tenant_id,
            service_account_id=sa.id,
            role_id=sa_role.id,
            scope=RoleScope.SELF,
        )
        assert (
            can(
                actor_id=sa.id,
                tenant_id=tenant_id,
                action=action,
                resource=resource,
                actor_type=PrincipalType.SERVICE_ACCOUNT,
                actor_tenant_id=tenant_id,
            )
            is True
        )

        requester, support_admin, _request_id = _approved_request(tenant_id)
        # Service account result is unchanged by the unrelated support grant.
        assert (
            can(
                actor_id=sa.id,
                tenant_id=tenant_id,
                action=action,
                resource=resource,
                actor_type=PrincipalType.SERVICE_ACCOUNT,
                actor_tenant_id=tenant_id,
            )
            is True
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_user(requester)
        _cleanup_user(support_admin)
        _cleanup_permission(resource, action)
        _cleanup_permission("service_account_role", "create")
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


# --- 18. RLS isolation ---------------------------------------------------


def test_force_row_level_security_is_actually_enabled_on_support_access_requests() -> None:
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'support_access_requests'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True


def test_cross_tenant_read_of_support_access_requests_is_denied_by_rls() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_a,
            reason="x",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        with tenant_session_scope(tenant_b) as session:
            rows = session.execute(
                text("SELECT id FROM core.support_access_requests WHERE id = :id"),
                {"id": str(request.id)},
            ).all()
        assert rows == []
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(requester)


def test_untenanted_read_of_support_access_requests_returns_nothing() -> None:
    tenant_id = _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        request = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_id,
            reason="x",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        with session_scope() as session:
            rows = session.execute(
                text("SELECT id FROM core.support_access_requests WHERE id = :id"),
                {"id": str(request.id)},
            ).all()
        assert rows == []
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(requester)


# --- 20. Multi-tenant negative cases -------------------------------------


def test_same_requester_can_have_independent_requests_in_different_tenants() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        requester = create_user().id
        starts, expires = _future_window()
        request_a = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_a,
            reason="a",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        request_b = create_support_access_request(
            requester_user_id=requester,
            tenant_id=tenant_b,
            reason="b",
            requested_starts_at=starts,
            requested_expires_at=expires,
        )
        assert request_a.id != request_b.id
        assert request_a.tenant_id == tenant_a
        assert request_b.tenant_id == tenant_b
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(requester)


def test_revoking_support_access_in_one_tenant_does_not_affect_another() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        requester_a, admin_a, request_a_id = _approved_request(tenant_a)
        requester_b, admin_b, request_b_id = _approved_request(tenant_b)
        revoke_support_access(revoker_user_id=admin_a, tenant_id=tenant_a, request_id=request_a_id)

        assert (
            can(actor_id=requester_a, tenant_id=tenant_a, action="read", resource="anything")
            is False
        )
        assert (
            can(actor_id=requester_b, tenant_id=tenant_b, action="read", resource="anything")
            is True
        )
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(requester_a)
        _cleanup_user(admin_a)
        _cleanup_user(requester_b)
        _cleanup_user(admin_b)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")
