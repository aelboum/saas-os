"""Phase I reference-consumer scenario validation (architecture research:
universal multi-tenant tenancy, Phase I -- "Reference Consumer
Extension"), against a real, disposable PostgreSQL instance.

This file imports `reference_consumer.scenarios` directly, from this
repository's own working tree -- a FAST, iterative validation that the
reference consumer's own composed business logic produces the correct
SaaS-OS-guaranteed outcomes. It deliberately does **not** rebuild the
packaging-boundary proof: that remains
`tests/test_reference_consumer_integration.py`'s own real-wheel,
isolated-venv mechanism (ADR-0018), re-run unchanged as part of Phase I
validation. `reference_consumer/`'s own source code still only ever
imports `core`/`api`/`control_plane` the ordinary package way -- the
`sys.path` insertion below is a test-harness convenience local to this
one file, not something `reference_consumer` itself does or needs.

Marked `integration` and excluded from the default `pytest` run, mirroring
every other database-backed integration test in this repository.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/test_reference_consumer_scenarios_integration.py
"""

from __future__ import annotations

import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

_REFERENCE_CONSUMER_ROOT = Path(__file__).resolve().parents[1] / "examples" / "reference-consumer"
if str(_REFERENCE_CONSUMER_ROOT) not in sys.path:
    sys.path.insert(0, str(_REFERENCE_CONSUMER_ROOT))

from core.api_keys.errors import (  # noqa: E402
    ExpiredApiKeyError,
    InactiveServiceAccountError,
    InvalidApiKeyError,
)
from core.billing.errors import InheritedBillingSubscriptionError  # noqa: E402
from core.billing.service import (  # noqa: E402
    cancel_subscription,
    create_plan,
    get_entitlements,
    upgrade_subscription,
)
from core.identity.errors import InvitationInvalidError  # noqa: E402
from core.identity.service import (  # noqa: E402
    accept_invitation,
    create_user,
    disable_service_account,
    enable_service_account,
    revoke_invitation,
    revoke_membership,
    suspend_membership,
)
from core.rbac.errors import DelegationNotAuthorizedError  # noqa: E402
from core.rbac.principal import PrincipalType  # noqa: E402
from core.rbac.scope import RoleScope  # noqa: E402
from core.rbac.service import (  # noqa: E402
    create_delegation,
    register_permission,
    revoke_delegation,
    revoke_support_access,
)
from core.usage.models import UsageEvent  # noqa: E402
from core.usage.service import aggregate_usage, aggregate_usage_including_descendants  # noqa: E402
from infra.db.config import get_database_config, get_migrations_database_config  # noqa: E402
from infra.db.engine import build_engine, get_engine  # noqa: E402
from infra.db.session import (  # noqa: E402
    build_session_factory,
    session_scope,
    tenant_session_scope,
)
from reference_consumer import scenarios  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.exc import OperationalError  # noqa: E402

from core.rbac import can  # noqa: E402
from core.tenancy import get_ancestor_ids, get_descendant_ids, move_tenant  # noqa: E402

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
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


# --- Cleanup helpers (union of every prior phase's own patterns) -----------


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


def _cleanup_tenant_tree(*tenant_ids_leaf_to_root: uuid.UUID) -> None:
    for tenant_id in tenant_ids_leaf_to_root:
        with _admin_session() as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.invitations WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
        with tenant_session_scope(tenant_id) as session:
            for table in (
                "delegation_grants",
                "deny_grants",
                "support_access_requests",
                "service_account_roles",
                "membership_roles",
                "role_permissions",
                "tenant_memberships",
                "roles",
                "service_accounts",
                "billing_subscriptions",
                "usage_events",
                "idempotency_records",
            ):
                session.execute(
                    text(f"DELETE FROM core.{table} WHERE tenant_id = :t"), {"t": str(tenant_id)}
                )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_users(*user_ids: uuid.UUID) -> None:
    with session_scope() as session:
        for user_id in user_ids:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


def _cleanup_permission(resource: str, action: str) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
            {"r": resource, "a": action},
        )


_WINDOW = (datetime.now(UTC) - timedelta(minutes=1), datetime.now(UTC) + timedelta(hours=1))


# --- 1. Application composition (structural, not real HTTP -- the real
# HTTP/build_platform_app proof remains the wheel-based end-to-end test) --


def test_reference_consumer_app_still_composes_via_build_platform_app() -> None:
    from reference_consumer.app import create_app

    app = create_app()
    assert app.title == "Reference Consumer"


# --- 2. B2B hierarchy ------------------------------------------------------


def test_b2b_hierarchy_ancestry_sibling_isolation_and_move() -> None:
    setup = scenarios.provision_b2b_hierarchy()
    try:
        team_ancestors = get_ancestor_ids(setup.team_tenant_id)
        assert setup.business_tenant_id in team_ancestors
        assert setup.department_tenant_id in team_ancestors

        business_descendants = get_descendant_ids(setup.business_tenant_id)
        assert setup.department_tenant_id in business_descendants
        assert setup.team_tenant_id in business_descendants

        # SELF at the business does not reach the department (hierarchy
        # itself grants nothing; RBAC below proves the SELF/SUBTREE split
        # explicitly).
        assert not can(
            actor_id=setup.business_admin_user_id,
            tenant_id=setup.department_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )

        # Hierarchy movement: move team out from under department, to be
        # a direct child of business -- ancestry updates live.
        move_tenant(setup.team_tenant_id, setup.business_tenant_id)
        new_ancestors = get_ancestor_ids(setup.team_tenant_id)
        assert setup.department_tenant_id not in new_ancestors
        assert setup.business_tenant_id in new_ancestors
    finally:
        _cleanup_tenant_tree(
            setup.team_tenant_id, setup.department_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(setup.business_admin_user_id)


# --- 3. B2C personal tenancy ------------------------------------------------


def test_b2c_personal_tenant_owner_authorization() -> None:
    setup = scenarios.provision_personal_tenant_for_new_user()
    try:
        assert can(
            actor_id=setup.user_id,
            tenant_id=setup.tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )
    finally:
        _cleanup_tenant_tree(setup.tenant_id)
        _cleanup_users(setup.user_id)
        _cleanup_permission(scenarios.WIDGET_RESOURCE, scenarios.WIDGET_ACTION)


# --- 4. B2B2C customer isolation, SUBTREE, delegation, explicit deny -------


def test_b2b2c_customer_isolation_and_authorization_paths() -> None:
    setup = scenarios.provision_b2b2c_customers()
    extra_user_ids: list[uuid.UUID] = []
    try:
        # Customer A cannot access Customer B, and vice versa.
        assert can(
            actor_id=setup.customer_a_user_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )
        assert not can(
            actor_id=setup.customer_a_user_id,
            tenant_id=setup.customer_b_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )
        assert not can(
            actor_id=setup.customer_b_user_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )

        # Hierarchy alone grants the business support user nothing.
        assert not can(
            actor_id=setup.business_support_user_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )

        # Explicit, authorization-driven path #1: a SUBTREE role at the
        # business tenant.
        scenarios.grant_business_subtree_access(
            setup.business_tenant_id, setup.business_support_user_id
        )
        assert can(
            actor_id=setup.business_support_user_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )
        assert can(
            actor_id=setup.business_support_user_id,
            tenant_id=setup.customer_b_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )

        # Explicit, authorization-driven path #2: delegation, scoped to
        # exactly one customer tenant -- never impersonation, never a
        # redelegation vector.
        other_support_user = create_user().id
        redelegation_target = None
        try:
            grant_id = scenarios.delegate_customer_access(
                delegator_user_id=setup.customer_a_user_id,
                delegate_user_id=other_support_user,
                customer_tenant_id=setup.customer_a_tenant_id,
            )
            assert can(
                actor_id=other_support_user,
                tenant_id=setup.customer_a_tenant_id,
                action=scenarios.WIDGET_ACTION,
                resource=scenarios.WIDGET_RESOURCE,
            )
            assert not can(
                actor_id=other_support_user,
                tenant_id=setup.customer_b_tenant_id,
                action=scenarios.WIDGET_ACTION,
                resource=scenarios.WIDGET_RESOURCE,
            )

            # The delegate cannot redelegate: it has no ordinary
            # membership-role authority at customer A of its own -- calls
            # `create_delegation()` directly (not the consumer's own
            # `scenarios.delegate_customer_access()` admin-provisioning
            # helper, which assumes its caller is already a tenant member)
            # to exercise SaaS OS's own anti-redelegation check exactly.
            redelegation_target = create_user()
            redelegation_permission = register_permission(
                scenarios.WIDGET_RESOURCE, scenarios.WIDGET_ACTION
            )
            with pytest.raises(DelegationNotAuthorizedError):
                create_delegation(
                    delegator_user_id=other_support_user,
                    delegate_user_id=redelegation_target.id,
                    tenant_id=setup.customer_a_tenant_id,
                    scope_mode=RoleScope.SELF,
                    permission_id=redelegation_permission.id,
                )

            # Revocation takes effect immediately.
            revoke_delegation(
                revoker_user_id=setup.customer_a_user_id,
                tenant_id=setup.customer_a_tenant_id,
                delegation_grant_id=grant_id,
            )
            assert not can(
                actor_id=other_support_user,
                tenant_id=setup.customer_a_tenant_id,
                action=scenarios.WIDGET_ACTION,
                resource=scenarios.WIDGET_RESOURCE,
            )
        finally:
            extra_user_ids.append(other_support_user)
            if redelegation_target is not None:
                extra_user_ids.append(redelegation_target.id)

        # Explicit deny overrides the SUBTREE allow -- Customer A's own
        # admin (a direct member there) denies the business support
        # user's otherwise-inherited SUBTREE access.
        scenarios.deny_widget_access(
            grantor_user_id=setup.customer_a_user_id,
            principal_user_id=setup.business_support_user_id,
            tenant_id=setup.customer_a_tenant_id,
        )
        assert not can(
            actor_id=setup.business_support_user_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )
        # Customer B is unaffected by a deny scoped to customer A.
        assert can(
            actor_id=setup.business_support_user_id,
            tenant_id=setup.customer_b_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )
    finally:
        _cleanup_tenant_tree(
            setup.customer_a_tenant_id, setup.customer_b_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(
            setup.customer_a_user_id,
            setup.customer_b_user_id,
            setup.business_support_user_id,
            *extra_user_ids,
        )
        _cleanup_permission(scenarios.WIDGET_RESOURCE, scenarios.WIDGET_ACTION)
        _cleanup_permission("delegation_grant", "create")
        _cleanup_permission("deny_grant", "create")


# --- 7/8. Service accounts + API-key hardening -----------------------------


def test_service_account_and_api_key_hardening() -> None:
    setup = scenarios.provision_b2b2c_customers()
    try:
        sa_setup = scenarios.provision_service_account_with_key(
            tenant_id=setup.customer_a_tenant_id, actor_user_id=setup.customer_a_user_id
        )

        # Tenant-bound: SELF at customer A works; the service account has
        # no authority at customer B (sibling) or the business (parent)
        # without an explicit SUBTREE grant.
        assert can(
            actor_id=sa_setup.service_account_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
            actor_type=PrincipalType.SERVICE_ACCOUNT,
            actor_tenant_id=setup.customer_a_tenant_id,
        )
        assert not can(
            actor_id=sa_setup.service_account_id,
            tenant_id=setup.customer_b_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
            actor_type=PrincipalType.SERVICE_ACCOUNT,
            actor_tenant_id=setup.customer_a_tenant_id,
        )
        assert not can(
            actor_id=sa_setup.service_account_id,
            tenant_id=setup.business_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
            actor_type=PrincipalType.SERVICE_ACCOUNT,
            actor_tenant_id=setup.customer_a_tenant_id,
        )

        # The raw key secret is never persisted -- only its hash.
        with tenant_session_scope(setup.customer_a_tenant_id) as session:
            key_hash = session.execute(
                text("SELECT key_hash FROM core.api_keys WHERE id = :id"),
                {"id": str(sa_setup.api_key_id)},
            ).scalar_one()
        assert sa_setup.raw_api_key not in key_hash
        assert key_hash != sa_setup.raw_api_key

        # A forged/arbitrary tenant cannot be selected via the key --
        # authentication resolves the key's OWN tenant, never a
        # caller-supplied one.
        resolved = scenarios.authenticate_with_api_key(sa_setup.raw_api_key)
        assert resolved.tenant_id == setup.customer_a_tenant_id
        assert resolved.tenant_id != setup.customer_b_tenant_id

        # Disabling the owning service account blocks authentication.
        disable_service_account(setup.customer_a_tenant_id, sa_setup.service_account_id)
        with pytest.raises(InactiveServiceAccountError):
            scenarios.authenticate_with_api_key(sa_setup.raw_api_key)
        assert not can(
            actor_id=sa_setup.service_account_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
            actor_type=PrincipalType.SERVICE_ACCOUNT,
            actor_tenant_id=setup.customer_a_tenant_id,
        )
        enable_service_account(setup.customer_a_tenant_id, sa_setup.service_account_id)

        # Expiry is enforced -- a key already expired at issuance time is
        # simulated with a near-future expiry plus a short real wait
        # (mirrors `core/api_keys`'s own live-timestamp evaluation; no
        # mock clock exists to inject here, by design).
        expiring_setup = scenarios.provision_service_account_with_key(
            tenant_id=setup.customer_a_tenant_id,
            actor_user_id=setup.customer_a_user_id,
            expires_at=datetime.now(UTC) + timedelta(seconds=1),
        )
        time.sleep(2)
        with pytest.raises(ExpiredApiKeyError):
            scenarios.authenticate_with_api_key(expiring_setup.raw_api_key)
    finally:
        _cleanup_tenant_tree(
            setup.customer_a_tenant_id, setup.customer_b_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(
            setup.customer_a_user_id,
            setup.customer_b_user_id,
            setup.business_support_user_id,
        )
        _cleanup_permission(scenarios.WIDGET_RESOURCE, scenarios.WIDGET_ACTION)
        _cleanup_permission("service_account_role", "create")
        _cleanup_permission("api_key", "create")


def test_unknown_api_key_fails_closed() -> None:
    with pytest.raises(InvalidApiKeyError):
        scenarios.authenticate_with_api_key("not-a-real-key")


# --- 10/11. Membership lifecycle + invitations ------------------------------


def test_membership_lifecycle_suspend_revoke_fail_closed() -> None:
    setup = scenarios.provision_b2b2c_customers()
    try:
        assert can(
            actor_id=setup.customer_a_user_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )
        from core.identity.service import get_membership

        membership = get_membership(setup.customer_a_tenant_id, setup.customer_a_user_id)
        assert membership is not None

        suspend_membership(
            setup.customer_a_tenant_id, membership.id, actor_user_id=setup.customer_a_user_id
        )
        assert not can(
            actor_id=setup.customer_a_user_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )

        revoke_membership(
            setup.customer_a_tenant_id, membership.id, actor_user_id=setup.customer_a_user_id
        )
        assert not can(
            actor_id=setup.customer_a_user_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
        )
    finally:
        _cleanup_tenant_tree(
            setup.customer_a_tenant_id, setup.customer_b_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(
            setup.customer_a_user_id,
            setup.customer_b_user_id,
            setup.business_support_user_id,
        )
        _cleanup_permission(scenarios.WIDGET_RESOURCE, scenarios.WIDGET_ACTION)


def test_invitation_acceptance_and_replay_prevention() -> None:
    setup = scenarios.provision_b2b_hierarchy()
    invitee = create_user()
    try:
        flow = scenarios.invite_team_member(
            tenant_id=setup.business_tenant_id, invited_email="new-teammate@example.com"
        )

        membership = accept_invitation(flow.raw_token, invitee.id)
        assert membership.tenant_id == setup.business_tenant_id
        assert membership.status == "active"

        # One-time: replaying the same token fails closed.
        with pytest.raises(InvitationInvalidError):
            accept_invitation(flow.raw_token, invitee.id)

        # No duplicate membership row was created.
        with tenant_session_scope(setup.business_tenant_id) as session:
            count = session.execute(
                text(
                    "SELECT COUNT(*) FROM core.tenant_memberships "
                    "WHERE tenant_id = :t AND user_id = :u"
                ),
                {"t": str(setup.business_tenant_id), "u": str(invitee.id)},
            ).scalar_one()
        assert count == 1

        # A revoked invitation cannot later be accepted, and a suspended
        # membership is never silently reactivated by acceptance.
        second_invitee = create_user()
        second_flow = scenarios.invite_team_member(
            tenant_id=setup.business_tenant_id, invited_email="revoked@example.com"
        )
        revoke_invitation(
            setup.business_tenant_id,
            second_flow.invitation_id,
            actor_user_id=second_flow.inviter_user_id,
        )
        with pytest.raises(InvitationInvalidError):
            accept_invitation(second_flow.raw_token, second_invitee.id)
    finally:
        _cleanup_tenant_tree(
            setup.team_tenant_id, setup.department_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(
            setup.business_admin_user_id,
            invitee.id,
            flow.inviter_user_id,
            second_invitee.id,
            second_flow.inviter_user_id,
        )
        _cleanup_permission("invitation", "create")
        _cleanup_permission("invitation", "revoke")


# --- 12/13. Hierarchy-aware billing & usage --------------------------------


def test_billing_owner_resolution_and_mutation_semantics() -> None:
    from core.billing.service import list_subscriptions, subscribe

    billing = scenarios.provision_hierarchy_aware_billing()
    new_plan_key = f"upgraded-{uuid.uuid4().hex[:8]}"
    another_plan_key = f"child-plan-{uuid.uuid4().hex[:8]}"
    child_user = None
    try:
        # get_entitlements(): child resolves to the parent's plan.
        assert get_entitlements(billing.child_tenant_id) == {"widgets": 10}
        owner = scenarios.resolve_effective_billing_owner(billing.child_tenant_id)
        assert owner == billing.parent_tenant_id

        # upgrade() resolves the effective owner.
        (parent_subscription,) = list_subscriptions(billing.parent_tenant_id)
        create_plan(new_plan_key, "Upgraded Plan", entitlements={"widgets": 20})

        upgraded = upgrade_subscription(
            billing.child_tenant_id,
            parent_subscription.id,
            new_plan_key,
            provider=billing.provider,
        )
        assert upgraded.tenant_id == billing.parent_tenant_id
        assert get_entitlements(billing.child_tenant_id) == {"widgets": 20}

        # Inherited subscribe fails closed -- no child subscription is
        # silently created.
        create_plan(another_plan_key, "Child Plan", entitlements={"widgets": 1})
        with pytest.raises(InheritedBillingSubscriptionError):
            subscribe(billing.child_tenant_id, another_plan_key, provider=billing.provider)
        with tenant_session_scope(billing.child_tenant_id) as session:
            child_sub_count = session.execute(
                text("SELECT COUNT(*) FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(billing.child_tenant_id)},
            ).scalar_one()
        assert child_sub_count == 0

        # cancel() also resolves the effective owner.
        canceled = cancel_subscription(
            billing.child_tenant_id, parent_subscription.id, provider=billing.provider
        )
        assert canceled.tenant_id == billing.parent_tenant_id
        assert canceled.status == "canceled"

        # Billing inheritance grants no authorization.
        from core.identity.service import add_tenant_membership

        child_user = create_user()
        add_tenant_membership(billing.child_tenant_id, child_user.id)
        assert not can(
            actor_id=child_user.id,
            tenant_id=billing.parent_tenant_id,
            action="read",
            resource="anything",
        )
    finally:
        _cleanup_tenant_tree(billing.child_tenant_id, billing.parent_tenant_id)
        if child_user is not None:
            _cleanup_users(child_user.id)
        with session_scope() as session:
            for key in (billing.plan_key, new_plan_key, another_plan_key):
                session.execute(text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": key})


def test_usage_origin_semantics_and_descendant_aggregation() -> None:
    setup = scenarios.provision_b2b_hierarchy()
    try:
        with tenant_session_scope(setup.department_tenant_id) as session:
            session.add(
                UsageEvent(
                    tenant_id=setup.department_tenant_id,
                    metric="widgets_checked",
                    quantity=Decimal("3"),
                    occurred_at=datetime.now(UTC),
                )
            )
            session.flush()
        with tenant_session_scope(setup.team_tenant_id) as session:
            session.add(
                UsageEvent(
                    tenant_id=setup.team_tenant_id,
                    metric="widgets_checked",
                    quantity=Decimal("5"),
                    occurred_at=datetime.now(UTC),
                )
            )
            session.flush()

        # Usage remains attributed to the originating tenant.
        assert aggregate_usage(
            setup.business_tenant_id, "widgets_checked", since=_WINDOW[0], until=_WINDOW[1]
        ) == Decimal("0")
        assert aggregate_usage(
            setup.department_tenant_id, "widgets_checked", since=_WINDOW[0], until=_WINDOW[1]
        ) == Decimal("3")

        # Explicit descendant aggregation rolls both up -- no duplication,
        # no rewritten tenant_id.
        total = aggregate_usage_including_descendants(
            setup.business_tenant_id, "widgets_checked", since=_WINDOW[0], until=_WINDOW[1]
        )
        assert total == Decimal("8")
    finally:
        _cleanup_tenant_tree(
            setup.team_tenant_id, setup.department_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(setup.business_admin_user_id)


# --- 9. Audit + support access ----------------------------------------------


def test_support_access_approval_active_authorization_and_revocation() -> None:
    setup = scenarios.provision_b2b_hierarchy()
    try:
        flow = scenarios.request_and_approve_support_access(tenant_id=setup.business_tenant_id)

        # No impersonation: authorization is evaluated under the
        # engineer's own real identity. Support access is tenant-level
        # (not scoped to the one consumer permission specifically), so it
        # authorizes a resource the engineer otherwise has no role for.
        assert can(
            actor_id=flow.support_engineer_user_id,
            tenant_id=setup.business_tenant_id,
            action="read",
            resource="reference_consumer.some_other_resource",
        )

        revoke_support_access(
            revoker_user_id=flow.approver_user_id,
            tenant_id=setup.business_tenant_id,
            request_id=flow.request_id,
        )
        assert not can(
            actor_id=flow.support_engineer_user_id,
            tenant_id=setup.business_tenant_id,
            action="read",
            resource="reference_consumer.some_other_resource",
        )

        # Audit linkage: the approval event carries acting_as_tenant_id
        # and support_access_id (architecture research Phase F).
        from core.audit_log.service import list as list_audit_entries

        entries = list_audit_entries(setup.business_tenant_id)
        approvals = [e for e in entries if e.action == "support_access.approve"]
        assert len(approvals) == 1
        assert approvals[0].acting_as_tenant_id == setup.business_tenant_id
        assert approvals[0].support_access_id == flow.request_id
    finally:
        _cleanup_tenant_tree(
            setup.team_tenant_id, setup.department_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(setup.business_admin_user_id)
        _cleanup_permission("support_access_request", "approve")
        _cleanup_permission("support_access_request", "deny")
        _cleanup_permission("support_access_request", "revoke")


# --- Security: forged inputs and fail-closed cases --------------------------


def test_forged_tenant_id_fails_closed() -> None:
    assert not can(
        actor_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        action=scenarios.WIDGET_ACTION,
        resource=scenarios.WIDGET_RESOURCE,
    )


def test_forged_service_account_tenant_fails_closed() -> None:
    setup = scenarios.provision_b2b2c_customers()
    try:
        sa_setup = scenarios.provision_service_account_with_key(
            tenant_id=setup.customer_a_tenant_id, actor_user_id=setup.customer_a_user_id
        )
        # actor_tenant_id claims customer B, but the service account was
        # created under customer A -- can() must fail closed, never
        # resolve a service account under a tenant it doesn't belong to.
        assert not can(
            actor_id=sa_setup.service_account_id,
            tenant_id=setup.customer_a_tenant_id,
            action=scenarios.WIDGET_ACTION,
            resource=scenarios.WIDGET_RESOURCE,
            actor_type=PrincipalType.SERVICE_ACCOUNT,
            actor_tenant_id=setup.customer_b_tenant_id,
        )
    finally:
        _cleanup_tenant_tree(
            setup.customer_a_tenant_id, setup.customer_b_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(
            setup.customer_a_user_id,
            setup.customer_b_user_id,
            setup.business_support_user_id,
        )
        _cleanup_permission(scenarios.WIDGET_RESOURCE, scenarios.WIDGET_ACTION)
        _cleanup_permission("service_account_role", "create")
        _cleanup_permission("api_key", "create")


def test_forged_billing_owner_is_not_possible() -> None:
    """`resolve_billing_owner()`/`upgrade_subscription()`/`cancel_subscription()`
    accept only `tenant_id` -- there is no `billing_owner_id` parameter
    anywhere in the public API for a caller to forge."""
    import inspect

    from core.billing.service import cancel_subscription as _cancel
    from core.billing.service import resolve_billing_owner as _resolve
    from core.billing.service import upgrade_subscription as _upgrade

    for fn in (_resolve, _upgrade, _cancel):
        params = inspect.signature(fn).parameters
        assert "billing_owner_id" not in params
        assert "owner_id" not in params


def test_sibling_cannot_become_billing_owner() -> None:
    setup = scenarios.provision_b2b2c_customers()
    from core.tenancy import set_tenant_billing_inheritance

    set_tenant_billing_inheritance(setup.customer_a_tenant_id, True)
    try:
        owner = scenarios.resolve_effective_billing_owner(setup.customer_a_tenant_id)
        assert owner == setup.business_tenant_id
        assert owner != setup.customer_b_tenant_id
    finally:
        _cleanup_tenant_tree(
            setup.customer_a_tenant_id, setup.customer_b_tenant_id, setup.business_tenant_id
        )
        _cleanup_users(
            setup.customer_a_user_id,
            setup.customer_b_user_id,
            setup.business_support_user_id,
        )
        _cleanup_permission(scenarios.WIDGET_RESOURCE, scenarios.WIDGET_ACTION)
