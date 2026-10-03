"""Phase 5.3 step 1 -- billing authority convergence, against a real
PostgreSQL instance (docs/ADR/0031-foundation-authority-and-evidence.md and
docs/ADR/0029-commercial-parties-and-billing-relationships.md, both
"Amendment (2026-10-02)").

What these tests pin:

- **Support boundary.** An approved support-access grant still satisfies
  billing *reads*, and never a billing *mutation* -- at `can()` and at
  every billing mutation entry point. Negative controls show the same
  mutations are allowed to an ordinary role holder, and that the reads
  really come from the grant.
- **Caller model.** `UserCaller` is authorized by `can()`;
  `SystemCaller(BILLING_OPERATIONS)` is the only accepted system purpose;
  other purposes and service accounts are refused; the deprecated callers
  map onto those types.
- **One transaction.** Authorization, mutation and audit share one
  transaction: a rolled-back mutation leaves no audit entry, and an
  authorization revoked between the provider call and the final
  transaction refuses the mutation.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import core.identity.models  # noqa: F401  (registers core.users for audit FKs)
import pytest
from core.authority import ServiceAccountCaller, SystemAuthority, SystemCaller, UserCaller
from core.billing.authorization import BillingActor, trusted_system
from core.billing.catalog import create_owned_plan
from core.billing.commercial import (
    cancel_commercial_subscription,
    create_subscription,
    reconcile_subscription_status,
)
from core.billing.errors import (
    BillingActorRequiredError,
    BillingNotAuthorizedError,
    SubscriptionNotFoundError,
)
from core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
    list_merchant_accounts,
    set_merchant_account_status,
)
from core.billing.provider import FakeBillingProvider, ProviderSubscriptionState
from core.billing.service import create_plan, get_subscription
from core.identity.service import add_tenant_membership, create_user
from core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
    create_deny,
    create_role,
    create_support_access_request,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.billing import authorization, commercial, parties
from core.identity import get_membership
from core.rbac import RoleScope, can
from core.tenancy import TenantStatus, create_tenant, get_tenancy_config, transition_tenant_status

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)

_BILLING_READS = (
    ("billing.subscription", "read"),
    ("billing.account", "read"),
    ("billing.catalog", "read"),
    ("billing.invoice", "read"),
)
_BILLING_MUTATIONS = (
    ("billing.subscription", "create"),
    ("billing.subscription", "change"),
    ("billing.subscription", "cancel"),
    ("billing.subscription", "reactivate"),
    ("billing.account", "charge"),
    ("billing.account", "manage"),
    ("billing.catalog", "manage"),
    ("billing.merchant", "manage"),
)


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.billing_merchant_accounts LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"Billing tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe_engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.plan_keys: list[str] = []

    def tenant(self, label: str) -> uuid.UUID:
        tenant = create_tenant(_unique(label))
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(self) -> uuid.UUID:
        user = create_user()
        self.user_ids.append(user.id)
        return user.id

    def plan(self) -> str:
        key = _unique("s1-plan")
        create_plan(key, "Step 1 plan", entitlements={"seats": 1})
        self.plan_keys.append(key)
        return key

    def grant(self, tenant_id: uuid.UUID, user_id: uuid.UUID, permissions) -> None:  # type: ignore[no-untyped-def]
        membership = get_membership(tenant_id, user_id)
        if membership is None:
            membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
        for resource, action in permissions:
            grant_permission(
                tenant_id, role.id, register_permission(resource, action).id, caller=_PROVISIONING
            )
        assign_first_role_for_new_tenant(
            tenant_id, membership.id, role.id, scope=RoleScope.SELF, caller=_PROVISIONING
        )

    def support_grant(self, tenant_id: uuid.UUID, *, approve: bool = True) -> uuid.UUID:
        """A support engineer holding an approved (or merely requested),
        currently-valid support grant at `tenant_id`, and nothing else."""
        approver, engineer = self.user(), self.user()
        self.grant(tenant_id, approver, [("support_access_request", "approve")])
        request = create_support_access_request(
            caller=UserCaller(engineer),
            tenant_id=tenant_id,
            reason="phase 5.3 step 1 billing boundary",
            requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        if approve:
            approve_support_access(
                caller=UserCaller(approver), tenant_id=tenant_id, request_id=request.id
            )
        return engineer

    def cleanup(self) -> None:
        tenants = [str(t) for t in self.tenant_ids]
        users = [str(u) for u in self.user_ids]
        engine = build_engine(get_migrations_database_config())
        try:
            factory = build_session_factory(engine)
            with session_scope(session_factory=factory) as session:
                for statement in (
                    "DELETE FROM core.audit_log WHERE tenant_id = ANY(:t) "
                    "OR actor_user_id = ANY(:u)",
                    "DELETE FROM core.outbox_consumptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.outbox_events WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_seller_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_payer_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.idempotency_records WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_provider_refs WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plan_offers WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plans WHERE owner_tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_merchant_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.support_access_requests WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.deny_grants WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
                    "DELETE FROM core.tenants WHERE id = ANY(:t)",
                    "DELETE FROM core.billing_plans WHERE key = ANY(:k)",
                    "DELETE FROM core.users WHERE id = ANY(:u)",
                ):
                    session.execute(
                        text(statement), {"t": tenants, "u": users, "k": self.plan_keys}
                    )
        finally:
            engine.dispose()


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


def _admin_rows(sql: str, **params: object) -> list:  # type: ignore[type-arg]
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return list(conn.execute(text(sql), params).all())
    finally:
        engine.dispose()


def _audit(tenant_id: uuid.UUID, action: str) -> list:  # type: ignore[type-arg]
    return _admin_rows(
        "SELECT actor_type, actor_user_id, resource_id, metadata AS meta FROM core.audit_log "
        "WHERE tenant_id = :t AND action = :a",
        t=str(tenant_id),
        a=action,
    )


def _merchant(caller: object, tenant_id: uuid.UUID, **kwargs: object):  # type: ignore[no-untyped-def]
    return create_merchant_account(
        caller,
        tenant_id,
        provider="fake",
        provider_account_ref=_unique("acct"),
        status=kwargs.get("status", MerchantAccountStatus.ACTIVE),  # type: ignore[arg-type]
    )


@dataclass
class _Commercial:
    """A platform merchant, a self-paying service tenant with a verified
    subscription, and the provider that holds it."""

    tenant_id: uuid.UUID
    subscription_id: uuid.UUID
    provider: FakeBillingProvider


@pytest.fixture
def commercial_world(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[_World, _Commercial]]:
    platform = world.tenant("platform")
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(platform))
    get_tenancy_config.cache_clear()
    merchant = _merchant(_BILLING_SYSTEM, platform)
    service = world.tenant("service")
    account, _ = get_or_create_billing_account(
        _BILLING_SYSTEM, service, merchant_tenant_id=platform, merchant_account_id=merchant.id
    )
    provider = FakeBillingProvider()
    _, result = create_subscription(
        _BILLING_SYSTEM,
        service_tenant_id=service,
        payer_tenant_id=service,
        billing_account_id=account.id,
        plan_id=create_owned_plan(
            _BILLING_SYSTEM,
            platform,
            merchant_account_id=merchant.id,
            key=_unique("s1-plan"),
            name="Step 1 plan",
        ).id,
        idempotency_key=_unique("idem"),
        provider=provider,
    )
    yield world, _Commercial(service, result.subscription_id, provider)
    get_tenancy_config.cache_clear()


# --- Support boundary: reads yes, mutations never ------------------------------------


@pytest.mark.parametrize(("resource", "action"), _BILLING_READS)
def test_support_access_still_satisfies_billing_reads(
    world: _World, resource: str, action: str
) -> None:
    tenant = world.tenant("support-read")
    engineer = world.support_grant(tenant)
    assert can(actor_id=engineer, tenant_id=tenant, action=action, resource=resource)


@pytest.mark.parametrize(("resource", "action"), _BILLING_READS)
def test_billing_reads_come_from_the_grant_itself(
    world: _World, resource: str, action: str
) -> None:
    """Negative control for the test above: an unapproved request grants
    no read, so the allowed read really is the support grant's."""
    tenant = world.tenant("support-unapproved")
    engineer = world.support_grant(tenant, approve=False)
    assert not can(actor_id=engineer, tenant_id=tenant, action=action, resource=resource)


@pytest.mark.parametrize(("resource", "action"), _BILLING_MUTATIONS)
def test_support_access_never_satisfies_a_billing_mutation(
    world: _World, resource: str, action: str
) -> None:
    tenant = world.tenant("support-mutation")
    engineer = world.support_grant(tenant)
    assert not can(actor_id=engineer, tenant_id=tenant, action=action, resource=resource)


@pytest.mark.parametrize(("resource", "action"), _BILLING_MUTATIONS)
def test_the_same_mutations_are_allowed_to_an_ordinary_role_holder(
    world: _World, resource: str, action: str
) -> None:
    """Negative control: the denial above is the support boundary, not an
    unregistered or otherwise unreachable permission."""
    tenant = world.tenant("role-mutation")
    user = world.user()
    world.grant(tenant, user, [(resource, action)])
    assert can(actor_id=user, tenant_id=tenant, action=action, resource=resource)


def test_support_cannot_create_or_change_a_merchant(world: _World) -> None:
    tenant = world.tenant("support-merchant")
    engineer = world.support_grant(tenant)
    with pytest.raises(BillingNotAuthorizedError):
        _merchant(UserCaller(engineer), tenant)
    assert list_merchant_accounts(tenant) == []
    merchant = _merchant(_BILLING_SYSTEM, tenant)
    with pytest.raises(BillingNotAuthorizedError):
        set_merchant_account_status(
            UserCaller(engineer), tenant, merchant.id, MerchantAccountStatus.DISABLED
        )
    assert list_merchant_accounts(tenant)[0].status == MerchantAccountStatus.ACTIVE.value


def test_support_cannot_manage_a_billing_account(world: _World) -> None:
    payee, payer = world.tenant("payee"), world.tenant("support-payer")
    merchant = _merchant(_BILLING_SYSTEM, payee)
    engineer = world.support_grant(payer)
    with pytest.raises(BillingNotAuthorizedError):
        get_or_create_billing_account(
            UserCaller(engineer), payer, merchant_tenant_id=payee, merchant_account_id=merchant.id
        )
    assert _audit(payer, "billing.account_created") == []


def test_support_cannot_create_a_subscription_or_charge_an_account(world: _World) -> None:
    tenant = world.tenant("support-subscribe")
    engineer = world.support_grant(tenant)
    with pytest.raises(BillingNotAuthorizedError):
        create_subscription(
            UserCaller(engineer),
            service_tenant_id=tenant,
            payer_tenant_id=tenant,
            billing_account_id=uuid.uuid4(),
            plan_id=uuid.uuid4(),
            idempotency_key=_unique("idem"),
            provider=FakeBillingProvider(),
        )


def test_support_cannot_cancel_but_can_reconcile(
    commercial_world: tuple[_World, _Commercial],
) -> None:
    world, sub = commercial_world
    engineer = world.support_grant(sub.tenant_id)
    with pytest.raises(BillingNotAuthorizedError):
        cancel_commercial_subscription(
            UserCaller(engineer),
            service_tenant_id=sub.tenant_id,
            subscription_id=sub.subscription_id,
            provider=sub.provider,
        )
    row = get_subscription(sub.tenant_id, sub.subscription_id)
    assert row.status == "active"
    # Refused before the provider was touched.
    assert (
        sub.provider.get_subscription_status(provider_subscription_id=row.provider_subscription_id)
        is ProviderSubscriptionState.ACTIVE
    )
    # Reconciliation is authorized by `billing.subscription:read`, which a
    # support grant still satisfies; it applies only provider truth.
    result = reconcile_subscription_status(
        UserCaller(engineer),
        service_tenant_id=sub.tenant_id,
        subscription_id=sub.subscription_id,
        provider=sub.provider,
    )
    assert result.changed is False


# --- Caller model -------------------------------------------------------------------


def test_user_caller_is_authorized_by_can_and_audited_as_the_user(world: _World) -> None:
    tenant, user = world.tenant("user-merchant"), world.user()
    world.grant(tenant, user, [("billing.merchant", "manage")])
    merchant = _merchant(UserCaller(user), tenant)
    [row] = _audit(tenant, "billing.merchant_account_created")
    assert (row.actor_type, row.actor_user_id, row.resource_id) == ("user", user, str(merchant.id))


def test_unauthorized_user_is_refused_with_no_row_and_no_audit(world: _World) -> None:
    tenant, user = world.tenant("no-permission"), world.user()
    world.grant(tenant, user, [("billing.merchant", "read")])  # a read is not manage
    with pytest.raises(BillingNotAuthorizedError):
        _merchant(UserCaller(user), tenant)
    assert list_merchant_accounts(tenant) == []
    assert _audit(tenant, "billing.merchant_account_created") == []


def test_billing_system_authority_is_audited_with_its_typed_purpose(world: _World) -> None:
    tenant = world.tenant("system-merchant")
    _merchant(_BILLING_SYSTEM, tenant)
    [row] = _audit(tenant, "billing.merchant_account_created")
    assert row.actor_type == "system" and row.actor_user_id is None
    assert row.meta["system_authority"] == "billing_operations"


@pytest.mark.parametrize("purpose", [SystemAuthority.PROVISIONING, SystemAuthority.TENANT_PURGE])
def test_other_system_purposes_are_refused(world: _World, purpose: SystemAuthority) -> None:
    tenant = world.tenant("wrong-purpose")
    with pytest.raises(BillingNotAuthorizedError):
        _merchant(SystemCaller(purpose), tenant)
    assert list_merchant_accounts(tenant) == []


def test_service_account_callers_are_not_billing_callers(world: _World) -> None:
    tenant = world.tenant("service-account")
    with pytest.raises(BillingActorRequiredError):
        _merchant(ServiceAccountCaller(uuid.uuid4(), tenant), tenant)
    assert list_merchant_accounts(tenant) == []


def test_deprecated_billing_actor_is_exactly_a_user_caller(world: _World) -> None:
    tenant, user = world.tenant("compat-actor"), world.user()
    with pytest.raises(BillingNotAuthorizedError):
        _merchant(BillingActor.user(user), tenant)
    world.grant(tenant, user, [("billing.merchant", "manage")])
    _merchant(BillingActor.user(user), tenant)
    [row] = _audit(tenant, "billing.merchant_account_created")
    assert (row.actor_type, row.actor_user_id) == ("user", user)


def test_deprecated_trusted_system_routes_to_the_typed_purpose(world: _World) -> None:
    tenant = world.tenant("compat-system")
    with pytest.warns(DeprecationWarning):
        caller = trusted_system("provisioning")
    _merchant(caller, tenant)
    [row] = _audit(tenant, "billing.merchant_account_created")
    # The text names no authority: the purpose is the typed billing one.
    assert row.meta["system_authority"] == "billing_operations"
    assert row.meta["trusted_system_reason"] == "provisioning"


# --- Authorization, mutation and audit in one transaction ---------------------------


def test_authorization_and_audit_use_the_mutation_session(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant, user = world.tenant("one-session"), world.user()
    world.grant(tenant, user, [("billing.merchant", "manage")])
    seen: dict[str, list[int]] = {"can": [], "audit": []}
    real_can, real_record = authorization.can, authorization.record_in_transaction

    def spying_can(**kwargs):  # type: ignore[no-untyped-def]
        seen["can"].append(id(kwargs["session"]))
        return real_can(**kwargs)

    def spying_record(session, **kwargs):  # type: ignore[no-untyped-def]
        seen["audit"].append(id(session))
        return real_record(session, **kwargs)

    monkeypatch.setattr(authorization, "can", spying_can)
    monkeypatch.setattr(authorization, "record_in_transaction", spying_record)
    _merchant(UserCaller(user), tenant)
    assert len(seen["can"]) == 1 and seen["can"] == seen["audit"]


def test_a_rolled_back_mutation_leaves_no_audit_entry(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = world.tenant("rollback")
    real_audit = parties.record_billing_audit

    def audit_then_fail(*args, **kwargs):  # type: ignore[no-untyped-def]
        real_audit(*args, **kwargs)
        raise RuntimeError("simulated failure after the audit entry was written")

    monkeypatch.setattr(parties, "record_billing_audit", audit_then_fail)
    with pytest.raises(RuntimeError):
        _merchant(_BILLING_SYSTEM, tenant)
    assert list_merchant_accounts(tenant) == []
    assert _audit(tenant, "billing.merchant_account_created") == []


def test_authority_revoked_after_the_provider_call_refuses_the_final_transaction(
    commercial_world: tuple[_World, _Commercial], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cancel is authorized, the provider cancels, and then -- before
    the local write -- the caller is denied. The final transaction
    re-authorizes and refuses: no local cancellation, no audit entry. The
    provider's cancellation is not lost: reconciliation converges it."""
    world, sub = commercial_world
    user, grantor = world.user(), world.user()
    world.grant(sub.tenant_id, user, [("billing.subscription", "cancel")])
    world.grant(sub.tenant_id, grantor, [("deny_grant", "create")])
    real_cancel = commercial.cancel_at_provider

    def cancel_then_deny(provider, provider_subscription_id):  # type: ignore[no-untyped-def]
        real_cancel(provider, provider_subscription_id)
        create_deny(
            caller=UserCaller(grantor),
            principal_user_id=user,
            tenant_id=sub.tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=register_permission("billing.subscription", "cancel").id,
        )

    monkeypatch.setattr(commercial, "cancel_at_provider", cancel_then_deny)
    with pytest.raises(BillingNotAuthorizedError):
        cancel_commercial_subscription(
            UserCaller(user),
            service_tenant_id=sub.tenant_id,
            subscription_id=sub.subscription_id,
            provider=sub.provider,
        )
    assert get_subscription(sub.tenant_id, sub.subscription_id).status == "active"
    assert _audit(sub.tenant_id, "billing.subscription_canceled") == []

    converged = reconcile_subscription_status(
        _BILLING_SYSTEM,
        service_tenant_id=sub.tenant_id,
        subscription_id=sub.subscription_id,
        provider=sub.provider,
    )
    assert (converged.changed, converged.status) == (True, "canceled")


def test_creation_audit_is_written_with_the_pending_row(
    commercial_world: tuple[_World, _Commercial],
) -> None:
    _, sub = commercial_world
    [created] = _audit(sub.tenant_id, "billing.subscription_created")
    assert created.resource_id == str(sub.subscription_id)
    assert created.meta["status"] == "pending"
    [confirmed] = _audit(sub.tenant_id, "billing.subscription_status_changed")
    assert (confirmed.meta["previous_status"], confirmed.meta["status"]) == ("pending", "active")


def test_missing_subscription_is_not_found_once_authorized(
    commercial_world: tuple[_World, _Commercial],
) -> None:
    _, sub = commercial_world
    with pytest.raises(SubscriptionNotFoundError):
        cancel_commercial_subscription(
            _BILLING_SYSTEM,
            service_tenant_id=sub.tenant_id,
            subscription_id=uuid.uuid4(),
            provider=sub.provider,
        )
