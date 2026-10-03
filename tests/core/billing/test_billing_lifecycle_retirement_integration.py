"""Phase 5.3 step 5 -- lifecycle and `inherits_billing` retirement, against
a real PostgreSQL instance (docs/ADR/0029-..., "Amendment (2026-10-02)":
"`inherits_billing`: retired forward" and "Lifecycle and cancellation
authority").

Shape (generic tenants):

    Agency A (merchant mA, plan X: descendants)       Agency B (merchant mB)
      +-- Client B   subscribes itself, at mA
      +-- Client C   Agency A pays for it, at mA
      +-- Child L    a legacy tenant that still inherits billing

Pins: no new `inherits_billing = true` anywhere (database trigger), the
authorized and audited opt-out and sponsored migration, the cancellation
authority matrix (service tenant, payer, merchant; nobody else; support
never), the final re-authorization fence, projection events on
cancellation, and that withdrawing a plan cancels nothing.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import core.identity.models  # noqa: F401  (registers core.users for audit FKs)
import pytest
from core.audit_log.service import list as list_audit_entries
from core.authority import SystemAuthority, SystemCaller, UserCaller
from core.billing.catalog import PlanVisibility, create_owned_plan, withdraw_plan
from core.billing.commercial import (
    CancellationCapacity,
    cancel_commercial_subscription,
    create_subscription,
)
from core.billing.errors import (
    BillingAccountNotFoundError,
    BillingInheritanceMigrationError,
    BillingNotAuthorizedError,
    BillingProviderError,
    CommercialPartyNotActiveError,
    InheritedBillingSubscriptionError,
    PlanNotEligibleError,
)
from core.billing.inheritance import (
    migrate_inherited_tenant_to_sponsorship,
    opt_out_of_billing_inheritance,
)
from core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
)
from core.billing.projections import SUBSCRIPTION_CHANGED_EVENT_TYPE, project_subscription
from core.billing.provider import FakeBillingProvider, ProviderSubscriptionState
from core.billing.service import create_plan, get_entitlements, get_subscription, subscribe
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
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

from core.billing import commercial
from core.identity import get_membership
from core.rbac import RoleScope
from core.tenancy import TenantStatus, create_tenant, get_tenant, transition_tenant_status

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
_CHARGE = ("billing.account", "charge")
_CREATE = ("billing.subscription", "create")
_CHANGE = ("billing.subscription", "change")
_CANCEL = ("billing.subscription", "cancel")
_MERCHANT = ("billing.merchant", "manage")


@pytest.fixture(autouse=True)
def _require_reachable_database_with_the_retirement_trigger() -> None:
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
            found = conn.execute(
                text(
                    "SELECT 1 FROM pg_trigger "
                    "WHERE tgname = 'trg_tenants_refuse_new_billing_inheritance'"
                )
            ).first()
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    finally:
        probe_engine.dispose()
    if found is None:
        pytest.skip("retirement trigger missing -- run `alembic upgrade head`")


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _admin(sql: str, *, replica: bool = False, **params: object) -> list:  # type: ignore[type-arg]
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            if replica:
                conn.execute(text("SET LOCAL session_replication_role = replica"))
            result = conn.execute(text(sql), params)
            return list(result.all()) if result.returns_rows else []
    finally:
        engine.dispose()


def _seed_legacy_billing_inheritance(tenant_id: uuid.UUID) -> None:
    """A tenant that inherited billing before this step: seeded the way it
    pre-existed (privileged role, triggers suppressed for one transaction)."""
    _admin(
        "UPDATE core.tenants SET inherits_billing = true WHERE id = :t",
        replica=True,
        t=str(tenant_id),
    )


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.legacy_keys: list[str] = []

    def tenant(self, label: str, *, parent_id: uuid.UUID | None = None) -> uuid.UUID:
        tenant = create_tenant(_unique(label), parent_id=parent_id)
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(
        self, *grants: tuple[uuid.UUID, tuple[str, str]], scope: RoleScope = RoleScope.SELF
    ) -> UserCaller:
        user = create_user()
        self.user_ids.append(user.id)
        for tenant_id, permission in grants:
            membership = get_membership(tenant_id, user.id)
            if membership is None:
                membership = add_tenant_membership(tenant_id, user.id, caller=_PROVISIONING)
            role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
            grant_permission(
                tenant_id, role.id, register_permission(*permission).id, caller=_PROVISIONING
            )
            assign_first_role_for_new_tenant(
                tenant_id, membership.id, role.id, scope=scope, caller=_PROVISIONING
            )
        return UserCaller(user.id)

    def support_engineer(self, *tenant_ids: uuid.UUID) -> UserCaller:
        engineer = create_user()
        self.user_ids.append(engineer.id)
        for tenant_id in tenant_ids:
            approver = self.user((tenant_id, ("support_access_request", "approve")))
            request = create_support_access_request(
                caller=UserCaller(engineer.id),
                tenant_id=tenant_id,
                reason="step 5 boundary",
                requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
            approve_support_access(caller=approver, tenant_id=tenant_id, request_id=request.id)
        return UserCaller(engineer.id)

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
                    "DELETE FROM core.billing_plan_offers WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plans WHERE owner_tenant_id = ANY(:t) "
                    "OR key = ANY(:k)",
                    "DELETE FROM core.billing_accounts WHERE tenant_id = ANY(:t)",
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
                    "DELETE FROM core.users WHERE id = ANY(:u)",
                ):
                    session.execute(
                        text(statement), {"t": tenants, "u": users, "k": self.legacy_keys}
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


class _Market:
    def __init__(self, world: _World) -> None:
        self.world = world
        self.provider = FakeBillingProvider()
        self.agency_a, self.agency_b = world.tenant("agency-a"), world.tenant("agency-b")
        self.client_b = world.tenant("client-b", parent_id=self.agency_a)
        self.client_c = world.tenant("client-c", parent_id=self.agency_a)
        self.legacy_child = world.tenant("legacy-child", parent_id=self.agency_a)
        self.m_a, self.m_b = self._merchant(self.agency_a), self._merchant(self.agency_b)
        self.plan_x = self._plan(self.agency_a, self.m_a)
        self.acct_a = self.account(self.agency_a, self.agency_a, self.m_a)
        self.acct_b = self.account(self.client_b, self.agency_a, self.m_a)
        self.sub_b = self.create(self.client_b, self.client_b, self.acct_b)
        self.sub_c = self.create(self.client_c, self.agency_a, self.acct_a)

    def _merchant(self, owner: uuid.UUID) -> uuid.UUID:
        return create_merchant_account(
            _BILLING_SYSTEM,
            owner,
            provider="fake",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        ).id

    def _plan(self, owner: uuid.UUID, merchant: uuid.UUID) -> uuid.UUID:
        return create_owned_plan(
            _BILLING_SYSTEM,
            owner,
            merchant_account_id=merchant,
            key=_unique("plan"),
            name="Agency plan",
            entitlements={"seats": 4},
            visibility=PlanVisibility.DESCENDANTS,
        ).id

    def account(self, payer: uuid.UUID, owner: uuid.UUID, merchant: uuid.UUID) -> uuid.UUID:
        account, _ = get_or_create_billing_account(
            _BILLING_SYSTEM, payer, merchant_tenant_id=owner, merchant_account_id=merchant
        )
        return account.id

    def create(self, service: uuid.UUID, payer: uuid.UUID, account: uuid.UUID) -> uuid.UUID:
        _, result = create_subscription(
            _BILLING_SYSTEM,
            service_tenant_id=service,
            payer_tenant_id=payer,
            billing_account_id=account,
            plan_id=self.plan_x,
            idempotency_key=_unique("idem"),
            provider=self.provider,
        )
        return result.subscription_id

    def cancel(self, caller: object, service: uuid.UUID, sub: uuid.UUID, as_: CancellationCapacity):  # type: ignore[no-untyped-def]
        return cancel_commercial_subscription(
            caller,
            service_tenant_id=service,
            subscription_id=sub,
            provider=self.provider,
            acting_as=as_,
        )

    def migrate(self, caller: object, *, payer: uuid.UUID, account: uuid.UUID, **kwargs):  # type: ignore[no-untyped-def]
        return migrate_inherited_tenant_to_sponsorship(
            caller,
            service_tenant_id=kwargs.get("service", self.legacy_child),  # type: ignore[arg-type]
            payer_tenant_id=payer,
            billing_account_id=account,
            plan_id=kwargs.get("plan", self.plan_x),  # type: ignore[arg-type]
            idempotency_key=kwargs.get("key", _unique("migrate")),  # type: ignore[arg-type]
            provider=self.provider,
        )


@pytest.fixture
def market(world: _World) -> _Market:
    m = _Market(world)
    _seed_legacy_billing_inheritance(m.legacy_child)
    return m


def _audit(tenant_id: uuid.UUID, action: str) -> list:  # type: ignore[type-arg]
    return [e for e in list_audit_entries(tenant_id) if e.action == action]


def _status(service: uuid.UUID, sub: uuid.UUID) -> str:
    return get_subscription(service, sub).status


def _subscriptions(tenant_id: uuid.UUID) -> int:
    with tenant_session_scope(tenant_id) as session:
        return session.execute(text("SELECT count(*) FROM core.billing_subscriptions")).scalar_one()


# --- The forward rule: no new inheritance, anywhere ---------------------------------


def test_the_database_refuses_any_new_inheritance(world: _World) -> None:
    tenant = world.tenant("flat")
    for sql in (
        "UPDATE core.tenants SET inherits_billing = true WHERE id = :t",
        "INSERT INTO core.tenants (id, name, status, inherits_billing) "
        "VALUES (gen_random_uuid(), 'x', 'active', true)",
    ):
        # Not even the privileged role can create one.
        with pytest.raises(DBAPIError, match="inherits_billing = true is retired"):
            _admin(sql, t=str(tenant))
        # Nor the application role.
        with pytest.raises(DBAPIError), tenant_session_scope(tenant) as session:
            session.execute(text(sql), {"t": str(tenant)})
    assert get_tenant(tenant).inherits_billing is False


def test_an_existing_inheriting_tenant_stays_readable_and_updatable(market: _Market) -> None:
    tenant = get_tenant(market.legacy_child)
    assert tenant.inherits_billing is True
    # Unrelated updates of the row, and re-asserting true, are unaffected.
    _admin("UPDATE core.tenants SET name = name WHERE id = :t", t=str(market.legacy_child))
    _admin(
        "UPDATE core.tenants SET inherits_billing = true WHERE id = :t",
        t=str(market.legacy_child),
    )
    assert get_tenant(market.legacy_child).inherits_billing is True


# --- Opt-out --------------------------------------------------------------------------


def test_an_authorized_opt_out_is_audited_and_final(world: _World, market: _Market) -> None:
    caller = world.user((market.legacy_child, _CHANGE))
    tenant = opt_out_of_billing_inheritance(caller, market.legacy_child)
    assert tenant.inherits_billing is False
    [entry] = _audit(market.legacy_child, "billing.inheritance_opted_out")
    assert entry.actor_user_id == caller.user_id
    assert entry.resource_id == str(market.legacy_child)
    assert entry.entry_metadata == {"previous_inherits_billing": True, "inherits_billing": False}
    # No forward path back to true.
    with pytest.raises(DBAPIError):
        _admin(
            "UPDATE core.tenants SET inherits_billing = true WHERE id = :t",
            t=str(market.legacy_child),
        )
    # Idempotent: a tenant that no longer inherits is returned unchanged.
    opt_out_of_billing_inheritance(caller, market.legacy_child)
    assert len(_audit(market.legacy_child, "billing.inheritance_opted_out")) == 1


def test_opting_out_makes_the_tenant_its_own_owner(market: _Market) -> None:
    assert get_entitlements(market.legacy_child) == {}  # the agency itself subscribes to nothing
    opt_out_of_billing_inheritance(_BILLING_SYSTEM, market.legacy_child)
    assert get_entitlements(market.legacy_child) == {}
    assert _subscriptions(market.legacy_child) == 0  # nothing was created


@pytest.mark.parametrize("who", ["reader", "parent_admin", "support", "provisioning"])
def test_an_unauthorized_opt_out_changes_nothing(world: _World, market: _Market, who: str) -> None:
    caller = {
        "reader": lambda: world.user((market.legacy_child, ("billing.subscription", "read"))),
        # Authority at the ancestor is not authority over the child's billing.
        "parent_admin": lambda: world.user((market.agency_a, _CHANGE)),
        "support": lambda: world.support_engineer(market.legacy_child),
        "provisioning": lambda: _PROVISIONING,
    }[who]()
    with pytest.raises(BillingNotAuthorizedError):
        opt_out_of_billing_inheritance(caller, market.legacy_child)
    assert get_tenant(market.legacy_child).inherits_billing is True
    assert _audit(market.legacy_child, "billing.inheritance_opted_out") == []


def test_legacy_mutations_of_an_inheriting_tenant_fail_closed(market: _Market) -> None:
    from core.billing.service import cancel_subscription, upgrade_subscription

    key = _unique("legacy")
    market.world.legacy_keys.append(key)
    create_plan(key, "Legacy")
    for attempt in (
        lambda: subscribe(market.legacy_child, key, provider=market.provider),
        lambda: upgrade_subscription(
            market.legacy_child, market.sub_c, key, provider=market.provider
        ),
        lambda: cancel_subscription(market.legacy_child, market.sub_c, provider=market.provider),
    ):
        with pytest.raises(InheritedBillingSubscriptionError):
            attempt()
    assert _status(market.client_c, market.sub_c) == "active"


# --- Sponsored migration --------------------------------------------------------------


def _migrator(world: _World, market: _Market) -> UserCaller:
    """An agency admin holding, on its subtree, every authority the
    migration needs: charge (payer), create and change (service tenant)."""
    return world.user((market.agency_a, _CHARGE), scope=RoleScope.SELF) and world.user(
        (market.agency_a, _CHARGE),
        (market.agency_a, _CREATE),
        (market.agency_a, _CHANGE),
        scope=RoleScope.SUBTREE,
    )


def test_an_authorized_migration_sponsors_the_tenant_and_ends_inheritance(
    world: _World, market: _Market
) -> None:
    caller = _migrator(world, market)
    _, result = market.migrate(caller, payer=market.agency_a, account=market.acct_a)
    row = get_subscription(market.legacy_child, result.subscription_id)
    assert (
        row.tenant_id,
        row.payer_tenant_id,
        row.billing_account_id,
        row.merchant_account_id,
    ) == (
        market.legacy_child,
        market.agency_a,
        market.acct_a,
        market.m_a,
    )
    assert get_tenant(market.legacy_child).inherits_billing is False
    assert get_entitlements(market.legacy_child) == {"seats": 4}
    [migrated] = _audit(market.legacy_child, "billing.inheritance_migrated")
    assert migrated.actor_user_id == caller.user_id
    assert migrated.entry_metadata is not None
    assert migrated.entry_metadata["subscription_id"] == str(result.subscription_id)
    assert migrated.entry_metadata["payer_tenant_id"] == str(market.agency_a)
    assert migrated.entry_metadata["previous_inherits_billing"] is True
    assert not any("provider" in key for key in migrated.entry_metadata)
    assert len(_audit(market.legacy_child, "billing.subscription_created")) == 1


def test_the_payer_is_whoever_is_named_never_the_former_billing_ancestor(
    world: _World, market: _Market
) -> None:
    # The child pays for itself: nothing about Agency A is inferred.
    own_account = market.account(market.legacy_child, market.agency_a, market.m_a)
    caller = world.user(
        (market.legacy_child, _CHARGE),
        (market.legacy_child, _CREATE),
        (market.legacy_child, _CHANGE),
    )
    _, result = market.migrate(caller, payer=market.legacy_child, account=own_account)
    row = get_subscription(market.legacy_child, result.subscription_id)
    assert row.payer_tenant_id == market.legacy_child


def test_migration_validates_the_named_payer_account_and_merchant(
    world: _World, market: _Market
) -> None:
    caller = _migrator(world, market)
    # The account must be the payer's own...
    with pytest.raises(BillingAccountNotFoundError):
        market.migrate(caller, payer=market.agency_a, account=market.acct_b)
    # ...active...
    _admin(
        "UPDATE core.billing_accounts SET status = 'disabled' WHERE id = :a", a=str(market.acct_a)
    )
    with pytest.raises(CommercialPartyNotActiveError):
        market.migrate(caller, payer=market.agency_a, account=market.acct_a)
    _admin("UPDATE core.billing_accounts SET status = 'active' WHERE id = :a", a=str(market.acct_a))
    # ...and at the plan's merchant.
    plan_b = create_owned_plan(
        _BILLING_SYSTEM, market.agency_b, merchant_account_id=market.m_b, key=_unique("k"), name="n"
    ).id
    with pytest.raises(PlanNotEligibleError):
        market.migrate(caller, payer=market.agency_a, account=market.acct_a, plan=plan_b)
    assert get_tenant(market.legacy_child).inherits_billing is True
    assert _subscriptions(market.legacy_child) == 0


@pytest.mark.parametrize("who", ["no_change", "unrelated", "support"])
def test_an_unauthorized_migration_changes_nothing(
    world: _World, market: _Market, who: str
) -> None:
    caller = {
        # charge + create, but not `change` on the inheriting tenant
        "no_change": lambda: world.user(
            (market.agency_a, _CHARGE), (market.agency_a, _CREATE), scope=RoleScope.SUBTREE
        ),
        "unrelated": lambda: world.user(
            (market.agency_b, _CHARGE),
            (market.agency_b, _CREATE),
            (market.agency_b, _CHANGE),
            scope=RoleScope.SUBTREE,
        ),
        "support": lambda: world.support_engineer(market.agency_a, market.legacy_child),
    }[who]()
    with pytest.raises(BillingNotAuthorizedError):
        market.migrate(caller, payer=market.agency_a, account=market.acct_a)
    assert get_tenant(market.legacy_child).inherits_billing is True
    assert _subscriptions(market.legacy_child) == 0
    assert market.provider.contexts == {
        k: v
        for k, v in market.provider.contexts.items()
        if v is None or v.payer_tenant_id != market.legacy_child
    }


def test_migration_never_runs_twice_or_duplicates_a_subscription(
    world: _World, market: _Market
) -> None:
    caller = _migrator(world, market)
    key = _unique("migrate")
    _, first = market.migrate(caller, payer=market.agency_a, account=market.acct_a, key=key)
    replay, again = market.migrate(caller, payer=market.agency_a, account=market.acct_a, key=key)
    assert replay is True and again.subscription_id == first.subscription_id
    with pytest.raises(BillingInheritanceMigrationError):
        market.migrate(caller, payer=market.agency_a, account=market.acct_a)
    assert _subscriptions(market.legacy_child) == 1
    # A tenant that never inherited cannot be "migrated" either.
    with pytest.raises(BillingInheritanceMigrationError):
        market.migrate(
            caller, payer=market.agency_a, account=market.acct_a, service=market.client_b
        )


def test_an_inheriting_tenant_with_its_own_live_subscription_is_refused(
    world: _World, market: _Market
) -> None:
    child = market.world.tenant("stray-child", parent_id=market.agency_a)
    key = _unique("legacy")
    market.world.legacy_keys.append(key)
    create_plan(key, "Legacy")
    subscribe(child, key, provider=market.provider)  # its own row, before inheriting
    _seed_legacy_billing_inheritance(child)
    with pytest.raises(BillingInheritanceMigrationError):
        market.migrate(
            _migrator(world, market), payer=market.agency_a, account=market.acct_a, service=child
        )
    assert get_tenant(child).inherits_billing is True


def test_an_opt_out_during_the_provider_call_refuses_the_migration(
    world: _World, market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = market.provider.create_subscription

    def create_then_opt_out(**kwargs):  # type: ignore[no-untyped-def]
        provider_subscription_id = real(**kwargs)
        opt_out_of_billing_inheritance(_BILLING_SYSTEM, market.legacy_child)
        return provider_subscription_id

    monkeypatch.setattr(market.provider, "create_subscription", create_then_opt_out)
    with pytest.raises(BillingInheritanceMigrationError):
        market.migrate(_migrator(world, market), payer=market.agency_a, account=market.acct_a)
    assert _subscriptions(market.legacy_child) == 0
    assert _audit(market.legacy_child, "billing.inheritance_migrated") == []
    [refused] = _audit(market.legacy_child, "billing.subscription_create_refused")
    assert refused.entry_metadata is not None
    assert refused.entry_metadata["refusal"] == "BillingInheritanceMigrationError"


# --- Cancellation authority -----------------------------------------------------------


@pytest.mark.parametrize(
    ("capacity", "grant_on"),
    [
        (CancellationCapacity.SERVICE_TENANT, "client_c"),
        (CancellationCapacity.PAYER, "agency_a_charge"),
        (CancellationCapacity.MERCHANT, "agency_a_merchant"),
    ],
)
def test_each_party_may_cancel_in_its_own_capacity(
    world: _World, market: _Market, capacity: CancellationCapacity, grant_on: str
) -> None:
    caller = {
        "client_c": lambda: world.user((market.client_c, _CANCEL)),
        "agency_a_charge": lambda: world.user((market.agency_a, _CHARGE)),
        "agency_a_merchant": lambda: world.user((market.agency_a, _MERCHANT)),
    }[grant_on]()
    before = get_subscription(market.client_c, market.sub_c).version
    result = market.cancel(caller, market.client_c, market.sub_c, capacity)
    assert result.status == "canceled"
    row = get_subscription(market.client_c, market.sub_c)
    assert row.version == before + 1
    [entry] = _audit(market.client_c, "billing.subscription_canceled")
    assert entry.actor_user_id == caller.user_id
    assert entry.entry_metadata is not None
    assert entry.entry_metadata["canceled_as"] == capacity.value
    assert not any("provider" in key for key in entry.entry_metadata)
    events = _admin(
        "SELECT payload FROM core.outbox_events WHERE tenant_id = :t AND event_type = :e "
        "ORDER BY created_at DESC LIMIT 1",
        t=str(market.client_c),
        e=SUBSCRIPTION_CHANGED_EVENT_TYPE,
    )
    assert events[0][0] == {"subscription_id": str(market.sub_c), "version": row.version}
    project_subscription(market.client_c, market.sub_c)
    with tenant_session_scope(market.agency_a) as session:
        projected = session.execute(
            text("SELECT status FROM core.billing_seller_subscriptions WHERE subscription_id = :s"),
            {"s": str(market.sub_c)},
        ).scalar_one()
    assert projected == "canceled"


@pytest.mark.parametrize(
    "case", ["unrelated_payer", "other_merchant", "wrong_capacity", "payer_of_another"]
)
def test_no_unrelated_party_may_cancel(world: _World, market: _Market, case: str) -> None:
    attempts = {
        # Charge authority somewhere else is not this subscription's payer.
        "unrelated_payer": (
            world.user((market.agency_b, _CHARGE)),
            market.client_c,
            market.sub_c,
            CancellationCapacity.PAYER,
        ),
        "other_merchant": (
            world.user((market.agency_b, _MERCHANT)),
            market.client_c,
            market.sub_c,
            CancellationCapacity.MERCHANT,
        ),
        # The payer's authority does not make it the service tenant.
        "wrong_capacity": (
            world.user((market.agency_a, _CHARGE)),
            market.client_c,
            market.sub_c,
            CancellationCapacity.SERVICE_TENANT,
        ),
        # Agency A pays for C, not for B (B pays itself).
        "payer_of_another": (
            world.user((market.agency_a, _CHARGE)),
            market.client_b,
            market.sub_b,
            CancellationCapacity.PAYER,
        ),
    }
    caller, service, sub, capacity = attempts[case]
    with pytest.raises(BillingNotAuthorizedError):
        market.cancel(caller, service, sub, capacity)
    assert _status(service, sub) == "active"


@pytest.mark.parametrize("capacity", list(CancellationCapacity))
def test_support_never_cancels_in_any_capacity(
    world: _World, market: _Market, capacity: CancellationCapacity
) -> None:
    engineer = world.support_engineer(market.client_c, market.agency_a)
    with pytest.raises(BillingNotAuthorizedError):
        market.cancel(engineer, market.client_c, market.sub_c, capacity)
    assert _status(market.client_c, market.sub_c) == "active"


def test_only_the_billing_system_purpose_cancels_as_the_system(market: _Market) -> None:
    with pytest.raises(BillingNotAuthorizedError):
        market.cancel(_PROVISIONING, market.client_c, market.sub_c, CancellationCapacity.PAYER)
    result = market.cancel(
        _BILLING_SYSTEM, market.client_c, market.sub_c, CancellationCapacity.MERCHANT
    )
    assert result.status == "canceled"


def test_a_payer_or_merchant_cannot_probe_for_subscriptions(world: _World, market: _Market) -> None:
    payer = world.user((market.agency_a, _CHARGE))
    with pytest.raises(BillingNotAuthorizedError):
        market.cancel(payer, market.client_c, uuid.uuid4(), CancellationCapacity.PAYER)


def test_authority_revoked_after_the_provider_cancel_refuses_the_local_cancel(
    world: _World, market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    payer = world.user((market.agency_a, _CHARGE))
    grantor = world.user((market.agency_a, ("deny_grant", "create")))
    real = commercial.cancel_at_provider

    def cancel_then_deny(provider, provider_subscription_id):  # type: ignore[no-untyped-def]
        real(provider, provider_subscription_id)
        create_deny(
            caller=grantor,
            principal_user_id=payer.user_id,
            tenant_id=market.agency_a,
            scope_mode=RoleScope.SELF,
            permission_id=register_permission(*_CHARGE).id,
        )

    monkeypatch.setattr(commercial, "cancel_at_provider", cancel_then_deny)
    with pytest.raises(BillingNotAuthorizedError):
        market.cancel(payer, market.client_c, market.sub_c, CancellationCapacity.PAYER)
    assert _status(market.client_c, market.sub_c) == "active"
    assert _audit(market.client_c, "billing.subscription_canceled") == []


def test_a_provider_refusal_never_cancels_locally(
    market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(**_: object) -> None:
        raise BillingProviderError("cancel_subscription", "refused")

    monkeypatch.setattr(market.provider, "cancel_subscription", refuse)
    with pytest.raises(BillingProviderError):
        market.cancel(
            _BILLING_SYSTEM, market.client_c, market.sub_c, CancellationCapacity.SERVICE_TENANT
        )
    assert _status(market.client_c, market.sub_c) == "active"
    assert _audit(market.client_c, "billing.subscription_canceled") == []


# --- Plan withdrawal cancels nothing -------------------------------------------------


def test_withdrawing_a_plan_blocks_new_subscriptions_and_cancels_none(
    market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        market.provider,
        "cancel_subscription",
        lambda **kw: calls.append(kw["provider_subscription_id"]),
    )
    withdraw_plan(_BILLING_SYSTEM, market.agency_a, market.plan_x)
    for service, sub in ((market.client_b, market.sub_b), (market.client_c, market.sub_c)):
        row = get_subscription(service, sub)
        assert (row.status, row.version) == ("active", 2)
    assert calls == []
    assert (
        market.provider.get_subscription_status(
            provider_subscription_id=get_subscription(
                market.client_c, market.sub_c
            ).provider_subscription_id
        )
        is ProviderSubscriptionState.ACTIVE
    )
    newcomer = market.world.tenant("newcomer", parent_id=market.agency_a)
    with pytest.raises(PlanNotEligibleError):
        market.create(newcomer, newcomer, market.account(newcomer, market.agency_a, market.m_a))
