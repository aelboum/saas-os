"""Phase 5.3 step 7 -- adversarial security and concurrency tests across the
whole B2B2C billing implementation, against a real PostgreSQL instance.

Shape (generic tenants):

    Agency A (merchant mA; plan X: api_calls 100, reports; descendants)
      +-- Client C   X, Agency A pays     (sub_cx)
      |               Y, C pays itself    (sub_cy, at Agency B's merchant)
      +-- Client B   X, pays itself       (sub_bx)
    Agency B (merchant mB; plan Y: api_calls 250, exports; public)
    Outsider O (unrelated branch)

Each test tries to cross a boundary the approved Phase 5.3 model forbids --
by capacity, by hierarchy, by support access, by system purpose, by a race,
by replay, by direct SQL -- and asserts it fails closed and leaves no
success state or evidence behind.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import core.identity.models  # noqa: F401  (registers core.users for audit FKs)
import pytest
from core.audit_log.service import list as list_audit_entries
from core.authority import SystemAuthority, SystemCaller, UserCaller
from core.billing.catalog import (
    PlanVisibility,
    adopt_legacy_plan,
    create_owned_plan,
    create_plan_offer,
    set_plan_visibility,
    withdraw_plan,
)
from core.billing.commercial import (
    CancellationCapacity,
    cancel_commercial_subscription,
    create_subscription,
    reconcile_subscription_status,
)
from core.billing.errors import (
    BillingAccountNotFoundError,
    BillingNotAuthorizedError,
    BillingProviderMismatchError,
    InvalidCatalogValueError,
    LegacyBillingPathError,
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
from core.billing.projections import project_subscription
from core.billing.provider import FakeBillingProvider
from core.billing.service import (
    cancel_subscription,
    create_plan,
    get_entitlements,
    get_subscription,
    has_entitlement,
    subscribe,
    upgrade_subscription,
)
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
from core.usage.reporting import (
    merchant_subscription_usage,
    payer_subscription_usage,
    service_tenant_usage_report,
)
from core.usage.service import check_quota
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

from core.idempotency import IdempotencyKeyReusedError
from core.identity import get_membership
from core.rbac import RoleScope
from core.tenancy import (
    TenantStatus,
    create_tenant,
    get_tenancy_config,
    move_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_PURGE = SystemCaller(SystemAuthority.TENANT_PURGE)
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
_CHARGE = ("billing.account", "charge")
_ACCOUNT_READ = ("billing.account", "read")
_ACCOUNT_MANAGE = ("billing.account", "manage")
_CREATE = ("billing.subscription", "create")
_READ = ("billing.subscription", "read")
_CHANGE = ("billing.subscription", "change")
_CANCEL = ("billing.subscription", "cancel")
_MERCHANT = ("billing.merchant", "manage")
_CATALOG = ("billing.catalog", "manage")
_ALL_MUTATIONS = (_CHARGE, _ACCOUNT_MANAGE, _CREATE, _CHANGE, _CANCEL, _MERCHANT, _CATALOG)
_SINCE = datetime(2026, 6, 1, tzinfo=UTC)
_UNTIL = datetime(2026, 7, 1, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _require_reachable_database_at_head() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.billing_seller_subscriptions LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable or not at head: {exc}")
    finally:
        probe.dispose()


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

    def all_billing(self, tenant: uuid.UUID, scope: RoleScope = RoleScope.SELF) -> UserCaller:
        return self.user(*((tenant, p) for p in _ALL_MUTATIONS), scope=scope)

    def support_engineer(self, *tenants: uuid.UUID) -> UserCaller:
        engineer = create_user()
        self.user_ids.append(engineer.id)
        for tenant_id in tenants:
            approver = self.user((tenant_id, ("support_access_request", "approve")))
            request = create_support_access_request(
                caller=UserCaller(engineer.id),
                tenant_id=tenant_id,
                reason="step 7 attack",
                requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
                scope_mode=RoleScope.SUBTREE,
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
                    "DELETE FROM core.usage_events WHERE tenant_id = ANY(:t)",
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
                    "DELETE FROM core.delegation_grants WHERE tenant_id = ANY(:t)",
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
        self.client_c = world.tenant("client-c", parent_id=self.agency_a)
        self.client_b = world.tenant("client-b", parent_id=self.agency_a)
        self.outsider = world.tenant("outsider")
        self.m_a, self.m_b = self._merchant(self.agency_a), self._merchant(self.agency_b)
        self.plan_x = self._plan(
            self.agency_a, self.m_a, {"api_calls": 100, "reports": True}, PlanVisibility.DESCENDANTS
        )
        self.plan_y = self._plan(
            self.agency_b, self.m_b, {"api_calls": 250, "exports": True}, PlanVisibility.PUBLIC
        )
        self.acct_a = self.account(self.agency_a, self.agency_a, self.m_a)
        self.acct_c_at_b = self.account(self.client_c, self.agency_b, self.m_b)
        self.acct_b = self.account(self.client_b, self.agency_a, self.m_a)
        self.sub_cx = self.create(self.client_c, self.agency_a, self.acct_a, self.plan_x)
        self.sub_cy = self.create(self.client_c, self.client_c, self.acct_c_at_b, self.plan_y)
        self.sub_bx = self.create(self.client_b, self.client_b, self.acct_b, self.plan_x)

    def _merchant(self, owner: uuid.UUID) -> uuid.UUID:
        return create_merchant_account(
            _BILLING_SYSTEM,
            owner,
            provider="fake",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        ).id

    def _plan(self, owner, merchant, entitlements, visibility):  # type: ignore[no-untyped-def]
        return create_owned_plan(
            _BILLING_SYSTEM,
            owner,
            merchant_account_id=merchant,
            key=_unique("plan"),
            name="Attacked plan",
            entitlements=entitlements,
            visibility=visibility,
        ).id

    def account(self, payer, owner, merchant):  # type: ignore[no-untyped-def]
        account, _ = get_or_create_billing_account(
            _BILLING_SYSTEM, payer, merchant_tenant_id=owner, merchant_account_id=merchant
        )
        return account.id

    def create(self, service, payer, account, plan, *, caller=None, key=None):  # type: ignore[no-untyped-def]
        _, result = create_subscription(
            caller or _BILLING_SYSTEM,
            service_tenant_id=service,
            payer_tenant_id=payer,
            billing_account_id=account,
            plan_id=plan,
            idempotency_key=key or _unique("idem"),
            provider=self.provider,
        )
        return result.subscription_id

    def cancel(self, caller, service, sub, capacity=CancellationCapacity.SERVICE_TENANT):  # type: ignore[no-untyped-def]
        return cancel_commercial_subscription(
            caller,
            service_tenant_id=service,
            subscription_id=sub,
            provider=self.provider,
            acting_as=capacity,
        )


@pytest.fixture
def market(world: _World) -> _Market:
    return _Market(world)


def _status(service: uuid.UUID, sub: uuid.UUID) -> str:
    return get_subscription(service, sub).status


def _version(service: uuid.UUID, sub: uuid.UUID) -> int:
    return get_subscription(service, sub).version


def _events(service: uuid.UUID, sub: uuid.UUID) -> int:
    return _admin(
        "SELECT count(*) FROM core.outbox_events WHERE tenant_id = :t AND aggregate_id = :s",
        t=str(service),
        s=str(sub),
    )[0][0]


# --- Defect regression: the legacy trusted paths vs commercial rows --------------------


def test_legacy_upgrade_cannot_rewrite_a_commercial_subscription(market: _Market) -> None:
    """Found by step 7: the unauthenticated legacy `upgrade_subscription()`
    could switch a verified commercial subscription to any legacy plan,
    bypassing Catalog v2 eligibility, merchant compatibility and every
    billing authority. It now refuses commercial rows."""
    key = _unique("legacy")
    market.world.legacy_keys.append(key)
    create_plan(key, "Legacy", entitlements={"api_calls": 999999})
    before = get_subscription(market.client_b, market.sub_bx)
    with pytest.raises(LegacyBillingPathError):
        upgrade_subscription(market.client_b, market.sub_bx, key, provider=market.provider)
    after = get_subscription(market.client_b, market.sub_bx)
    assert (after.plan_id, after.version) == (before.plan_id, before.version)
    assert get_entitlements(market.client_b) == {"api_calls": 100, "reports": True}


def test_legacy_cancel_cannot_bypass_the_cancellation_matrix(market: _Market) -> None:
    with pytest.raises(LegacyBillingPathError):
        cancel_subscription(market.client_c, market.sub_cx, provider=market.provider)
    assert _status(market.client_c, market.sub_cx) == "active"
    assert (
        market.provider.get_subscription_status(
            provider_subscription_id=get_subscription(
                market.client_c, market.sub_cx
            ).provider_subscription_id
        ).value
        == "active"
    )


# --- Hierarchy never substitutes for a commercial relationship -------------------------


@pytest.mark.parametrize("scope", [RoleScope.SELF, RoleScope.SUBTREE])
@pytest.mark.parametrize("relation", ["parent", "sibling", "child_of_agency_b", "outsider"])
def test_full_billing_authority_elsewhere_never_reaches_client_cs_y_subscription(
    world: _World, market: _Market, scope: RoleScope, relation: str
) -> None:
    """Every billing mutation permission, held at a tenant related to C by
    hierarchy only (or not at all), in either scope: none of it makes that
    tenant C's payer for Y (C pays), Y's merchant (Agency B) or the service
    tenant. Cancellation, payer/merchant usage and cross-payer creation all
    fail."""
    holder = {
        "parent": market.agency_a,
        "sibling": market.client_b,
        "child_of_agency_b": world.tenant("b-child", parent_id=market.agency_b),
        "outsider": market.outsider,
    }[relation]
    caller = world.all_billing(holder, scope)
    reader = world.user((holder, _ACCOUNT_READ), (holder, _MERCHANT), scope=scope)
    # A parent with a SUBTREE role holds explicit, delegated authority over
    # C's own billing (ADR-0029: a SUBTREE role is an authorization input) --
    # it may act FOR C, the recorded payer and service tenant. That is
    # authority, not ownership: it still is not Y's merchant, and the
    # payer/merchant views below still refuse to treat it as a party.
    delegated = relation == "parent" and scope is RoleScope.SUBTREE
    capacities = [CancellationCapacity.MERCHANT]
    if not delegated:
        capacities += [CancellationCapacity.PAYER, CancellationCapacity.SERVICE_TENANT]
    for capacity in capacities:
        with pytest.raises(BillingNotAuthorizedError):
            market.cancel(caller, market.client_c, market.sub_cy, capacity)
    for view in (payer_subscription_usage, merchant_subscription_usage):
        with pytest.raises(BillingNotAuthorizedError):
            view(
                reader,
                holder,
                service_tenant_id=market.client_c,
                subscription_id=market.sub_cy,
                since=_SINCE,
                until=_UNTIL,
            )
    if not delegated:
        with pytest.raises((BillingNotAuthorizedError, BillingAccountNotFoundError)):
            market.create(
                market.client_c, market.client_c, market.acct_c_at_b, market.plan_y, caller=caller
            )
    assert _status(market.client_c, market.sub_cy) == "active"


def test_an_explicit_deny_beats_a_subtree_grant(world: _World, market: _Market) -> None:
    admin = world.all_billing(market.agency_a, RoleScope.SUBTREE)
    grantor = world.user((market.client_c, ("deny_grant", "create")))
    create_deny(
        caller=grantor,
        principal_user_id=admin.user_id,
        tenant_id=market.client_c,
        scope_mode=RoleScope.SELF,
        permission_id=register_permission(*_CANCEL).id,
    )
    with pytest.raises(BillingNotAuthorizedError):
        market.cancel(admin, market.client_c, market.sub_cx)
    # The deny names the service tenant's cancel action only: the agency may
    # still cancel in its own capacity as the payer.
    assert market.cancel(
        admin, market.client_c, market.sub_cx, CancellationCapacity.PAYER
    ).status == ("canceled")


# --- Support and system purposes against every mutation ------------------------------


def _every_mutation(market: _Market, caller: object) -> list:  # type: ignore[type-arg]
    unlisted = create_owned_plan(
        _BILLING_SYSTEM,
        market.agency_a,
        merchant_account_id=market.m_a,
        key=_unique("k"),
        name="n",
        visibility=PlanVisibility.UNLISTED,
    ).id
    return [
        lambda: market.create(
            market.client_b, market.client_b, market.acct_b, market.plan_x, caller=caller
        ),
        *(
            (
                lambda capacity=capacity: market.cancel(
                    caller, market.client_c, market.sub_cx, capacity
                )
            )
            for capacity in CancellationCapacity
        ),
        lambda: opt_out_of_billing_inheritance(caller, market.client_c),
        lambda: migrate_inherited_tenant_to_sponsorship(
            caller,
            service_tenant_id=market.client_c,
            payer_tenant_id=market.agency_a,
            billing_account_id=market.acct_a,
            plan_id=market.plan_x,
            idempotency_key=_unique("m"),
            provider=market.provider,
        ),
        lambda: create_owned_plan(
            caller, market.agency_a, merchant_account_id=market.m_a, key=_unique("k"), name="n"
        ),
        lambda: withdraw_plan(caller, market.agency_a, market.plan_x),
        lambda: set_plan_visibility(caller, market.agency_a, market.plan_x, PlanVisibility.PUBLIC),
        lambda: create_plan_offer(
            caller, market.agency_a, unlisted, service_tenant_id=market.outsider
        ),
        lambda: create_merchant_account(
            caller, market.agency_a, provider="fake", provider_account_ref=_unique("r")
        ),
        lambda: get_or_create_billing_account(
            caller,
            market.outsider,
            merchant_tenant_id=market.agency_a,
            merchant_account_id=market.m_a,
        ),
    ]


@pytest.mark.parametrize("who", ["support", "provisioning", "tenant_purge"])
def test_support_and_other_system_purposes_mutate_nothing(
    world: _World, market: _Market, who: str
) -> None:
    caller = {
        "support": lambda: world.support_engineer(
            market.agency_a, market.client_c, market.client_b, market.outsider
        ),
        "provisioning": lambda: _PROVISIONING,
        "tenant_purge": lambda: _PURGE,
    }[who]()
    for attempt in _every_mutation(market, caller):
        with pytest.raises(BillingNotAuthorizedError):
            attempt()
    assert _status(market.client_c, market.sub_cx) == "active"
    if who == "support":
        # Billing reads stay readable through support access. Reconciliation
        # is provider-driven synchronization, authorized as a read (post-5.3
        # audit decision R1): the provider decides the status, never the caller.
        assert service_tenant_usage_report(caller, market.client_c, since=_SINCE, until=_UNTIL)
        reconcile_subscription_status(
            caller,
            service_tenant_id=market.client_c,
            subscription_id=market.sub_cx,
            provider=market.provider,
        )


# --- Races ---------------------------------------------------------------------------


def _run_concurrently(*actions) -> list:  # type: ignore[no-untyped-def]
    barrier = threading.Barrier(len(actions))
    outcomes: list[object] = [None] * len(actions)

    def run(index: int, action) -> None:  # type: ignore[no-untyped-def]
        try:
            barrier.wait(10)
            outcomes[index] = action()
        except BaseException as exc:  # noqa: BLE001
            outcomes[index] = exc

    threads = [threading.Thread(target=run, args=(i, a)) for i, a in enumerate(actions)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    return outcomes


def test_three_parties_cancelling_at_once_change_the_row_exactly_once(
    world: _World, market: _Market
) -> None:
    service = world.user((market.client_c, _CANCEL))
    payer = world.user((market.agency_a, _CHARGE))
    merchant = world.user((market.agency_a, _MERCHANT))
    before_version, before_events = (
        _version(market.client_c, market.sub_cx),
        _events(market.client_c, market.sub_cx),
    )
    outcomes = _run_concurrently(
        lambda: market.cancel(service, market.client_c, market.sub_cx),
        lambda: market.cancel(payer, market.client_c, market.sub_cx, CancellationCapacity.PAYER),
        lambda: market.cancel(
            merchant, market.client_c, market.sub_cx, CancellationCapacity.MERCHANT
        ),
    )
    assert all(getattr(o, "status", None) == "canceled" for o in outcomes), outcomes
    assert _version(market.client_c, market.sub_cx) == before_version + 1
    assert _events(market.client_c, market.sub_cx) == before_events + 1
    audits = [
        e
        for e in list_audit_entries(market.client_c)
        if e.action == "billing.subscription_canceled"
    ]
    assert len(audits) == 1


def test_creations_race_one_live_per_merchant_but_merchants_coexist(
    world: _World, market: _Market
) -> None:
    newcomer = world.tenant("newcomer", parent_id=market.agency_a)
    acct_x = market.account(newcomer, market.agency_a, market.m_a)
    acct_y = market.account(newcomer, market.agency_b, market.m_b)
    outcomes = _run_concurrently(
        *(lambda: market.create(newcomer, newcomer, acct_x, market.plan_x) for _ in range(3)),
        lambda: market.create(newcomer, newcomer, acct_y, market.plan_y),
    )
    created = [o for o in outcomes if isinstance(o, uuid.UUID)]
    live = _admin(
        "SELECT merchant_account_id, count(*) FROM core.billing_subscriptions "
        "WHERE tenant_id = :t AND status IN ('pending','active','past_due') GROUP BY 1",
        t=str(newcomer),
    )
    assert {merchant: count for merchant, count in live} == {market.m_a: 1, market.m_b: 1}
    assert len(created) == 2
    assert get_entitlements(newcomer) == {"api_calls": 250, "reports": True, "exports": True}


def test_a_move_during_the_provider_call_refuses_a_descendants_plan(
    world: _World, market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    mover = world.tenant("mover", parent_id=market.agency_a)
    account = market.account(mover, market.agency_a, market.m_a)
    real = market.provider.create_subscription

    def create_then_move(**kwargs):  # type: ignore[no-untyped-def]
        provider_subscription_id = real(**kwargs)
        move_tenant(mover, market.outsider)  # no longer a descendant of the plan owner
        return provider_subscription_id

    monkeypatch.setattr(market.provider, "create_subscription", create_then_move)
    with pytest.raises(PlanNotEligibleError):
        market.create(mover, mover, account, market.plan_x)
    with tenant_session_scope(mover) as session:
        assert (
            session.execute(text("SELECT count(*) FROM core.billing_subscriptions")).scalar_one()
            == 0
        )


def test_cancellation_and_projection_converge_whatever_the_order(market: _Market) -> None:
    outcomes = _run_concurrently(
        lambda: market.cancel(_BILLING_SYSTEM, market.client_c, market.sub_cx),
        lambda: project_subscription(market.client_c, market.sub_cx),
        lambda: project_subscription(market.client_c, market.sub_cx),
    )
    assert not any(isinstance(o, BaseException) for o in outcomes), outcomes
    project_subscription(market.client_c, market.sub_cx)
    project_subscription(market.client_c, market.sub_cx)  # duplicate: harmless
    canonical = get_subscription(market.client_c, market.sub_cx)
    for table, owner in (
        ("billing_seller_subscriptions", market.agency_a),
        ("billing_payer_subscriptions", market.agency_a),
    ):
        with tenant_session_scope(owner) as session:
            row = session.execute(
                text(f"SELECT status, source_version FROM core.{table} WHERE subscription_id = :s"),
                {"s": str(market.sub_cx)},
            ).one()
        assert tuple(row) == ("canceled", canonical.version), table


# --- Idempotency cannot change the meaning of a completed request -------------------


def test_a_reused_key_cannot_change_a_completed_request(market: _Market) -> None:
    key = _unique("idem")
    newcomer = market.world.tenant("idem-tenant", parent_id=market.agency_a)
    account = market.account(newcomer, market.agency_a, market.m_a)
    first = market.create(newcomer, newcomer, account, market.plan_x, key=key)
    assert market.create(newcomer, newcomer, account, market.plan_x, key=key) == first
    other_plan = create_owned_plan(
        _BILLING_SYSTEM, market.agency_a, merchant_account_id=market.m_a, key=_unique("k"), name="n"
    ).id
    with pytest.raises(IdempotencyKeyReusedError):
        market.create(newcomer, newcomer, account, other_plan, key=key)


# --- Entitlements stay consistent across every reader ----------------------------------


def test_every_reader_agrees_on_the_combined_entitlements_through_a_cancel(
    world: _World, market: _Market
) -> None:
    def readers() -> tuple:  # type: ignore[type-arg]
        report = service_tenant_usage_report(
            _BILLING_SYSTEM, market.client_c, since=_SINCE, until=_UNTIL
        )
        line = next(m for m in report.metrics if m.metric == "api_calls")
        return (
            get_entitlements(market.client_c).get("api_calls"),
            check_quota(market.client_c, "api_calls", since=_SINCE, until=_UNTIL).limit,
            line.limit,
            has_entitlement(market.client_c, "reports"),
            has_entitlement(market.client_c, "exports"),
        )

    assert readers() == (250, 250, 250, True, True)  # MAX(100, 250), never 350; OR
    market.cancel(_BILLING_SYSTEM, market.client_c, market.sub_cy)
    assert readers() == (100, 100, 100, True, False)  # no stale grant survives


# --- No probing: indistinguishable refusals ------------------------------------------


def test_refusals_are_indistinguishable(world: _World, market: _Market) -> None:
    payer_a = world.user((market.agency_a, _ACCOUNT_READ), (market.agency_a, _CHARGE))
    unauthorized = world.user()

    def message(action) -> tuple[type, str]:  # type: ignore[no-untyped-def]
        with pytest.raises(BillingNotAuthorizedError) as excinfo:
            action()
        return type(excinfo.value), str(excinfo.value)

    def usage(caller, sub):  # type: ignore[no-untyped-def]
        return lambda: payer_subscription_usage(
            caller,
            market.agency_a,
            service_tenant_id=market.client_c,
            subscription_id=sub,
            since=_SINCE,
            until=_UNTIL,
        )

    def cancel(caller, sub):  # type: ignore[no-untyped-def]
        return lambda: market.cancel(caller, market.client_c, sub, CancellationCapacity.PAYER)

    for build in (usage, cancel):
        outcomes = {
            message(build(payer_a, uuid.uuid4())),  # missing
            message(build(payer_a, market.sub_cy)),  # paid by someone else
            message(build(unauthorized, market.sub_cx)),  # no authority
        }
        assert len(outcomes) == 1, outcomes


# --- The database holds the invariants on its own -------------------------------------


def test_rls_refuses_cross_tenant_reads_and_writes_on_every_billing_table(
    market: _Market,
) -> None:
    project_subscription(market.client_c, market.sub_cx)
    with tenant_session_scope(market.outsider) as session:
        for table in (
            "billing_subscriptions",
            "billing_accounts",
            "billing_merchant_accounts",
            "billing_plan_offers",
            "billing_seller_subscriptions",
            "billing_payer_subscriptions",
            "usage_events",
            "outbox_events",
        ):
            assert session.execute(text(f"SELECT count(*) FROM core.{table}")).scalar_one() == 0
            updated = session.execute(
                text(f"UPDATE core.{table} SET tenant_id = tenant_id RETURNING 1")
            ).all()
            assert updated == [], table
    for sql in (
        "INSERT INTO core.billing_plan_offers (id, tenant_id, plan_id, service_tenant_id, "
        "status) VALUES (gen_random_uuid(), :victim, :plan, :me, 'active')",
        "INSERT INTO core.billing_seller_subscriptions (id, tenant_id, subscription_id, "
        "merchant_account_id, service_tenant_id, payer_tenant_id, plan_id, status, "
        "verification, subscription_created_at, subscription_updated_at, source_version, "
        "projected_at) VALUES (gen_random_uuid(), :victim, :sub, :merchant, :me, :me, :plan, "
        "'active', 'verified', now(), now(), 99, now())",
    ):
        with pytest.raises(DBAPIError), tenant_session_scope(market.outsider) as session:
            session.execute(
                text(sql),
                {
                    "victim": str(market.agency_a),
                    "plan": str(market.plan_x),
                    "me": str(market.outsider),
                    "sub": str(market.sub_cx),
                    "merchant": str(market.m_a),
                },
            )


@pytest.mark.parametrize(
    "violation",
    [
        "second_live_at_one_merchant",
        "projection_of_a_foreign_merchant",
        "second_active_offer",
        "plan_with_a_foreign_merchant",
        "projection_version_zero",
        "new_inheritance",
    ],
)
def test_the_database_refuses_invariant_violations_directly(
    market: _Market, violation: str
) -> None:
    params = {
        "c": str(market.client_c),
        "a": str(market.agency_a),
        "b": str(market.agency_b),
        "mb": str(market.m_b),
        "ma": str(market.m_a),
        "acct": str(market.acct_a),
        "x": str(market.plan_x),
        "sub": str(market.sub_cx),
    }
    if violation == "second_active_offer":
        unlisted = create_owned_plan(
            _BILLING_SYSTEM,
            market.agency_a,
            merchant_account_id=market.m_a,
            key=_unique("k"),
            name="n",
            visibility=PlanVisibility.UNLISTED,
        ).id
        create_plan_offer(
            _BILLING_SYSTEM, market.agency_a, unlisted, service_tenant_id=market.client_c
        )
        params["x"] = str(unlisted)
    sql = {
        "second_live_at_one_merchant": "INSERT INTO core.billing_subscriptions (id, tenant_id, "
        "plan_id, status, provider_subscription_id, payer_tenant_id, billing_account_id, "
        "merchant_account_id, provider, verification) VALUES (gen_random_uuid(), :c, :x, "
        "'active', 'raw', :a, :acct, :ma, 'fake', 'verified')",
        "projection_of_a_foreign_merchant": "INSERT INTO core.billing_seller_subscriptions (id, "
        "tenant_id, subscription_id, merchant_account_id, service_tenant_id, payer_tenant_id, "
        "plan_id, status, verification, subscription_created_at, subscription_updated_at, "
        "source_version, projected_at) VALUES (gen_random_uuid(), :a, :sub, :mb, :c, :a, :x, "
        "'active', 'verified', now(), now(), 1, now())",
        "second_active_offer": "INSERT INTO core.billing_plan_offers (id, tenant_id, plan_id, "
        "service_tenant_id, status) VALUES (gen_random_uuid(), :a, :x, :c, 'active')",
        "plan_with_a_foreign_merchant": "INSERT INTO core.billing_plans (id, key, name, "
        "entitlements, owner_tenant_id, merchant_account_id, legacy) VALUES "
        "(gen_random_uuid(), 'raw-plan', 'x', '{}', :a, :mb, false)",
        "projection_version_zero": "INSERT INTO core.billing_seller_subscriptions (id, "
        "tenant_id, subscription_id, merchant_account_id, service_tenant_id, payer_tenant_id, "
        "plan_id, status, verification, subscription_created_at, subscription_updated_at, "
        "source_version, projected_at) VALUES (gen_random_uuid(), :a, :sub, :ma, :c, :a, :x, "
        "'active', 'verified', now(), now(), 0, now())",
        "new_inheritance": "UPDATE core.tenants SET inherits_billing = true WHERE id = :c",
    }[violation]
    # Even the privileged role is refused: these are database invariants.
    engine = build_engine(get_migrations_database_config())
    try:
        with pytest.raises(DBAPIError), engine.begin() as conn:
            conn.execute(text(sql), params)
    finally:
        engine.dispose()


# --- Audit integrity ------------------------------------------------------------------


def test_success_has_exactly_one_audit_entry_without_provider_references(
    world: _World, market: _Market
) -> None:
    newcomer = world.tenant("audited", parent_id=market.agency_a)
    account = market.account(newcomer, market.agency_a, market.m_a)
    sub = market.create(newcomer, newcomer, account, market.plan_x)
    market.cancel(_BILLING_SYSTEM, newcomer, sub)
    row = get_subscription(newcomer, sub)
    customer = _admin(
        "SELECT provider_customer_ref FROM core.billing_accounts WHERE id = :a", a=str(account)
    )[0][0]
    entries = list_audit_entries(newcomer)
    for action in ("billing.subscription_created", "billing.subscription_canceled"):
        assert len([e for e in entries if e.action == action]) == 1, action
    for entry in entries:
        rendered = repr(entry.entry_metadata)
        assert row.provider_subscription_id not in rendered
        assert customer is None or customer not in rendered


# --- Sponsored migration under attack ---------------------------------------------------


def _seed_inheriting_child(market: _Market) -> uuid.UUID:
    child = market.world.tenant("inheriting", parent_id=market.agency_a)
    _admin(
        "UPDATE core.tenants SET inherits_billing = true WHERE id = :t", replica=True, t=str(child)
    )
    return child


def _migrate(market: _Market, child: uuid.UUID, *, payer, account, key):  # type: ignore[no-untyped-def]
    return migrate_inherited_tenant_to_sponsorship(
        _BILLING_SYSTEM,
        service_tenant_id=child,
        payer_tenant_id=payer,
        billing_account_id=account,
        plan_id=market.plan_x,
        idempotency_key=key,
        provider=market.provider,
    )


def test_concurrent_migrations_of_one_tenant_create_one_subscription(market: _Market) -> None:
    child = _seed_inheriting_child(market)
    outcomes = _run_concurrently(
        *(
            lambda: _migrate(
                market, child, payer=market.agency_a, account=market.acct_a, key=_unique("m")
            )
            for _ in range(3)
        )
    )
    successes = [o for o in outcomes if isinstance(o, tuple)]
    assert len(successes) == 1, outcomes
    live = _admin(
        "SELECT count(*) FROM core.billing_subscriptions WHERE tenant_id = :t "
        "AND status IN ('pending','active','past_due')",
        t=str(child),
    )[0][0]
    assert live == 1
    assert (
        _admin("SELECT inherits_billing FROM core.tenants WHERE id = :t", t=str(child))[0][0]
        is False
    )


def test_a_completed_migrations_key_cannot_be_reused_for_another_payer(market: _Market) -> None:
    child = _seed_inheriting_child(market)
    key = _unique("m")
    _, first = _migrate(market, child, payer=market.agency_a, account=market.acct_a, key=key)
    replay, again = _migrate(market, child, payer=market.agency_a, account=market.acct_a, key=key)
    assert replay is True and again.subscription_id == first.subscription_id
    own_account = market.account(child, market.agency_a, market.m_a)
    with pytest.raises(IdempotencyKeyReusedError):
        _migrate(market, child, payer=child, account=own_account, key=key)
    assert get_subscription(child, first.subscription_id).payer_tenant_id == market.agency_a


# --- Post-5.3 audit regressions ---------------------------------------------------------


def test_legacy_paths_refuse_an_unverified_row_that_records_a_payer(market: _Market) -> None:
    """Post-5.3 audit: a Phase 2 sponsored row is `legacy_unverified` yet names
    its payer, billing account and merchant. The unauthorized legacy
    upgrade/cancel must not act on it either (it changes only through the
    commercial API, after reconciliation)."""
    _admin(
        "UPDATE core.billing_subscriptions SET verification = 'legacy_unverified' WHERE id = :s",
        s=str(market.sub_cx),
    )
    key = _unique("legacy")
    market.world.legacy_keys.append(key)
    create_plan(key, "Legacy", entitlements={"api_calls": 999999})
    before = get_subscription(market.client_c, market.sub_cx)
    with pytest.raises(LegacyBillingPathError):
        upgrade_subscription(market.client_c, market.sub_cx, key, provider=market.provider)
    with pytest.raises(LegacyBillingPathError):
        cancel_subscription(market.client_c, market.sub_cx, provider=market.provider)
    after = get_subscription(market.client_c, market.sub_cx)
    assert (after.plan_id, after.status, after.version) == (
        before.plan_id,
        before.status,
        before.version,
    )


def _withdrawn_adopted_legacy_plan(market: _Market) -> str:
    key = _unique("adopted")
    market.world.legacy_keys.append(key)
    plan = create_plan(key, "Adopted", entitlements={"api_calls": 999999})
    adopt_legacy_plan(
        _BILLING_SYSTEM, plan.id, owner_tenant_id=market.agency_a, merchant_account_id=market.m_a
    )
    withdraw_plan(_BILLING_SYSTEM, market.agency_a, plan.id)
    return key


def test_legacy_paths_refuse_a_withdrawn_adopted_plan(world: _World, market: _Market) -> None:
    """Post-5.3 audit: an adopted legacy plan stays key-addressable; once
    withdrawn, neither the legacy `subscribe()` nor a legacy plan change
    may put anyone on it."""
    key = _withdrawn_adopted_legacy_plan(market)
    tenant = world.tenant("legacy-buyer")
    with pytest.raises(PlanNotEligibleError):
        subscribe(tenant, key, provider=market.provider)
    open_key = _unique("open")
    world.legacy_keys.append(open_key)
    create_plan(open_key, "Open", entitlements={})
    legacy = subscribe(tenant, open_key, provider=market.provider)
    with pytest.raises(PlanNotEligibleError):
        upgrade_subscription(tenant, legacy.id, key, provider=market.provider)
    assert get_subscription(tenant, legacy.id).plan_id == legacy.plan_id
    assert get_entitlements(tenant) == {}


def test_a_withdrawal_during_a_legacy_subscribe_refuses_the_write(
    world: _World, market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _unique("adopted")
    world.legacy_keys.append(key)
    plan = create_plan(key, "Adopted", entitlements={"api_calls": 999999})
    adopt_legacy_plan(
        _BILLING_SYSTEM, plan.id, owner_tenant_id=market.agency_a, merchant_account_id=market.m_a
    )
    real = market.provider.create_subscription

    def create_then_withdraw(**kwargs):  # type: ignore[no-untyped-def]
        provider_subscription_id = real(**kwargs)
        withdraw_plan(_BILLING_SYSTEM, market.agency_a, plan.id)
        return provider_subscription_id

    monkeypatch.setattr(market.provider, "create_subscription", create_then_withdraw)
    tenant = world.tenant("legacy-racer")
    with pytest.raises(PlanNotEligibleError):
        subscribe(tenant, key, provider=market.provider)
    with tenant_session_scope(tenant) as session:
        assert (
            session.execute(text("SELECT count(*) FROM core.billing_subscriptions")).scalar_one()
            == 0
        )


class _StripeNamedAdapter(FakeBillingProvider):
    """Any adapter named "stripe" that does not declare it acts in the
    merchant's own account -- as the deployment's `StripeBillingProvider`."""

    name = "stripe"


class _ConnectCapableAdapter(_StripeNamedAdapter):
    acts_in_merchant_accounts = True


def test_an_explicit_stripe_adapter_cannot_charge_a_tenant_merchants_customers(
    world: _World, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    """Post-5.3 audit: passing a Stripe adapter explicitly must not bypass the
    rule that the deployment's Stripe account sells only for the platform
    tenant's merchant. Nothing reaches the adapter."""
    seller, payer = world.tenant("stripe-seller"), world.tenant("stripe-payer")
    # A designated platform tenant that is not the seller.
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(world.tenant("platform")))
    get_tenancy_config.cache_clear()
    request.addfinalizer(get_tenancy_config.cache_clear)
    merchant = create_merchant_account(
        _BILLING_SYSTEM,
        seller,
        provider="stripe",
        provider_account_ref=_unique("acct_stripe"),
        status=MerchantAccountStatus.ACTIVE,
    ).id
    account, _ = get_or_create_billing_account(
        _BILLING_SYSTEM, payer, merchant_tenant_id=seller, merchant_account_id=merchant
    )
    plan = create_owned_plan(
        _BILLING_SYSTEM, seller, merchant_account_id=merchant, key=_unique("k"), name="n"
    ).id

    def create(adapter):  # type: ignore[no-untyped-def]
        return create_subscription(
            _BILLING_SYSTEM,
            service_tenant_id=payer,
            payer_tenant_id=payer,
            billing_account_id=account.id,
            plan_id=plan,
            idempotency_key=_unique("idem"),
            provider=adapter,
        )

    refused = _StripeNamedAdapter()
    with pytest.raises(BillingProviderMismatchError):
        create(refused)
    assert refused.customers == {} and refused.contexts == {}
    capable = _ConnectCapableAdapter()
    _, result = create(capable)
    assert result.status == "active"
    assert set(capable.customers) and set(capable.contexts)


def test_a_persisted_non_numeric_value_never_erases_a_numeric_quota(world: _World) -> None:
    """Post-5.3 audit remediation R4: plans written before write validation
    may hold a non-numeric value. Before R4, the newest such value replaced
    an older plan's numeric limit and read as "no limit" -- unlimited quota
    for every reader. Now every reader keeps the numeric limit."""
    tenant = world.tenant("mixed")
    provider = FakeBillingProvider()
    capped, poisoned = _unique("capped"), _unique("poisoned")
    world.legacy_keys += [capped, poisoned]
    create_plan(capped, "Capped", entitlements={"api_calls": 100})
    create_plan(poisoned, "Poisoned", entitlements={"api_calls": 1})
    _admin(  # what a plan persisted before validation may hold
        'UPDATE core.billing_plans SET entitlements = \'{"api_calls": null, "reports": true}\' '
        "WHERE key = :k AND legacy",
        k=poisoned,
    )
    subscribe(tenant, capped, provider=provider)
    subscribe(tenant, poisoned, provider=provider)  # the newest subscription
    report = service_tenant_usage_report(_BILLING_SYSTEM, tenant, since=_SINCE, until=_UNTIL)
    line = next(m for m in report.metrics if m.metric == "api_calls")
    assert get_entitlements(tenant) == {"api_calls": 100, "reports": True}
    assert check_quota(tenant, "api_calls", since=_SINCE, until=_UNTIL).limit == 100
    assert line.limit == 100
    assert has_entitlement(tenant, "reports")
    with pytest.raises(InvalidCatalogValueError):
        create_plan(_unique("refused"), "Refused", entitlements={"api_calls": "100"})
