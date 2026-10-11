"""Hierarchy-aware billing integration tests against a real PostgreSQL
instance (architecture research: universal multi-tenant tenancy, Phase H
-- "Hierarchy-Aware Billing & Usage").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/billing/test_billing_integration.py` and
`tests/core/tenancy/test_tenant_hierarchy_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/billing/test_billing_hierarchy_integration.py

Covers `resolve_billing_owner()`'s own precedence rules end to end, plus
the security invariant this whole phase exists to protect: billing
inheritance never grants, widens, or interacts with authorization.

Also covers the billing-owner CONSISTENCY REPAIR: `subscribe()`/
`upgrade_subscription()`/`cancel_subscription()` resolving through the
same `resolve_billing_owner()` boundary `get_entitlements()` already
used.
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.billing.errors import (
    InheritedBillingSubscriptionError,
    InvalidBillingHierarchyError,
)
from saas_os.core.billing.inheritance import opt_out_of_billing_inheritance
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import (
    cancel_subscription,
    create_plan,
    get_entitlements,
    resolve_billing_owner,
    subscribe,
    subscribe_idempotent,
    upgrade_subscription,
)
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.rbac import can
from saas_os.core.rbac.scope import RoleScope
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import create_tenant, move_tenant
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
    finally:
        engine.dispose()


_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)

pytestmark = pytest.mark.integration


def _seed_legacy_billing_inheritance(tenant_id: uuid.UUID) -> None:
    """Simulate a tenant that inherited billing before Phase 5.3 step 5. A
    new `inherits_billing = true` is refused by the database (trigger
    `trg_tenants_refuse_new_billing_inheritance`), so the state is seeded the
    way it pre-existed: with the privileged role, triggers suppressed for
    this one transaction only."""
    from sqlalchemy import text as _text

    from saas_os.infra.db.config import get_migrations_database_config as _migrations_config
    from saas_os.infra.db.engine import build_engine as _build_engine

    engine = _build_engine(_migrations_config())
    try:
        with engine.begin() as conn:
            conn.execute(_text("SET LOCAL session_replication_role = replica"))
            conn.execute(
                _text("UPDATE core.tenants SET inherits_billing = true WHERE id = :t"),
                {"t": str(tenant_id)},
            )
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _require_reachable_database_with_billing_hierarchy_column() -> None:
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
            conn.execute(text("SELECT inherits_billing FROM core.tenants LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            "core.tenants.inherits_billing does not exist yet -- run "
            f"`alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _cleanup_tenant_tree(*tenant_ids_leaf_to_root: uuid.UUID) -> None:
    """Delete tenants in leaf-to-root order -- `Tenant.parent_id` is a
    plain (non-cascading) FK, so a parent with a living child cannot be
    deleted first (`saas_os/core/tenancy/models.py`'s own docstring)."""
    for tenant_id in tenant_ids_leaf_to_root:
        _admin_delete_audit_log_for_tenant(tenant_id)
        with tenant_session_scope(tenant_id) as session:
            session.execute(
                text("DELETE FROM core.idempotency_records WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
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
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
        with session_scope() as session:
            _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_plan(key: str) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": key})


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        _admin_clear_audit_references({"id": str(user_id)}, table="users")
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


def _cleanup_permission(resource: str, action: str) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
            {"r": resource, "a": action},
        )


def _subscribe(tenant_id: uuid.UUID, plan_key: str) -> None:
    subscribe(tenant_id, plan_key, provider=FakeBillingProvider())


# --- Flat-tenant / default-behavior backward compatibility ------------------


def test_flat_tenant_inherits_billing_defaults_to_false() -> None:
    tenant = create_tenant(_unique_name("flat"))
    try:
        assert tenant.inherits_billing is False
        assert resolve_billing_owner(tenant.id) == tenant.id
    finally:
        _cleanup_tenant_tree(tenant.id)


def test_flat_tenant_entitlements_unchanged_by_phase_h() -> None:
    """A tenant that never opts in resolves and reads its own
    subscription exactly as every pre-Phase-H caller already did."""
    tenant = create_tenant(_unique_name("flat"))
    plan_key = _unique_name("plan")
    try:
        create_plan(plan_key, "Flat Plan", entitlements={"api_calls": 100})
        _subscribe(tenant.id, plan_key)
        assert get_entitlements(tenant.id) == {"api_calls": 100}
    finally:
        _cleanup_tenant_tree(tenant.id)
        _cleanup_plan(plan_key)


# --- Ownership resolution: own / inherited / nested -------------------------


def test_tenant_with_inherits_billing_false_is_its_own_owner() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    try:
        assert resolve_billing_owner(child.id) == child.id
    finally:
        _cleanup_tenant_tree(child.id, parent.id)


def test_child_inherits_billing_resolves_to_parent() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        assert resolve_billing_owner(child.id) == parent.id
    finally:
        _cleanup_tenant_tree(child.id, parent.id)


def test_inherited_entitlements_read_parents_plan() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    try:
        create_plan(plan_key, "Parent Plan", entitlements={"seats": 50})
        _subscribe(parent.id, plan_key)
        assert get_entitlements(child.id) == {"seats": 50}
        # The child's own (nonexistent) subscription is irrelevant -- the
        # parent's plan is what's read.
        assert get_entitlements(parent.id) == {"seats": 50}
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)


def test_nested_inheritance_resolves_to_nearest_non_inheriting_ancestor() -> None:
    """grandparent (owns) <- parent (inherits) <- child (inherits):
    resolves all the way up to grandparent."""
    grandparent = create_tenant(_unique_name("gp"))
    parent = create_tenant(_unique_name("parent"), parent_id=grandparent.id)
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        assert resolve_billing_owner(child.id) == grandparent.id
        assert resolve_billing_owner(parent.id) == grandparent.id
    finally:
        _cleanup_tenant_tree(child.id, parent.id, grandparent.id)


def test_nested_inheritance_stops_at_nearest_owning_ancestor() -> None:
    """grandparent (owns) <- parent (OWNS, opts out) <- child (inherits):
    resolves to parent, never skips past it to grandparent."""
    grandparent = create_tenant(_unique_name("gp"))
    parent = create_tenant(_unique_name("parent"), parent_id=grandparent.id)
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        assert resolve_billing_owner(child.id) == parent.id
    finally:
        _cleanup_tenant_tree(child.id, parent.id, grandparent.id)


def test_explicit_opt_out_after_inheriting_is_respected() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    assert resolve_billing_owner(child.id) == parent.id
    opt_out_of_billing_inheritance(_BILLING_SYSTEM, child.id)
    try:
        assert resolve_billing_owner(child.id) == child.id
    finally:
        _cleanup_tenant_tree(child.id, parent.id)


# --- Invalid configuration: fail closed --------------------------------


def test_root_tenant_with_inherits_billing_true_fails_closed() -> None:
    root = create_tenant(_unique_name("root"))
    _seed_legacy_billing_inheritance(root.id)
    try:
        with pytest.raises(InvalidBillingHierarchyError):
            resolve_billing_owner(root.id)
    finally:
        _cleanup_tenant_tree(root.id)


def test_fully_inheriting_chain_up_to_root_fails_closed() -> None:
    """Every ancestor, up to and including the root, inherits -- nobody
    in the chain actually owns billing."""
    root = create_tenant(_unique_name("root"))
    parent = create_tenant(_unique_name("parent"), parent_id=root.id)
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(root.id)
    _seed_legacy_billing_inheritance(parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        with pytest.raises(InvalidBillingHierarchyError):
            resolve_billing_owner(child.id)
    finally:
        _cleanup_tenant_tree(child.id, parent.id, root.id)


def test_invalid_hierarchy_fails_closed_never_falls_back_to_self() -> None:
    """A failed resolution must never silently treat the tenant as its
    own owner -- that would reactivate billing for a tenant that
    explicitly opted into inheritance."""
    root = create_tenant(_unique_name("root"))
    _seed_legacy_billing_inheritance(root.id)
    try:
        with pytest.raises(InvalidBillingHierarchyError):
            resolve_billing_owner(root.id)
        # get_entitlements must propagate the same fail-closed error,
        # never silently return {} or the tenant's own (nonexistent) plan.
        with pytest.raises(InvalidBillingHierarchyError):
            get_entitlements(root.id)
    finally:
        _cleanup_tenant_tree(root.id)


def test_resolve_billing_owner_on_unknown_tenant_fails_closed() -> None:
    from saas_os.core.tenancy import TenantNotFoundError

    with pytest.raises(TenantNotFoundError):
        resolve_billing_owner(uuid.uuid4())


# --- Never crosses branches / never returns a sibling -----------------------


def test_resolution_never_returns_a_sibling() -> None:
    parent = create_tenant(_unique_name("parent"))
    child_a = create_tenant(_unique_name("child-a"), parent_id=parent.id)
    child_b = create_tenant(_unique_name("child-b"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child_a.id)
    try:
        owner = resolve_billing_owner(child_a.id)
        assert owner == parent.id
        assert owner != child_b.id
    finally:
        _cleanup_tenant_tree(child_a.id, child_b.id, parent.id)


def test_resolution_never_crosses_unrelated_branches() -> None:
    unrelated_root = create_tenant(_unique_name("unrelated"))
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        owner = resolve_billing_owner(child.id)
        assert owner == parent.id
        assert owner != unrelated_root.id
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_tenant_tree(unrelated_root.id)


# --- Hierarchy moves ---------------------------------------------------


def test_moving_a_tenant_changes_future_resolution_only() -> None:
    old_parent = create_tenant(_unique_name("old-parent"))
    new_parent = create_tenant(_unique_name("new-parent"))
    child = create_tenant(_unique_name("child"), parent_id=old_parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    try:
        create_plan(plan_key, "Old Plan", entitlements={"x": 1})
        _subscribe(old_parent.id, plan_key)
        assert resolve_billing_owner(child.id) == old_parent.id
        assert get_entitlements(child.id) == {"x": 1}

        move_tenant(child.id, new_parent.id)

        # Resolution reflects the NEW hierarchy on the very next call --
        # no caching, nothing to invalidate.
        assert resolve_billing_owner(child.id) == new_parent.id
        # The new parent has no subscription -> safe-default {}, not an
        # error and not a leftover of the old parent's plan.
        assert get_entitlements(child.id) == {}
    finally:
        _cleanup_tenant_tree(child.id, old_parent.id, new_parent.id)
        _cleanup_plan(plan_key)


def test_moving_a_tenant_does_not_rewrite_historical_subscription() -> None:
    """Old Parent's own Subscription row is completely untouched by the
    child moving away from it."""
    old_parent = create_tenant(_unique_name("old-parent"))
    new_parent = create_tenant(_unique_name("new-parent"))
    child = create_tenant(_unique_name("child"), parent_id=old_parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    try:
        create_plan(plan_key, "Old Plan", entitlements={"x": 1})
        subscription = subscribe(old_parent.id, plan_key, provider=FakeBillingProvider())
        move_tenant(child.id, new_parent.id)

        with tenant_session_scope(old_parent.id) as session:
            row = session.get(type(subscription), subscription.id)
            assert row is not None
            assert row.tenant_id == old_parent.id
            assert row.plan_id == subscription.plan_id
            assert row.status == "active"
    finally:
        _cleanup_tenant_tree(child.id, old_parent.id, new_parent.id)
        _cleanup_plan(plan_key)


# --- Concurrency ---------------------------------------------------------


def test_concurrent_resolution_is_deterministic() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        results: list[uuid.UUID] = []
        lock = threading.Lock()

        def _resolve() -> None:
            owner = resolve_billing_owner(child.id)
            with lock:
                results.append(owner)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: _resolve(), range(8)))

        assert len(results) == 8
        assert all(r == parent.id for r in results)
    finally:
        _cleanup_tenant_tree(child.id, parent.id)


def test_concurrent_move_and_resolution_never_produces_invalid_owner() -> None:
    """A resolution racing a hierarchy move must always return either the
    old or the new parent -- never a crash, never a sibling, never an
    unrelated tenant."""
    old_parent = create_tenant(_unique_name("old-parent"))
    new_parent = create_tenant(_unique_name("new-parent"))
    child = create_tenant(_unique_name("child"), parent_id=old_parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        results: list[uuid.UUID] = []
        errors: list[Exception] = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def _resolve() -> None:
            barrier.wait()
            try:
                owner = resolve_billing_owner(child.id)
                with lock:
                    results.append(owner)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        def _move() -> None:
            barrier.wait()
            move_tenant(child.id, new_parent.id)

        t1 = threading.Thread(target=_resolve)
        t2 = threading.Thread(target=_move)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors
        assert len(results) == 1
        assert results[0] in {old_parent.id, new_parent.id}
    finally:
        _cleanup_tenant_tree(child.id, old_parent.id, new_parent.id)


# --- Security: billing inheritance never grants authorization --------------


def test_billing_inheritance_grants_no_authorization_to_parent_over_child() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        resolve_billing_owner(child.id)  # confirm inheritance is active

        parent_admin = create_user().id
        add_tenant_membership(parent.id, parent_admin, caller=_PROVISIONING)
        assert not can(
            actor_id=parent_admin, tenant_id=child.id, action="read", resource="anything"
        )
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_user(parent_admin)


def test_billing_inheritance_grants_no_authorization_to_child_over_parent() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    try:
        child_admin = create_user().id
        add_tenant_membership(child.id, child_admin, caller=_PROVISIONING)
        assert not can(
            actor_id=child_admin, tenant_id=parent.id, action="read", resource="anything"
        )
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_user(child_admin)


def test_billing_inheritance_does_not_change_sibling_isolation() -> None:
    parent = create_tenant(_unique_name("parent"))
    child_a = create_tenant(_unique_name("child-a"), parent_id=parent.id)
    child_b = create_tenant(_unique_name("child-b"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child_a.id)
    _seed_legacy_billing_inheritance(child_b.id)
    try:
        user_a = create_user().id
        add_tenant_membership(child_a.id, user_a, caller=_PROVISIONING)
        assert not can(actor_id=user_a, tenant_id=child_b.id, action="read", resource="anything")
    finally:
        _cleanup_tenant_tree(child_a.id, child_b.id, parent.id)
        _cleanup_user(user_a)


def test_billing_inheritance_does_not_bypass_role_scope() -> None:
    """A SELF-scoped role at the parent must still not reach the child,
    exactly as before Phase H -- billing inheritance changes nothing
    about `RoleScope` evaluation."""
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    resource, action = _unique_name("resource"), "read"
    try:
        user_id = create_user().id
        membership = add_tenant_membership(parent.id, user_id, caller=_PROVISIONING)
        role = create_role(parent.id, _unique_name("role"), caller=_PROVISIONING)
        permission = register_permission(resource, action)
        grant_permission(parent.id, role.id, permission.id, caller=_PROVISIONING)
        assign_first_role_for_new_tenant(
            parent.id, membership.id, role.id, scope=RoleScope.SELF, caller=_PROVISIONING
        )

        assert can(actor_id=user_id, tenant_id=parent.id, action=action, resource=resource)
        assert not can(actor_id=user_id, tenant_id=child.id, action=action, resource=resource)
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_user(user_id)
        _cleanup_permission(resource, action)


# =============================================================================
# Billing-owner CONSISTENCY REPAIR: subscribe/upgrade/cancel resolve through
# resolve_billing_owner() exactly like get_entitlements() already does.
# =============================================================================


# --- Flat tenant: byte-for-byte unchanged -----------------------------------


def test_flat_tenant_subscribe_upgrade_cancel_operate_on_its_own_subscription() -> None:
    tenant = create_tenant(_unique_name("flat"))
    plan_key = _unique_name("plan")
    other_plan_key = _unique_name("plan2")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        create_plan(other_plan_key, "Plan 2", entitlements={"x": 2})
        provider = FakeBillingProvider()

        subscription = subscribe(tenant.id, plan_key, provider=provider)
        assert subscription.tenant_id == tenant.id

        upgraded = upgrade_subscription(
            tenant.id, subscription.id, other_plan_key, provider=provider
        )
        assert upgraded.tenant_id == tenant.id
        assert get_entitlements(tenant.id) == {"x": 2}

        canceled = cancel_subscription(tenant.id, subscription.id, provider=provider)
        assert canceled.tenant_id == tenant.id
        assert canceled.status == "canceled"
    finally:
        _cleanup_tenant_tree(tenant.id)
        _cleanup_plan(plan_key)
        _cleanup_plan(other_plan_key)


# --- Inherited tenant: mutations resolve to the parent ----------------------


def test_inherited_tenant_upgrade_fails_closed_and_leaves_the_parent_untouched() -> None:
    """Supersedes `test_inherited_tenant_upgrade_operates_on_parents_subscription`
    (Phase 5.3 step 5, ADR-0029 amendment): a legacy upgrade through an
    inheriting tenant is no longer redirected to the ancestor -- it fails
    closed; read compatibility (`get_entitlements()`) is unchanged."""
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    new_plan_key = _unique_name("plan2")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        create_plan(new_plan_key, "Plan 2", entitlements={"x": 2})
        provider = FakeBillingProvider()
        subscription = subscribe(parent.id, plan_key, provider=provider)

        with pytest.raises(InheritedBillingSubscriptionError):
            upgrade_subscription(child.id, subscription.id, new_plan_key, provider=provider)

        with tenant_session_scope(parent.id) as session:
            row = session.get(type(subscription), subscription.id)
            assert row is not None
            assert (row.plan_id, row.status) == (subscription.plan_id, "active")
        assert get_entitlements(child.id) == {"x": 1}  # still read-compatible
        assert get_entitlements(parent.id) == {"x": 1}
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)
        _cleanup_plan(new_plan_key)


def test_inherited_tenant_cancel_fails_closed_and_never_cancels_the_ancestor() -> None:
    """Supersedes `test_inherited_tenant_cancel_operates_on_parents_subscription`
    (Phase 5.3 step 5): canceling through an inheriting tenant fails closed
    before the provider is touched; the ancestor's subscription stays live."""
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        provider = FakeBillingProvider()
        subscription = subscribe(parent.id, plan_key, provider=provider)

        with pytest.raises(InheritedBillingSubscriptionError):
            cancel_subscription(child.id, subscription.id, provider=provider)

        with tenant_session_scope(parent.id) as session:
            row = session.get(type(subscription), subscription.id)
            assert row is not None
            assert (row.plan_id, row.status) == (subscription.plan_id, "active")
        assert (
            provider.get_subscription_status(
                provider_subscription_id=subscription.provider_subscription_id
            ).value
            == "active"
        )  # the provider was never asked to cancel
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)


def test_a_refused_inherited_mutation_leaves_no_evidence_of_success() -> None:
    """Supersedes `test_upgrade_audit_records_effective_owner_and_requested_tenant`:
    a refused inherited upgrade or cancel writes no audit entry and no
    subscription version anywhere -- it changed nothing."""
    from saas_os.core.audit_log.service import list as list_audit_entries

    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    new_plan_key = _unique_name("plan2")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        create_plan(new_plan_key, "Plan 2", entitlements={"x": 2})
        provider = FakeBillingProvider()
        subscription = subscribe(parent.id, plan_key, provider=provider)
        with pytest.raises(InheritedBillingSubscriptionError):
            upgrade_subscription(child.id, subscription.id, new_plan_key, provider=provider)
        with pytest.raises(InheritedBillingSubscriptionError):
            cancel_subscription(child.id, subscription.id, provider=provider)

        actions = {e.action for e in list_audit_entries(parent.id)} | {
            e.action for e in list_audit_entries(child.id)
        }
        assert "billing.subscription_upgraded" not in actions
        assert "billing.subscription_canceled" not in actions
        with tenant_session_scope(parent.id) as session:
            row = session.get(type(subscription), subscription.id)
            assert row is not None and row.version == subscription.version
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)
        _cleanup_plan(new_plan_key)


# --- No fallback to a child/sibling subscription ----------------------------


def test_inherited_tenant_upgrade_with_no_owner_subscription_fails_closed() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    new_plan_key = _unique_name("plan2")
    try:
        create_plan(new_plan_key, "Plan 2", entitlements={"x": 2})
        with pytest.raises(InheritedBillingSubscriptionError):
            upgrade_subscription(child.id, uuid.uuid4(), new_plan_key)
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(new_plan_key)


def test_upgrade_does_not_fall_back_to_childs_own_stray_subscription() -> None:
    """Even if the child happens to hold its own (orphaned) Subscription
    row -- e.g. created before `inherits_billing` was set -- upgrading via
    the child must never fall back to mutating it; only the resolved
    owner's own row is ever eligible."""
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    plan_key = _unique_name("plan")
    new_plan_key = _unique_name("plan2")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        create_plan(new_plan_key, "Plan 2", entitlements={"x": 2})
        provider = FakeBillingProvider()
        # Child subscribes to its own plan WHILE it still owns its own
        # billing (inherits_billing=False) -- a legitimate row.
        child_subscription = subscribe(child.id, plan_key, provider=provider)
        # Only now does it opt into inheritance.
        _seed_legacy_billing_inheritance(child.id)

        with pytest.raises(InheritedBillingSubscriptionError):
            upgrade_subscription(child.id, child_subscription.id, new_plan_key, provider=provider)
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)
        _cleanup_plan(new_plan_key)


def test_upgrade_cannot_target_a_siblings_subscription() -> None:
    parent = create_tenant(_unique_name("parent"))
    child_a = create_tenant(_unique_name("child-a"), parent_id=parent.id)
    child_b = create_tenant(_unique_name("child-b"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child_a.id)
    plan_key = _unique_name("plan")
    new_plan_key = _unique_name("plan2")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        create_plan(new_plan_key, "Plan 2", entitlements={"x": 2})
        provider = FakeBillingProvider()
        # child_b owns its own billing and has its own subscription --
        # never a valid target for child_a's (parent-resolved) mutation.
        sibling_subscription = subscribe(child_b.id, plan_key, provider=provider)

        with pytest.raises(InheritedBillingSubscriptionError):
            upgrade_subscription(
                child_a.id, sibling_subscription.id, new_plan_key, provider=provider
            )
    finally:
        _cleanup_tenant_tree(child_a.id, child_b.id, parent.id)
        _cleanup_plan(plan_key)
        _cleanup_plan(new_plan_key)


# --- subscribe() fails closed for an inheriting tenant ----------------------


def test_subscribe_on_inheriting_tenant_fails_closed() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        provider = FakeBillingProvider()

        with pytest.raises(InheritedBillingSubscriptionError):
            subscribe(child.id, plan_key, provider=provider)

        # No subscription was created anywhere -- not for the child, and
        # not silently redirected to the parent either.
        with tenant_session_scope(child.id) as session:
            count = session.execute(
                text("SELECT COUNT(*) FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(child.id)},
            ).scalar_one()
        assert count == 0
        with tenant_session_scope(parent.id) as session:
            count = session.execute(
                text("SELECT COUNT(*) FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(parent.id)},
            ).scalar_one()
        assert count == 0
        # The provider was never called at all.
        assert provider._subscriptions == {}
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)


def test_subscribing_the_resolved_owner_directly_still_works() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        provider = FakeBillingProvider()
        owner_id = resolve_billing_owner(child.id)
        subscription = subscribe(owner_id, plan_key, provider=provider)
        assert subscription.tenant_id == parent.id
        assert get_entitlements(child.id) == {"x": 1}
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)


# --- Nested inheritance: all mutations resolve to the same owner -----------


def test_nested_inherited_mutations_fail_closed_at_every_level() -> None:
    """Supersedes `test_nested_inherited_billing_mutations_resolve_to_same_owner`:
    neither an inheriting child nor an inheriting parent can mutate the
    grandparent's subscription; reads still resolve to it."""
    grandparent = create_tenant(_unique_name("gp"))
    parent = create_tenant(_unique_name("parent"), parent_id=grandparent.id)
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    new_plan_key = _unique_name("plan2")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        create_plan(new_plan_key, "Plan 2", entitlements={"x": 2})
        provider = FakeBillingProvider()
        subscription = subscribe(grandparent.id, plan_key, provider=provider)

        with pytest.raises(InheritedBillingSubscriptionError):
            upgrade_subscription(child.id, subscription.id, new_plan_key, provider=provider)
        with pytest.raises(InheritedBillingSubscriptionError):
            cancel_subscription(parent.id, subscription.id, provider=provider)
        with tenant_session_scope(grandparent.id) as session:
            row = session.get(type(subscription), subscription.id)
            assert row is not None
            assert (row.plan_id, row.status) == (subscription.plan_id, "active")
        assert get_entitlements(child.id) == {"x": 1}
    finally:
        _cleanup_tenant_tree(child.id, parent.id, grandparent.id)
        _cleanup_plan(plan_key)
        _cleanup_plan(new_plan_key)


# --- Hierarchy move: mutations follow the NEW owner, history untouched -----


def test_after_a_move_reads_follow_the_new_owner_and_mutations_still_fail_closed() -> None:
    """Supersedes `test_hierarchy_move_redirects_future_mutations_to_new_owner`:
    a moved inheriting tenant reads its NEW owner's plan (resolution is
    live), but cannot mutate either owner's subscription."""
    old_parent = create_tenant(_unique_name("old-parent"))
    new_parent = create_tenant(_unique_name("new-parent"))
    child = create_tenant(_unique_name("child"), parent_id=old_parent.id)
    _seed_legacy_billing_inheritance(child.id)
    old_plan_key = _unique_name("plan-old")
    new_plan_key = _unique_name("plan-new")
    changed_plan_key = _unique_name("plan-changed")
    try:
        create_plan(old_plan_key, "Old Plan", entitlements={"x": 1})
        create_plan(new_plan_key, "New Plan", entitlements={"x": 2})
        create_plan(changed_plan_key, "Changed Plan", entitlements={"x": 3})
        provider = FakeBillingProvider()
        old_subscription = subscribe(old_parent.id, old_plan_key, provider=provider)
        new_subscription = subscribe(new_parent.id, new_plan_key, provider=provider)

        move_tenant(child.id, new_parent.id)
        assert get_entitlements(child.id) == {"x": 2}

        for target in (new_subscription, old_subscription):
            with pytest.raises(InheritedBillingSubscriptionError):
                upgrade_subscription(child.id, target.id, changed_plan_key, provider=provider)
        with tenant_session_scope(old_parent.id) as session:
            row = session.get(type(old_subscription), old_subscription.id)
            assert row is not None
            assert (row.plan_id, row.status) == (old_subscription.plan_id, "active")
        with tenant_session_scope(new_parent.id) as session:
            row = session.get(type(new_subscription), new_subscription.id)
            assert row is not None
            assert (row.plan_id, row.status) == (new_subscription.plan_id, "active")
    finally:
        _cleanup_tenant_tree(child.id, old_parent.id, new_parent.id)
        _cleanup_plan(old_plan_key)
        _cleanup_plan(new_plan_key)
        _cleanup_plan(changed_plan_key)


# --- Idempotency: fails closed repeatably, never touches the provider ------


def test_subscribe_idempotent_on_inheriting_tenant_fails_closed_repeatably() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    idempotency_key = _unique_name("idem")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        provider = FakeBillingProvider()

        with pytest.raises(InheritedBillingSubscriptionError):
            subscribe_idempotent(child.id, plan_key, idempotency_key, provider=provider)
        with pytest.raises(InheritedBillingSubscriptionError):
            subscribe_idempotent(child.id, plan_key, idempotency_key, provider=provider)

        # Never replayed as a cached "success", and the provider was
        # never actually invoked either time.
        assert provider._subscriptions == {}
        with tenant_session_scope(child.id) as session:
            count = session.execute(
                text("SELECT COUNT(*) FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(child.id)},
            ).scalar_one()
        assert count == 0
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)


def test_subscribe_idempotent_flat_tenant_still_idempotent() -> None:
    """Regression: the ordinary flat-tenant idempotency guarantee
    (`tests/core/billing/test_subscribe_idempotent_integration.py`) is
    unaffected by the billing-owner consistency repair."""
    tenant = create_tenant(_unique_name("flat"))
    plan_key = _unique_name("plan")
    idempotency_key = _unique_name("idem")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        provider = FakeBillingProvider()

        is_replay_1, result_1 = subscribe_idempotent(
            tenant.id, plan_key, idempotency_key, provider=provider
        )
        is_replay_2, result_2 = subscribe_idempotent(
            tenant.id, plan_key, idempotency_key, provider=provider
        )

        assert is_replay_1 is False
        assert is_replay_2 is True
        assert result_1.subscription_id == result_2.subscription_id
        assert len(provider._subscriptions) == 1
    finally:
        _cleanup_tenant_tree(tenant.id)
        _cleanup_plan(plan_key)


# --- Authorization remains unaffected by the consistency repair ------------


def test_billing_owner_mutation_grants_no_authorization() -> None:
    parent = create_tenant(_unique_name("parent"))
    child = create_tenant(_unique_name("child"), parent_id=parent.id)
    _seed_legacy_billing_inheritance(child.id)
    plan_key = _unique_name("plan")
    try:
        create_plan(plan_key, "Plan", entitlements={"x": 1})
        provider = FakeBillingProvider()
        subscribe(parent.id, plan_key, provider=provider)

        child_user = create_user().id
        add_tenant_membership(child.id, child_user, caller=_PROVISIONING)
        assert not can(actor_id=child_user, tenant_id=parent.id, action="read", resource="anything")
    finally:
        _cleanup_tenant_tree(child.id, parent.id)
        _cleanup_plan(plan_key)
        _cleanup_user(child_user)
