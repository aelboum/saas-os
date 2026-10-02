"""RE-4: webhook subscription lifecycle authority, against real PostgreSQL.

`subscribe()`/`unsubscribe()` are the only mutating subscription operations
(there is no update, enable/disable or secret rotation). Both now follow
the Foundation Authority & Evidence model (ADR-0031):

- an explicit typed `caller` -- never an optional actor id, never `None`
  meaning "system";
- `can()` evaluated inside the mutation's own tenant transaction, so explicit
  deny applies and a principal authorized in one tenant has no authority in
  another;
- the audit entry written in that same transaction (`record_in_transaction`),
  naming the authorized caller; a failed audit write rolls the mutation back;
- the subscription lookup scoped by RLS to the caller's tenant.

Support access can never satisfy `webhook_subscription` -- it is in
`AUTHORITY_RESOURCES`, proven for every such resource by
`tests/core/rbac/test_authority_evidence_integration.py`.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from typing import Any

import core.webhooks.service as webhooks_service
import pytest
from core.authority import CallerTypeError, SystemAuthority, SystemCaller, UserCaller
from core.identity.service import add_tenant_membership, create_user
from core.rbac.errors import AuthorityNotAuthorizedError
from core.rbac.models import DenyGrant
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from core.webhooks.service import list_subscriptions, subscribe, unsubscribe
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import core.rbac  # noqa: F401 -- registers the mappers core.audit_log references by name
from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_URL = "https://hooks.example.com/re4"


@pytest.fixture(autouse=True)
def _require_database() -> None:
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
            conn.execute(text("SELECT 1 FROM core.webhook_subscriptions LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated: {exc}")
    finally:
        probe.dispose()


def _admin(sql: str, params: Mapping[str, object]) -> list[Any]:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            result = session.execute(text(sql), params)
            return list(result) if sql.lstrip().upper().startswith("SELECT") else []
    finally:
        engine.dispose()


class _World:
    def __init__(self) -> None:
        self.tenants: list[uuid.UUID] = []
        self.users: list[uuid.UUID] = []

    def tenant(self) -> uuid.UUID:
        tenant_id = create_tenant(f"re4-authority-{uuid.uuid4().hex[:10]}").id
        self.tenants.append(tenant_id)
        return tenant_id

    def member(self, tenant_id: uuid.UUID, *capabilities: tuple[str, str]) -> UserCaller:
        user_id = create_user().id
        self.users.append(user_id)
        membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        role = create_role(tenant_id, f"role-{uuid.uuid4().hex[:8]}", caller=_PROVISIONING)
        for resource, action in capabilities:
            permission = register_permission(resource, action)
            grant_permission(tenant_id, role.id, permission.id, caller=_PROVISIONING)
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=_PROVISIONING)
        return UserCaller(user_id)

    def deny(self, tenant_id: uuid.UUID, user: UserCaller, resource: str, action: str) -> None:
        permission = register_permission(resource, action)
        with tenant_session_scope(tenant_id) as session:
            session.add(
                DenyGrant(
                    tenant_id=tenant_id,
                    principal_type="user",
                    principal_id=user.user_id,
                    scope_mode="self",
                    permission_id=permission.id,
                )
            )

    def cleanup(self) -> None:
        for tenant_id in self.tenants:
            params = {"t": str(tenant_id)}
            for table in (
                "webhook_subscriptions",
                "deny_grants",
                "membership_roles",
                "role_permissions",
                "roles",
                "tenant_memberships",
            ):
                _admin(f"DELETE FROM core.{table} WHERE tenant_id = :t", params)  # noqa: S608
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)
        for user_id in self.users:
            params = {"u": str(user_id)}
            _admin("DELETE FROM core.audit_log WHERE actor_user_id = :u", params)
            _admin("DELETE FROM core.users WHERE id = :u", params)


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


_MANAGE = (("webhook_subscription", "create"), ("webhook_subscription", "delete"))


def _audit(tenant_id: uuid.UUID, action: str) -> list[tuple[Any, ...]]:
    return _admin(
        "SELECT actor_type, actor_user_id, resource_id FROM core.audit_log "
        "WHERE tenant_id = :t AND action = :a",
        {"t": str(tenant_id), "a": action},
    )


# --- Authorized lifecycle, with same-transaction evidence --------------------------


def test_an_authorized_member_creates_and_deletes_with_audit_evidence(world: _World) -> None:
    tenant_id = world.tenant()
    admin = world.member(tenant_id, *_MANAGE)

    subscription, _ = subscribe(tenant_id, _URL, caller=admin)
    assert [s.id for s in list_subscriptions(tenant_id)] == [subscription.id]
    assert _audit(tenant_id, "webhook.subscription_created") == [
        ("user", admin.user_id, str(subscription.id))
    ]

    unsubscribe(tenant_id, subscription.id, caller=admin)
    assert list_subscriptions(tenant_id) == []
    assert _audit(tenant_id, "webhook.subscription_deleted") == [
        ("user", admin.user_id, str(subscription.id))
    ]


def test_a_failed_audit_write_rolls_the_subscription_back(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()
    admin = world.member(tenant_id, *_MANAGE)

    def _audit_down(*_: object, **__: object) -> None:
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(webhooks_service, "record_in_transaction", _audit_down)
    with pytest.raises(RuntimeError):
        subscribe(tenant_id, _URL, caller=admin)
    assert list_subscriptions(tenant_id) == []


def test_a_failed_audit_write_rolls_the_deletion_back(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()
    admin = world.member(tenant_id, *_MANAGE)
    subscription, _ = subscribe(tenant_id, _URL, caller=admin)

    def _audit_down(*_: object, **__: object) -> None:
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(webhooks_service, "record_in_transaction", _audit_down)
    with pytest.raises(RuntimeError):
        unsubscribe(tenant_id, subscription.id, caller=admin)
    assert [s.id for s in list_subscriptions(tenant_id)] == [subscription.id]


# --- Refusals ------------------------------------------------------------------------


def test_a_member_without_the_capability_is_refused_and_nothing_is_written(
    world: _World,
) -> None:
    tenant_id = world.tenant()
    member = world.member(tenant_id)
    subscription, _ = subscribe(tenant_id, _URL, caller=_PROVISIONING)

    with pytest.raises(AuthorityNotAuthorizedError):
        subscribe(tenant_id, "https://hooks.example.com/other", caller=member)
    with pytest.raises(AuthorityNotAuthorizedError):
        unsubscribe(tenant_id, subscription.id, caller=member)
    # ...and the same refusal for an id that does not exist: no enumeration.
    with pytest.raises(AuthorityNotAuthorizedError):
        unsubscribe(tenant_id, uuid.uuid4(), caller=member)

    assert [s.id for s in list_subscriptions(tenant_id)] == [subscription.id]
    assert [r[1] for r in _audit(tenant_id, "webhook.subscription_created")] == [None]
    assert _audit(tenant_id, "webhook.subscription_deleted") == []


def test_an_explicit_deny_overrides_the_capability(world: _World) -> None:
    tenant_id = world.tenant()
    admin = world.member(tenant_id, *_MANAGE)
    world.deny(tenant_id, admin, "webhook_subscription", "create")

    with pytest.raises(AuthorityNotAuthorizedError):
        subscribe(tenant_id, _URL, caller=admin)
    assert list_subscriptions(tenant_id) == []


def test_authority_in_one_tenant_is_no_authority_in_another(world: _World) -> None:
    tenant_a, tenant_b = world.tenant(), world.tenant()
    admin_a = world.member(tenant_a, *_MANAGE)
    subscription_b, _ = subscribe(tenant_b, _URL, caller=_PROVISIONING)

    with pytest.raises(AuthorityNotAuthorizedError):
        subscribe(tenant_b, _URL, caller=admin_a)
    with pytest.raises(AuthorityNotAuthorizedError):
        unsubscribe(tenant_b, subscription_b.id, caller=admin_a)
    # Authorized in A, naming B's subscription id under tenant A: RLS scopes
    # the lookup to A, so it is not found and nothing is deleted or audited.
    unsubscribe(tenant_a, subscription_b.id, caller=admin_a)

    assert [s.id for s in list_subscriptions(tenant_b)] == [subscription_b.id]
    assert _audit(tenant_a, "webhook.subscription_deleted") == []


@pytest.mark.parametrize("bad_caller", [None, uuid.uuid4(), "user", object()])
def test_a_missing_or_untyped_caller_is_refused(world: _World, bad_caller: object) -> None:
    tenant_id = world.tenant()
    with pytest.raises(CallerTypeError):
        subscribe(tenant_id, _URL, caller=bad_caller)  # type: ignore[arg-type]
    with pytest.raises(CallerTypeError):
        unsubscribe(tenant_id, uuid.uuid4(), caller=bad_caller)  # type: ignore[arg-type]
    assert list_subscriptions(tenant_id) == []


def test_only_provisioning_system_authority_is_accepted(world: _World) -> None:
    tenant_id = world.tenant()
    with pytest.raises(AuthorityNotAuthorizedError):
        subscribe(tenant_id, _URL, caller=SystemCaller(SystemAuthority.TENANT_PURGE))
    subscription, _ = subscribe(tenant_id, _URL, caller=_PROVISIONING)
    assert _audit(tenant_id, "webhook.subscription_created") == [
        ("system", None, str(subscription.id))
    ]
