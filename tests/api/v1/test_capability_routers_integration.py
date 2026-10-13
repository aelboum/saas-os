"""The opt-in capability routers (docs/ADR/0040-...) against real PostgreSQL
and Redis, through the real ingress chain.

What is proven here, per router and across all of them:

- **opt-in**: on an application that did not register a router, its
  routes do not exist, even for a fully authorized administrator;
- **the denial matrix**, for every one of the 18 routes: no credential
  (401), an authenticated non-member (404), a member without the
  permission (403), and an administrator of another tenant naming this
  tenant in the path (404);
- **cross-tenant object ids**: another tenant's membership, invitation,
  API key or subscription under the caller's own tenant path is the same
  404 as an id that does not exist;
- **one-time secrets**: an invitation token and an API key appear once,
  in the issuing response, and never in a list;
- **billing invariants are Core's**: a subscription needs authority at
  the payer as well as at the service tenant, needs an idempotency key,
  and a replay creates nothing new;
- **audit evidence** for a mutation and for a denial.

Marked `integration`. The reusable permission-gate negative control is
the matrix itself: each route is called by a member who holds every
capability permission except that route's own (403), and by one who
holds only that permission (not 403). Gate a route with the wrong
permission and one of the two cases fails.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import PROVISIONING, platform_operator
from saas_os.api.platform import build_platform_app
from saas_os.api.v1 import (
    CAPABILITY_PERMISSIONS,
    api_keys_router,
    build_billing_router,
    invitations_router,
    members_router,
    register_capability_permissions,
    usage_router,
)
from saas_os.core.api_keys import validate_api_key
from saas_os.core.api_keys.errors import RevokedApiKeyError
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.billing import FakeBillingProvider, get_entitlements, projections
from saas_os.core.billing.catalog import create_owned_plan
from saas_os.core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
)
from saas_os.core.identity import get_membership
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.identity.sessions import issue_session
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import (
    TenantStatus,
    create_tenant,
    get_tenancy_config,
    transition_tenant_status,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload
from saas_os.infra.ratelimit.config import get_ratelimit_config

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
_CHARGE = ("billing.account", "charge")


@pytest.fixture(autouse=True)
def _require_reachable_database_and_redis() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_ratelimit_config.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.membership_roles LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.membership_roles not reachable: {exc}")
    finally:
        probe.dispose()
    try:
        config = get_ratelimit_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    import redis as redis_sync

    try:
        redis_sync.Redis.from_url(config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}")


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _as_admin(statement: str, **params: object) -> list[tuple[Any, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return [tuple(row) for row in conn.execute(text(statement), params).all()]
    finally:
        engine.dispose()


class _World:
    """Everything a test creates, torn down with the privileged migration
    role in foreign-key order."""

    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    def tenant(self, label: str) -> uuid.UUID:
        tenant = create_tenant(_unique(label), caller=PROVISIONING)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(self) -> tuple[uuid.UUID, str]:
        user = create_user()
        self.user_ids.append(user.id)
        _, token = issue_session(user.id)
        return user.id, token

    def member(
        self, tenant_id: uuid.UUID, permissions: list[tuple[str, str]] | None = None
    ) -> tuple[uuid.UUID, str, uuid.UUID]:
        """A user with an ACTIVE membership in `tenant_id`, holding exactly
        `permissions` (none when omitted). Returns (user id, session token,
        membership id)."""
        user_id, token = self.user()
        add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        if permissions:
            self.grant(tenant_id, user_id, permissions)
        membership = get_membership(tenant_id, user_id)
        assert membership is not None
        return user_id, token, membership.id

    def grant(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, permissions: list[tuple[str, str]]
    ) -> None:
        membership = get_membership(tenant_id, user_id)
        if membership is None:
            membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
        for resource, action in permissions:
            grant_permission(
                tenant_id, role.id, register_permission(resource, action).id, caller=_PROVISIONING
            )
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=_PROVISIONING)

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
                    "DELETE FROM core.sessions WHERE user_id = ANY(:u)",
                    "DELETE FROM core.invitations WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.api_keys WHERE tenant_id = ANY(:t)",
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
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
                    "DELETE FROM core.platform_audit_log WHERE target_tenant_id = ANY(:t)",
                    "DELETE FROM core.tenants WHERE id = ANY(:t)",
                    "DELETE FROM core.users WHERE id = ANY(:u)",
                ):
                    session.execute(text(statement), {"t": tenants, "u": users})
        finally:
            engine.dispose()


@pytest.fixture
def world() -> Iterator[_World]:
    register_capability_permissions()
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


@pytest.fixture(scope="module")
def provider() -> FakeBillingProvider:
    return FakeBillingProvider()


@pytest.fixture(scope="module")
def app(provider: FakeBillingProvider) -> FastAPI:
    application = build_platform_app(title="capability routers", version="test")
    application.include_router(members_router)
    application.include_router(invitations_router)
    application.include_router(api_keys_router)
    application.include_router(build_billing_router(provider=provider))
    application.include_router(usage_router)
    return application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:  # runs the lifespan: route policies, DB role guard
        yield test_client


def _auth(token: str | None, **extra: str) -> dict[str, str]:
    headers = dict(extra)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@dataclass(frozen=True)
class _Rig:
    tenant: uuid.UUID
    admin: uuid.UUID
    admin_token: str
    admin_membership: uuid.UUID
    plain: uuid.UUID
    plain_token: str
    plain_membership: uuid.UUID
    outsider_token: str


def _rig(world: _World) -> _Rig:
    tenant = world.tenant("cap")
    admin, admin_token, admin_membership = world.member(tenant, [*CAPABILITY_PERMISSIONS, _CHARGE])
    plain, plain_token, plain_membership = world.member(tenant)
    _, outsider_token = world.user()
    return _Rig(
        tenant,
        admin,
        admin_token,
        admin_membership,
        plain,
        plain_token,
        plain_membership,
        outsider_token,
    )


@pytest.fixture
def rig(world: _World) -> _Rig:
    return _rig(world)


@pytest.fixture
def other(world: _World) -> _Rig:
    return _rig(world)


# --- Opt-in ----------------------------------------------------------------------------


def test_routes_do_not_exist_on_an_application_that_did_not_register_them(rig: _Rig) -> None:
    with TestClient(build_platform_app(title="bare", version="test")) as bare:
        for path in ("members", "invitations", "api-keys", "billing/entitlements", "usage"):
            response = bare.get(f"/v1/tenants/{rig.tenant}/{path}", headers=_auth(rig.admin_token))
            assert response.status_code == 404, path
            assert response.json() == {"detail": "Not Found"}, path  # the router is absent


# --- The denial matrix, every route ------------------------------------------------------

_ID = "00000000-0000-4000-8000-000000000001"
_SUBSCRIBE_BODY = {"plan_id": _ID, "payer_tenant_id": _ID, "billing_account_id": _ID}
# (method, path under the tenant, body, the one permission that gates it, and the
# status a member holding exactly that permission gets for these arguments --
# every object id below is random, so an object route answers 404 from Core).
_PROBES: list[tuple[str, str, Mapping[str, object] | None, tuple[str, str], int]] = [
    ("GET", "members", None, ("membership", "read"), 200),
    ("POST", f"members/{_ID}/suspend", None, ("membership", "suspend"), 404),
    ("POST", f"members/{_ID}/reactivate", None, ("membership", "reactivate"), 404),
    ("POST", f"members/{_ID}/revoke", None, ("membership", "revoke"), 404),
    ("POST", "invitations", {"email": "someone@example.test"}, ("invitation", "create"), 201),
    ("GET", "invitations", None, ("invitation", "read"), 200),
    ("POST", f"invitations/{_ID}/revoke", None, ("invitation", "revoke"), 404),
    ("POST", "api-keys", {"name": "probe"}, ("api_key", "self_manage"), 201),
    ("GET", "api-keys", None, ("api_key", "self_manage"), 200),
    ("POST", f"api-keys/{_ID}/rotate", None, ("api_key", "self_manage"), 404),
    ("DELETE", f"api-keys/{_ID}", None, ("api_key", "self_manage"), 404),
    ("GET", "billing/entitlements", None, ("billing.subscription", "read"), 200),
    ("GET", "billing/plans", None, ("billing.subscription", "create"), 200),
    # Core also requires `billing.account:charge` at the payer (ADR-0029), and
    # the payer named here is not even a real tenant: Core's generic 403.
    ("POST", "billing/subscriptions", _SUBSCRIBE_BODY, ("billing.subscription", "create"), 403),
    ("POST", f"billing/subscriptions/{_ID}/cancel", None, ("billing.subscription", "cancel"), 404),
    ("GET", "billing/payer-subscriptions", None, ("billing.account", "read"), 200),
    ("GET", f"billing/payer-subscriptions/{_ID}", None, ("billing.account", "read"), 404),
    ("GET", "usage", None, ("billing.subscription", "read"), 200),
]


def _call(client: TestClient, tenant: uuid.UUID, probe, token: str | None):  # type: ignore[no-untyped-def]
    method, path, body, _, _ = probe
    return client.request(
        method,
        f"/v1/tenants/{tenant}/{path}",
        json=body,
        headers=_auth(token, **{"Idempotency-Key": _unique("probe")}),
    )


def test_the_matrix_covers_every_route_the_routers_serve(app: FastAPI) -> None:
    from saas_os.api.route_policy import assert_route_policies

    def normalized(label: str) -> str:
        return re.sub(r"\{(?!tenant_id\})[a-z_]+\}", "{id}", label)

    served = {
        normalized(key) for key in assert_route_policies(app, production=False) if " /v1/" in key
    }
    probed = {
        f"{method} /v1/tenants/{{tenant_id}}/{path.replace(_ID, '{id}')}"
        for method, path, _, _, _ in _PROBES
    }
    assert served == probed
    assert len(_PROBES) == 18


@pytest.mark.parametrize("probe", _PROBES, ids=lambda p: f"{p[0]} {p[1].replace(_ID, 'id')}")
def test_denial_matrix(  # type: ignore[no-untyped-def]
    world: _World, client: TestClient, rig: _Rig, other: _Rig, probe
) -> None:
    permission = probe[3]
    # No credential: rejected before any tenant context exists.
    assert _call(client, rig.tenant, probe, None).status_code == 401
    # Authenticated, not a member: the tenant does not exist for them.
    outsider = _call(client, rig.tenant, probe, rig.outsider_token)
    assert outsider.status_code == 404 and outsider.json() == {"detail": "tenant not found."}
    # A member with no permission at all: refused.
    denied = _call(client, rig.tenant, probe, rig.plain_token)
    assert denied.status_code == 403 and denied.json() == {"detail": "Not authorized."}
    # A member holding EVERY capability permission except this route's own:
    # still refused. A route gated by the wrong permission, or by none of
    # its own, fails here.
    all_but_one = [p for p in (*CAPABILITY_PERMISSIONS, _CHARGE) if p != permission]
    _, near_token, _ = world.member(rig.tenant, all_but_one)
    near = _call(client, rig.tenant, probe, near_token)
    assert near.status_code == 403 and near.json() == {"detail": "Not authorized."}
    # A member holding ONLY this route's permission passes the route's gate
    # and gets exactly what Core answers for these arguments.
    _, exact_token, _ = world.member(rig.tenant, [permission])
    exact = _call(client, rig.tenant, probe, exact_token)
    assert exact.status_code == probe[4], exact.text
    # An administrator of another tenant, naming this tenant in the path:
    # indistinguishable from the non-member case.
    foreign = _call(client, rig.tenant, probe, other.admin_token)
    assert foreign.status_code == 404 and foreign.json() == {"detail": "tenant not found."}


def test_a_denial_is_recorded_as_audit_evidence(client: TestClient, rig: _Rig) -> None:
    assert (
        client.get(f"/v1/tenants/{rig.tenant}/members", headers=_auth(rig.plain_token)).status_code
        == 403
    )
    rows = _as_admin(
        "SELECT resource_id, outcome FROM core.audit_log "
        "WHERE tenant_id = :t AND action = 'api.access_denied' AND actor_user_id = :u",
        t=str(rig.tenant),
        u=str(rig.plain),
    )
    assert ("membership:read", "denied") in rows


# --- Members ---------------------------------------------------------------------------


def test_members_list_and_lifecycle(client: TestClient, rig: _Rig, other: _Rig) -> None:
    base = f"/v1/tenants/{rig.tenant}/members"
    headers = _auth(rig.admin_token)

    listed = client.get(base, headers=headers)
    assert listed.status_code == 200
    assert {m["id"] for m in listed.json()} == {
        str(rig.admin_membership),
        str(rig.plain_membership),
    }
    assert set(listed.json()[0]) == {"id", "user_id", "status", "created_at"}
    assert client.get(f"{base}?limit=1", headers=headers).json() == listed.json()[:1]
    assert client.get(f"{base}?limit=0", headers=headers).status_code == 422

    suspended = client.post(f"{base}/{rig.plain_membership}/suspend", headers=headers)
    assert suspended.status_code == 200 and suspended.json()["status"] == "suspended"
    # Core audited that specific mutation, attributed to the acting administrator.
    actions = [
        row[0]
        for row in _as_admin(
            "SELECT action FROM core.audit_log WHERE tenant_id = :t AND actor_user_id = :u",
            t=str(rig.tenant),
            u=str(rig.admin),
        )
    ]
    assert actions.count("membership.suspend") == 1, actions

    reactivated = client.post(f"{base}/{rig.plain_membership}/reactivate", headers=headers)
    assert reactivated.status_code == 200 and reactivated.json()["status"] == "active"

    revoked = client.post(f"{base}/{rig.plain_membership}/revoke", headers=headers)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    # Revocation is terminal: Core refuses the transition, the route says 409.
    again = client.post(f"{base}/{rig.plain_membership}/reactivate", headers=headers)
    assert again.status_code == 409

    # Another tenant's membership id under this tenant's path: not found,
    # and untouched.
    foreign = client.post(f"{base}/{other.plain_membership}/suspend", headers=headers)
    assert foreign.status_code == 404 and foreign.json() == {"detail": "membership not found."}
    missing = client.post(f"{base}/{uuid.uuid4()}/suspend", headers=headers)
    assert missing.status_code == 404 and missing.json() == foreign.json()
    untouched = get_membership(other.tenant, other.plain)
    assert untouched is not None and untouched.status == "active"


def test_a_suspended_member_loses_access_on_the_next_request(
    world: _World, client: TestClient, rig: _Rig
) -> None:
    reader, reader_token, reader_membership = world.member(rig.tenant, [("membership", "read")])
    base = f"/v1/tenants/{rig.tenant}/members"
    assert client.get(base, headers=_auth(reader_token)).status_code == 200
    assert (
        client.post(
            f"{base}/{reader_membership}/suspend", headers=_auth(rig.admin_token)
        ).status_code
        == 200
    )
    assert client.get(base, headers=_auth(reader_token)).status_code == 403


# --- Invitations -----------------------------------------------------------------------


def test_invitation_token_is_issued_once_and_never_listed(
    client: TestClient, rig: _Rig, other: _Rig
) -> None:
    base = f"/v1/tenants/{rig.tenant}/invitations"
    headers = _auth(rig.admin_token)
    email = f"{_unique('invitee')}@example.test"

    created = client.post(base, json={"email": email}, headers=headers)
    assert created.status_code == 201, created.text
    body = created.json()
    token = body["token"]
    assert len(token) >= 32 and body["status"] == "pending" and body["invited_email"] == email
    assert "token_hash" not in body

    listed = client.get(base, headers=headers)
    assert listed.status_code == 200
    (entry,) = listed.json()
    assert entry["id"] == body["id"]
    assert "token" not in entry and "token_hash" not in entry
    assert token not in listed.text
    # Only the hash is stored.
    (stored,) = _as_admin("SELECT token_hash FROM core.invitations WHERE id = :i", i=body["id"])
    assert stored[0] != token and token not in str(stored[0])

    assert client.post(base, json={"email": email}, headers=headers).status_code == 409
    assert client.post(base, json={"email": "not-an-email"}, headers=headers).status_code == 400

    # Another tenant's administrator cannot revoke it through their own
    # tenant's path: same answer as an id that does not exist.
    cross = client.post(
        f"/v1/tenants/{other.tenant}/invitations/{body['id']}/revoke",
        headers=_auth(other.admin_token),
    )
    assert cross.status_code == 404 and cross.json() == {"detail": "invitation not found."}

    revoked = client.post(f"{base}/{body['id']}/revoke", headers=headers)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert "token" not in revoked.json()


# --- API keys --------------------------------------------------------------------------


def test_api_keys_are_issued_once_and_confined_to_their_owner(
    world: _World, client: TestClient, rig: _Rig, other: _Rig
) -> None:
    base = f"/v1/tenants/{rig.tenant}/api-keys"
    headers = _auth(rig.admin_token)
    peer, peer_token, _ = world.member(rig.tenant, [("api_key", "self_manage")])

    created = client.post(base, json={"name": "ci"}, headers=headers)
    assert created.status_code == 201, created.text
    key_id, raw_key = created.json()["id"], created.json()["key"]
    assert "key_hash" not in created.json()
    assert validate_api_key(raw_key).id == uuid.UUID(key_id)  # a real, working key
    (stored,) = _as_admin("SELECT key_hash FROM core.api_keys WHERE id = :i", i=key_id)
    assert raw_key not in str(stored[0])

    peer_key = client.post(base, json={"name": "peer"}, headers=_auth(peer_token)).json()

    # Each member sees only their own keys, and never a key or a hash.
    mine = client.get(base, headers=headers)
    assert [k["id"] for k in mine.json()] == [key_id]
    assert raw_key not in mine.text and "key" not in mine.json()[0]
    assert [k["id"] for k in client.get(base, headers=_auth(peer_token)).json()] == [peer_key["id"]]

    # A peer's key, another tenant's path, and a missing id: the one 404.
    not_found = {"detail": "api key not found."}
    for response in (
        client.post(f"{base}/{peer_key['id']}/rotate", headers=headers),
        client.delete(f"{base}/{peer_key['id']}", headers=headers),
        client.delete(f"{base}/{uuid.uuid4()}", headers=headers),
        client.delete(
            f"/v1/tenants/{other.tenant}/api-keys/{key_id}", headers=_auth(other.admin_token)
        ),
    ):
        assert response.status_code == 404 and response.json() == not_found
    assert validate_api_key(peer_key["key"]).id == uuid.UUID(peer_key["id"])  # untouched

    rotated = client.post(f"{base}/{key_id}/rotate", headers=headers)
    assert rotated.status_code == 200
    new_id, new_key = rotated.json()["id"], rotated.json()["key"]
    assert new_id != key_id and new_key != raw_key
    with pytest.raises(RevokedApiKeyError):
        validate_api_key(raw_key)
    assert validate_api_key(new_key).id == uuid.UUID(new_id)

    assert client.delete(f"{base}/{new_id}", headers=headers).status_code == 204
    with pytest.raises(RevokedApiKeyError):
        validate_api_key(new_key)
    assert client.post(base, json={"name": ""}, headers=headers).status_code == 422


# --- Billing and usage -------------------------------------------------------------------


@dataclass(frozen=True)
class _Commerce:
    plan_id: uuid.UUID
    other_plan_id: uuid.UUID
    merchant_tenant: uuid.UUID
    merchant_account: uuid.UUID

    def account_for(self, payer_tenant_id: uuid.UUID) -> uuid.UUID:
        account, _ = get_or_create_billing_account(
            _BILLING_SYSTEM,
            payer_tenant_id,
            merchant_tenant_id=self.merchant_tenant,
            merchant_account_id=self.merchant_account,
        )
        return account.id


@pytest.fixture
def commerce(world: _World, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Commerce]:
    """A platform tenant with an active `fake` merchant selling two plans."""
    platform = world.tenant("platform")
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(platform))
    get_tenancy_config.cache_clear()
    merchant = create_merchant_account(
        _BILLING_SYSTEM,
        platform,
        provider="fake",
        provider_account_ref=_unique("acct"),
        status=MerchantAccountStatus.ACTIVE,
    )
    plan, other_plan = (
        create_owned_plan(
            _BILLING_SYSTEM,
            platform,
            merchant_account_id=merchant.id,
            key=_unique("cap-plan"),
            name="Capability plan",
            entitlements={"seats": seats},
        )
        for seats in (5, 50)
    )
    yield _Commerce(plan.id, other_plan.id, platform, merchant.id)
    get_tenancy_config.cache_clear()


def _deliver_projections(*tenant_ids: uuid.UUID) -> None:
    """Run every pending subscription-projection outbox event of these
    tenants through its consumer, oldest first."""
    for tenant_id in tenant_ids:
        events = _as_admin(
            "SELECT id, payload FROM core.outbox_events WHERE tenant_id = :t "
            "AND event_type = :e AND status = 'pending' ORDER BY created_at, id",
            t=str(tenant_id),
            e=projections.SUBSCRIPTION_CHANGED_EVENT_TYPE,
        )
        for event_id, payload in events:
            asyncio.run(
                projections._project_subscription_job(
                    TenantJobContext(tenant_id=tenant_id, event_id=event_id),
                    TenantJobPayload(tenant_id=str(tenant_id), data=dict(payload)),
                )
            )


def test_billing_subscription_lifecycle_keeps_cores_invariants(
    world: _World, client: TestClient, rig: _Rig, other: _Rig, commerce: _Commerce
) -> None:
    base = f"/v1/tenants/{rig.tenant}/billing"
    headers = _auth(rig.admin_token)
    account = commerce.account_for(rig.tenant)
    body = {
        "plan_id": str(commerce.plan_id),
        "payer_tenant_id": str(rig.tenant),
        "billing_account_id": str(account),
    }

    plans = client.get(f"{base}/plans", headers=headers)
    assert plans.status_code == 200
    assert str(commerce.plan_id) in {p["id"] for p in plans.json()}
    assert set(plans.json()[0]) == {"id", "key", "name", "entitlements"}

    # An idempotency key is mandatory.
    assert client.post(f"{base}/subscriptions", json=body, headers=headers).status_code == 400

    # Authority at the service tenant alone is not enough: Core also
    # requires `billing.account:charge` at the payer.
    _, creator_token, _ = world.member(rig.tenant, [("billing.subscription", "create")])
    half = client.post(
        f"{base}/subscriptions",
        json=body,
        headers=_auth(creator_token, **{"Idempotency-Key": _unique("half")}),
    )
    assert half.status_code == 403 and half.json() == {"detail": "Not authorized."}

    # Nor can a caller name another tenant as the payer.
    substituted = client.post(
        f"{base}/subscriptions",
        json={
            **body,
            "payer_tenant_id": str(other.tenant),
            "billing_account_id": str(commerce.account_for(other.tenant)),
        },
        headers=_auth(rig.admin_token, **{"Idempotency-Key": _unique("sub")}),
    )
    assert substituted.status_code == 403
    assert _as_admin(
        "SELECT count(*) FROM core.billing_subscriptions WHERE tenant_id = :t", t=str(rig.tenant)
    ) == [(0,)]

    key = _unique("idem")
    created = client.post(
        f"{base}/subscriptions",
        json=body,
        headers=_auth(rig.admin_token, **{"Idempotency-Key": key}),
    )
    assert created.status_code == 201, created.text
    subscription = created.json()
    assert subscription["replayed"] is False
    assert subscription["plan_id"] == str(commerce.plan_id)
    assert subscription["payer_tenant_id"] == str(rig.tenant)
    assert "provider_subscription_id" not in subscription

    replay = client.post(
        f"{base}/subscriptions",
        json=body,
        headers=_auth(rig.admin_token, **{"Idempotency-Key": key}),
    )
    assert replay.status_code == 201 and replay.json()["replayed"] is True
    assert replay.json()["subscription_id"] == subscription["subscription_id"]
    assert _as_admin(
        "SELECT count(*) FROM core.billing_subscriptions WHERE tenant_id = :t", t=str(rig.tenant)
    ) == [(1,)]
    # The same key with a different, equally valid request is refused -- not
    # replayed, and no second subscription is created.
    reused = client.post(
        f"{base}/subscriptions",
        json={**body, "plan_id": str(commerce.other_plan_id)},
        headers=_auth(rig.admin_token, **{"Idempotency-Key": key}),
    )
    assert reused.status_code == 409, reused.text
    assert reused.json() == {"detail": "Idempotency-Key already used with a different request."}
    assert _as_admin(
        "SELECT count(*) FROM core.billing_subscriptions WHERE tenant_id = :t", t=str(rig.tenant)
    ) == [(1,)]

    # Holding exactly the two authorities Core requires is enough to get
    # past authorization: the route's own gate is `billing.subscription:create`.
    _, both_token, _ = world.member(rig.tenant, [("billing.subscription", "create"), _CHARGE])
    assert (
        client.post(
            f"{base}/subscriptions",
            json={**body, "plan_id": str(uuid.uuid4())},
            headers=_auth(both_token, **{"Idempotency-Key": _unique("both")}),
        ).status_code
        == 404
    )

    # A plan that does not exist and a billing account that does not exist
    # are one answer: no oracle for which private plan ids exist.
    for wrong in ({"plan_id": str(uuid.uuid4())}, {"billing_account_id": str(uuid.uuid4())}):
        missing = client.post(
            f"{base}/subscriptions",
            json={**body, **wrong},
            headers=_auth(rig.admin_token, **{"Idempotency-Key": _unique("missing")}),
        )
        assert missing.status_code == 404, missing.text
        assert missing.json() == {"detail": "plan or billing account not found."}

    # Entitlements are exactly Core's answer for this tenant.
    entitlements = client.get(f"{base}/entitlements", headers=headers)
    assert entitlements.status_code == 200
    assert entitlements.json() == {"entitlements": get_entitlements(rig.tenant)}
    # ... and another tenant's are its own.
    assert client.get(
        f"/v1/tenants/{other.tenant}/billing/entitlements", headers=_auth(other.admin_token)
    ).json() == {"entitlements": {}}

    # The payer read model is fed by the outbox consumer; run it, as the
    # dispatcher would, so the reads below are not vacuous.
    _deliver_projections(rig.tenant, commerce.merchant_tenant)
    payer = client.get(f"{base}/payer-subscriptions", headers=headers)
    assert payer.status_code == 200
    assert [row["subscription_id"] for row in payer.json()] == [subscription["subscription_id"]]
    assert payer.json()[0]["plan_id"] == str(commerce.plan_id)
    assert payer.json()[0]["service_tenant_id"] == str(rig.tenant)
    one = client.get(
        f"{base}/payer-subscriptions/{subscription['subscription_id']}", headers=headers
    )
    assert one.status_code == 200 and one.json() == payer.json()[0]
    not_found = {"detail": "subscription not found."}
    for response in (
        client.get(f"{base}/payer-subscriptions/{uuid.uuid4()}", headers=headers),
        # another payer cannot read it under its own tenant path
        client.get(
            f"/v1/tenants/{other.tenant}/billing/payer-subscriptions/"
            f"{subscription['subscription_id']}",
            headers=_auth(other.admin_token),
        ),
    ):
        assert response.status_code == 404 and response.json() == not_found
    assert (
        client.get(
            f"/v1/tenants/{other.tenant}/billing/payer-subscriptions",
            headers=_auth(other.admin_token),
        ).json()
        == []
    )

    # Another tenant's administrator cannot cancel it through their own path.
    cross = client.post(
        f"/v1/tenants/{other.tenant}/billing/subscriptions/"
        f"{subscription['subscription_id']}/cancel",
        headers=_auth(other.admin_token),
    )
    assert cross.status_code == 404 and cross.json() == {"detail": "subscription not found."}

    cancelled = client.post(
        f"{base}/subscriptions/{subscription['subscription_id']}/cancel", headers=headers
    )
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["status"] == "canceled"
    assert (
        client.post(f"{base}/subscriptions/{uuid.uuid4()}/cancel", headers=headers).status_code
        == 404
    )


def test_usage_report_is_the_tenants_own(client: TestClient, rig: _Rig) -> None:
    base = f"/v1/tenants/{rig.tenant}/usage"
    headers = _auth(rig.admin_token)
    report = client.get(base, headers=headers)
    assert report.status_code == 200, report.text
    assert report.json()["tenant_id"] == str(rig.tenant)
    assert set(report.json()) == {
        "tenant_id",
        "since",
        "until",
        "metrics",
        "effective_entitlements",
    }
    # A window needs both bounds or neither.
    assert client.get(f"{base}?since=2026-01-01T00:00:00Z", headers=headers).status_code == 400


# --- Tenant state, hierarchy, hostile input ----------------------------------------------


def test_a_suspended_tenant_is_not_found_even_for_its_administrator(
    client: TestClient, rig: _Rig
) -> None:
    base = f"/v1/tenants/{rig.tenant}"
    assert client.get(f"{base}/members", headers=_auth(rig.admin_token)).status_code == 200
    transition_tenant_status(rig.tenant, TenantStatus.ACTIVE, caller=platform_operator())
    transition_tenant_status(rig.tenant, TenantStatus.SUSPENDED, caller=platform_operator())
    for method, path in (("GET", "members"), ("POST", "api-keys"), ("GET", "usage")):
        response = client.request(
            method, f"{base}/{path}", json={"name": "x"}, headers=_auth(rig.admin_token)
        )
        assert response.status_code == 404 and response.json() == {"detail": "tenant not found."}


def test_authority_in_a_parent_tenant_does_not_reach_a_child_tenants_routes(
    world: _World, client: TestClient, rig: _Rig
) -> None:
    """The administrator's role in the parent is SELF-scoped, and they are
    not a member of the child: the child tenant is not found for them."""
    child = create_tenant(_unique("cap-child"), parent_id=rig.tenant, caller=platform_operator())
    world.tenant_ids.insert(0, child.id)
    _, child_admin_token, _ = world.member(child.id, list(CAPABILITY_PERMISSIONS))
    assert (
        client.get(f"/v1/tenants/{child.id}/members", headers=_auth(child_admin_token)).status_code
        == 200
    )
    for path in ("members", "invitations", "api-keys", "billing/entitlements", "usage"):
        response = client.get(f"/v1/tenants/{child.id}/{path}", headers=_auth(rig.admin_token))
        assert response.status_code == 404, path
        assert response.json() == {"detail": "tenant not found."}, path
    # ... and the child's administrator does not reach the parent's either.
    assert (
        client.get(
            f"/v1/tenants/{rig.tenant}/members", headers=_auth(child_admin_token)
        ).status_code
        == 404
    )


def test_control_characters_are_rejected_before_they_reach_the_database(
    client: TestClient, rig: _Rig
) -> None:
    base = f"/v1/tenants/{rig.tenant}"
    headers = _auth(rig.admin_token)
    nul = "a\u0000b"
    assert (
        client.post(
            f"{base}/invitations", json={"email": f"{nul}@example.test"}, headers=headers
        ).status_code
        == 422
    )
    assert client.post(f"{base}/api-keys", json={"name": nul}, headers=headers).status_code == 422
    assert client.get(f"{base}/usage", params={"metric": nul}, headers=headers).status_code == 400
    assert client.get(f"{base}/invitations", headers=headers).json() == []
    assert client.get(f"{base}/api-keys", headers=headers).json() == []


def test_an_idempotency_key_is_not_examined_before_the_caller_is_authorized(
    client: TestClient, rig: _Rig
) -> None:
    """An invalid key from an unauthenticated or unauthorized caller gets the
    401 / 403, not a 400 that would confirm the route exists for them."""
    url = f"/v1/tenants/{rig.tenant}/billing/subscriptions"
    bad = {"Idempotency-Key": "not a valid key " + "x" * 400}
    assert client.post(url, json=_SUBSCRIBE_BODY, headers=bad).status_code == 401
    assert (
        client.post(url, json=_SUBSCRIBE_BODY, headers=_auth(rig.plain_token, **bad)).status_code
        == 403
    )


# --- ADR-0043: the last administrator, through the route ----------------------------------


def test_the_last_administrator_cannot_be_removed_through_the_route(
    world: _World, client: TestClient, rig: _Rig
) -> None:
    """An administrator is whoever can assign roles in the tenant
    (`membership_role:create`). The rig's `admin` holds the capability
    permissions but not that one, so the tenant's one administrator is the
    `owner` created here."""
    manage = [("membership", "suspend"), ("membership", "revoke"), ("membership_role", "create")]
    owner, owner_token, owner_membership = world.member(rig.tenant, manage)
    base = f"/v1/tenants/{rig.tenant}/members"
    refusal = {"detail": "The last administrator of a tenant cannot be suspended or revoked."}

    for caller_token in (owner_token, rig.admin_token):  # themselves, or someone else
        for verb in ("suspend", "revoke"):
            response = client.post(f"{base}/{owner_membership}/{verb}", headers=_auth(caller_token))
            assert response.status_code == 409 and response.json() == refusal, (verb, response.text)
    membership = get_membership(rig.tenant, owner)
    assert membership is not None and membership.status == "active"

    # With a second administrator the same request succeeds.
    world.member(rig.tenant, manage)
    left = client.post(f"{base}/{owner_membership}/revoke", headers=_auth(owner_token))
    assert left.status_code == 200 and left.json()["status"] == "revoked"


# --- ADR-0044: cookie-authenticated mutations must be same-origin -----------------------------

_APP_ORIGIN = "https://app.capability.test"


@pytest.fixture
def cookie_client(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    from saas_os.api.auth.config import get_auth_http_config

    monkeypatch.delenv("PUBLIC_APP_ORIGIN", raising=False)
    monkeypatch.setenv("OIDC_REDIRECT_URI", f"{_APP_ORIGIN}/auth/callback")
    get_auth_http_config.cache_clear()
    with TestClient(app) as test_client:
        yield test_client
    get_auth_http_config.cache_clear()


def test_a_forged_cookie_request_changes_nothing_and_a_same_origin_one_works(
    cookie_client: TestClient, rig: _Rig
) -> None:
    cookie_client.cookies.set("saas_os_session", rig.admin_token)
    url = f"/v1/tenants/{rig.tenant}/members/{rig.plain_membership}/suspend"

    for headers in (
        {},  # no Origin
        {"Origin": "https://evil.capability.test"},  # sibling subdomain
        {"Origin": "https://attacker.example.net"},  # unrelated site
        {"Origin": _APP_ORIGIN, "Sec-Fetch-Site": "same-site"},
    ):
        forged = cookie_client.post(url, headers=headers)
        assert forged.status_code == 403 and forged.json() == {"detail": "Not authorized."}
    membership = get_membership(rig.tenant, rig.plain)
    assert membership is not None and membership.status == "active"  # nothing happened
    assert _as_admin(
        "SELECT count(*) FROM core.audit_log "
        "WHERE tenant_id = :t AND action = 'membership.suspend'",
        t=str(rig.tenant),
    ) == [(0,)]

    # Reading with the cookie needs no Origin; mutating from the application's
    # own origin works.
    assert cookie_client.get(f"/v1/tenants/{rig.tenant}/members").status_code == 200
    genuine = cookie_client.post(url, headers={"Origin": _APP_ORIGIN})
    assert genuine.status_code == 200 and genuine.json()["status"] == "suspended"


def test_a_bearer_client_mutates_without_any_origin_header(
    cookie_client: TestClient, rig: _Rig
) -> None:
    """The same deployment, the same route, no browser: unaffected."""
    url = f"/v1/tenants/{rig.tenant}/members/{rig.plain_membership}/suspend"
    response = cookie_client.post(url, headers=_auth(rig.admin_token))
    assert response.status_code == 200 and response.json()["status"] == "suspended"
    hostile = cookie_client.post(
        f"/v1/tenants/{rig.tenant}/members/{rig.plain_membership}/reactivate",
        headers=_auth(rig.admin_token, Origin="https://attacker.example.net"),
    )
    assert hostile.status_code == 200 and hostile.json()["status"] == "active"
