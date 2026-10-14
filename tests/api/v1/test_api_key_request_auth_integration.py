"""API-key request authentication (ADR-0047) against real PostgreSQL and
Redis, through the real ingress chain.

What is proven here:

- **opt-in**: a route accepts `X-API-Key` only when it declares
  `require_permission(..., api_key=True)`; any other route ignores the
  header and still needs a session; a resource that changes authority
  cannot opt in at all;
- **the principal**: a user's key acts as that user, with the user's
  membership; a service account's key acts as the service account, and
  `can()` decides with the service account's own roles;
- **one tenant**: a key reaches only its own tenant -- any other is the
  404 a non-member gets;
- **authentication is `validate_api_key()`**: unknown, revoked, expired,
  over-long, an inactive user's and a disabled service account's keys are
  the one generic 401; a key presented together with a session credential
  is 401 too;
- **authorization**: a key whose owner lacks the permission, or whose
  membership is suspended, is 403, audited with the key's principal;
- **rate limit**: a key-authenticated request is limited per key as well
  as per tenant;
- **lifetime**: a key issued over HTTP carries the `sok_` prefix and
  expires within 365 days; rotating one that never expired bounds the new
  key too.

Marked `integration`.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

import saas_os.api.dependencies as deps
import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import PROVISIONING
from saas_os.api.auth.config import get_auth_http_config
from saas_os.api.context import RequestContext, RequestPrincipal
from saas_os.api.dependencies import require_entitlement_and_quota, require_permission
from saas_os.api.platform import build_platform_app
from saas_os.api.route_policy import RoutePolicyKind, assert_route_policies
from saas_os.api.v1 import api_keys_router, register_capability_permissions
from saas_os.core.api_keys import (
    API_KEY_PREFIX,
    create_api_key,
    create_service_account_api_key,
    revoke_api_key,
)
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import create_service_account
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.identity.sessions import issue_session
from saas_os.core.rbac import AUTHORITY_RESOURCES
from saas_os.core.rbac.authorization import (
    BILLING_MUTATION_ACTIONS,
    TENANT_SELF_SUSPEND_ACTION,
)
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    assign_service_account_role,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import TenantStatus, create_tenant, transition_tenant_status
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.ratelimit.config import get_ratelimit_config

pytestmark = pytest.mark.integration

_SYSTEM = SystemCaller(SystemAuthority.PROVISIONING)
_RESOURCE = "g3_widget"
_ACTION = "read"
_UNAUTHORIZED = {"detail": "Authentication required."}


@pytest.fixture(autouse=True)
def _require_reachable_database_and_redis() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_ratelimit_config.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
        config = get_ratelimit_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database or Redis not configured: {exc}")
    probe = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.api_keys LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    finally:
        probe.dispose()
    import redis as redis_sync

    try:
        redis_sync.Redis.from_url(config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable: {exc}")


def _admin(statement: str, **params: object) -> list[tuple[Any, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(statement), params)
            return [tuple(row) for row in result.all()] if result.returns_rows else []
    finally:
        engine.dispose()


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    def tenant(self, *, parent: uuid.UUID | None = None, activate: bool = True) -> uuid.UUID:
        tenant = create_tenant(f"g3-{uuid.uuid4().hex[:8]}", parent_id=parent, caller=PROVISIONING)
        self.tenant_ids.append(tenant.id)
        if activate:
            transition_tenant_status(tenant.id, TenantStatus.ACTIVE, caller=PROVISIONING)
        return tenant.id

    def member(
        self, tenant_id: uuid.UUID, permissions: tuple[tuple[str, str], ...]
    ) -> tuple[uuid.UUID, uuid.UUID]:
        """A member holding exactly `permissions`. Returns (user, membership)."""
        user = create_user()
        self.user_ids.append(user.id)
        membership = add_tenant_membership(tenant_id, user.id, caller=_SYSTEM)
        role = create_role(tenant_id, f"g3-{uuid.uuid4().hex[:6]}", caller=_SYSTEM)
        for resource, action in permissions:
            grant_permission(
                tenant_id, role.id, register_permission(resource, action).id, caller=_SYSTEM
            )
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=_SYSTEM)
        return user.id, membership.id

    def user_key(self, tenant_id: uuid.UUID, *, allowed: bool = True) -> tuple[uuid.UUID, str]:
        user_id, _ = self.member(tenant_id, ((_RESOURCE, _ACTION),) if allowed else ())
        key, raw = create_api_key(tenant_id, "g3", caller=UserCaller(user_id))
        return key.id, raw

    def service_account_key(
        self, tenant_id: uuid.UUID, *, allowed: bool = True
    ) -> tuple[uuid.UUID, uuid.UUID, str]:
        """A service account with a key, holding the route's permission
        through its own role when `allowed`. Returns (account, key, raw)."""
        admin, _ = self.member(
            tenant_id,
            (
                ("api_key", "create"),
                ("service_account_role", "create"),
                (_RESOURCE, _ACTION),
            ),
        )
        account = create_service_account(tenant_id, f"svc-{uuid.uuid4().hex[:6]}", caller=_SYSTEM)
        if allowed:
            role = create_role(tenant_id, f"svc-{uuid.uuid4().hex[:6]}", caller=_SYSTEM)
            grant_permission(
                tenant_id, role.id, register_permission(_RESOURCE, _ACTION).id, caller=_SYSTEM
            )
            assign_service_account_role(
                caller=UserCaller(admin),
                tenant_id=tenant_id,
                service_account_id=account.id,
                role_id=role.id,
            )
        key, raw = create_service_account_api_key(
            tenant_id=tenant_id, service_account_id=account.id, name="svc", caller=UserCaller(admin)
        )
        return account.id, key.id, raw

    def session(self, tenant_id: uuid.UUID) -> str:
        user_id, _ = self.member(tenant_id, ((_RESOURCE, _ACTION),))
        return issue_session(user_id)[1]

    def cleanup(self) -> None:
        tenants = [str(t) for t in self.tenant_ids]
        users = [str(u) for u in self.user_ids]
        for statement in (
            "DELETE FROM core.audit_log WHERE tenant_id = ANY(:t) OR actor_user_id = ANY(:u)",
            "DELETE FROM core.api_keys WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.sessions WHERE user_id = ANY(:u)",
            "DELETE FROM core.service_account_roles WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.service_accounts WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) OR ancestor_id = ANY(:t)",
            "DELETE FROM core.platform_audit_log WHERE target_tenant_id = ANY(:t)",
            "DELETE FROM core.tenants WHERE id = ANY(:t)",
            "DELETE FROM core.users WHERE id = ANY(:u)",
        ):
            _admin(statement, t=tenants, u=users)


@pytest.fixture
def world() -> Iterator[_World]:
    register_capability_permissions()
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


_widgets = APIRouter()
_accepting_keys = require_permission(_RESOURCE, _ACTION, api_key=True)
_session_only_permission = require_permission(_RESOURCE, _ACTION)
_ENTITLEMENT = "g3_never_granted"
_entitled_keys = require_entitlement_and_quota(
    _RESOURCE, _ACTION, entitlement_key=_ENTITLEMENT, api_key=True
)


@_widgets.get("/v1/tenants/{tenant_id}/g3-widgets")
def _read_widgets(
    context: Annotated[RequestContext, Depends(_accepting_keys)],
) -> dict[str, Any]:
    return {
        "principal": context.principal.value,
        "actor_id": str(context.actor_id),
        "membership_id": None if context.membership_id is None else str(context.membership_id),
        "api_key_id": None if context.api_key_id is None else str(context.api_key_id),
    }


@_widgets.post("/v1/tenants/{tenant_id}/g3-widgets")
def _write_widget(
    context: Annotated[RequestContext, Depends(_accepting_keys)],
) -> dict[str, Any]:
    return {"principal": context.principal.value}


@_widgets.get("/v1/tenants/{tenant_id}/g3-entitled")
def _entitled(
    context: Annotated[RequestContext, Depends(_entitled_keys)],
) -> dict[str, Any]:
    return {"principal": context.principal.value}


@_widgets.get("/v1/tenants/{tenant_id}/g3-session-only")
def _session_only(
    context: Annotated[RequestContext, Depends(_session_only_permission)],
) -> dict[str, Any]:
    return {"actor_id": str(context.actor_id)}


def _app() -> FastAPI:
    application = build_platform_app(title="api keys", version="test")
    application.include_router(_widgets)
    application.include_router(api_keys_router)
    return application


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(_app()) as test_client:
        yield test_client


def _widgets_of(
    client: TestClient, tenant_id: uuid.UUID, *, key: str | None = None, **headers: str
) -> Any:
    if key is not None:
        headers["X-API-Key"] = key
    return client.get(f"/v1/tenants/{tenant_id}/g3-widgets", headers=headers)


# --- opt-in ---------------------------------------------------------------------------------


def test_the_route_policy_records_which_routes_accept_a_key() -> None:
    policies = assert_route_policies(_app(), production=False)
    accepting = policies["GET /v1/tenants/{tenant_id}/g3-widgets"]
    session_only = policies["GET /v1/tenants/{tenant_id}/g3-session-only"]
    assert accepting.kind is RoutePolicyKind.PERMISSION and accepting.accepts_api_key
    assert session_only.kind is RoutePolicyKind.PERMISSION and not session_only.accepts_api_key
    # Core's own routers accept none.
    assert not any(
        policy.accepts_api_key for label, policy in policies.items() if "/api-keys" in label
    )


@pytest.mark.parametrize(
    ("resource", "action"),
    [(resource, "read") for resource in sorted(AUTHORITY_RESOURCES)]
    + sorted(BILLING_MUTATION_ACTIONS)
    + [TENANT_SELF_SUSPEND_ACTION],
)
def test_a_permission_that_changes_authority_cannot_accept_a_key(
    resource: str, action: str
) -> None:
    """The set a support-access grant may never satisfy: every capability
    on an authority resource, the billing mutations, self-suspension."""
    with pytest.raises(ValueError, match="cannot accept an API key"):
        require_permission(resource, action, api_key=True)
    with pytest.raises(ValueError, match="cannot accept an API key"):
        require_entitlement_and_quota(resource, action, api_key=True)
    # The same permission without a key is unaffected.
    require_permission(resource, action)


def test_a_billing_read_may_accept_a_key() -> None:
    require_permission("billing.subscription", "read", api_key=True)


def test_a_route_that_does_not_opt_in_ignores_the_key(world: _World, client: TestClient) -> None:
    tenant = world.tenant()
    _, raw = world.user_key(tenant)
    response = client.get(f"/v1/tenants/{tenant}/g3-session-only", headers={"X-API-Key": raw})
    assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)


def test_a_session_still_works_on_a_route_that_accepts_keys(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    token = world.session(tenant)
    response = _widgets_of(client, tenant, Authorization=f"Bearer {token}")
    assert response.status_code == 200
    assert response.json()["principal"] == "user"
    assert response.json()["api_key_id"] is None


# --- the principal -------------------------------------------------------------------------


def test_a_user_key_acts_as_its_user_with_the_users_membership(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    key_id, raw = world.user_key(tenant)
    assert raw.startswith(API_KEY_PREFIX)
    response = _widgets_of(client, tenant, key=raw)
    assert response.status_code == 200
    body = response.json()
    (owner,) = _admin("SELECT user_id FROM core.api_keys WHERE id = :k", k=str(key_id))
    assert body["principal"] == RequestPrincipal.USER.value
    assert body["actor_id"] == str(owner[0])
    assert body["membership_id"] is not None
    assert body["api_key_id"] == str(key_id)


def test_a_service_account_key_acts_as_the_service_account(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    account, key_id, raw = world.service_account_key(tenant)
    response = _widgets_of(client, tenant, key=raw)
    assert response.status_code == 200
    assert response.json() == {
        "principal": RequestPrincipal.SERVICE_ACCOUNT.value,
        "actor_id": str(account),
        "membership_id": None,
        "api_key_id": str(key_id),
    }


@pytest.mark.parametrize("owner", ["user", "service_account"])
def test_a_key_whose_owner_lacks_the_permission_is_refused_and_audited(
    world: _World, client: TestClient, owner: str
) -> None:
    tenant = world.tenant()
    if owner == "user":
        _, raw = world.user_key(tenant, allowed=False)
    else:
        _, _, raw = world.service_account_key(tenant, allowed=False)
    assert _widgets_of(client, tenant, key=raw).status_code == 403
    rows = _admin(
        "SELECT actor_type, actor_user_id IS NULL, actor_service_account_id IS NULL "
        "FROM core.audit_log WHERE tenant_id = :t AND action = 'api.access_denied'",
        t=str(tenant),
    )
    if owner == "user":
        assert rows == [("user", False, True)]
    else:
        assert rows == [("service_account", True, False)]


@pytest.mark.parametrize("owner", ["user", "service_account"])
def test_an_entitlement_refusal_is_audited_with_the_keys_principal(
    world: _World, client: TestClient, owner: str
) -> None:
    tenant = world.tenant()
    if owner == "user":
        _, raw = world.user_key(tenant)
    else:
        _, _, raw = world.service_account_key(tenant)
    response = client.get(f"/v1/tenants/{tenant}/g3-entitled", headers={"X-API-Key": raw})
    assert response.status_code == 403
    rows = _admin(
        "SELECT actor_type, actor_user_id IS NULL, actor_service_account_id IS NULL "
        "FROM core.audit_log WHERE tenant_id = :t AND action = 'api.access_denied' "
        "AND resource_type = 'entitlement'",
        t=str(tenant),
    )
    if owner == "user":
        assert rows == [("user", False, True)]
    else:
        assert rows == [("service_account", True, False)]


def test_a_suspended_members_key_is_refused_at_authorization(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    key_id, raw = world.user_key(tenant)
    _admin(
        "UPDATE core.tenant_memberships SET status = 'suspended' WHERE tenant_id = :t "
        "AND user_id = (SELECT user_id FROM core.api_keys WHERE id = :k)",
        t=str(tenant),
        k=str(key_id),
    )
    assert _widgets_of(client, tenant, key=raw).status_code == 403


# --- one tenant ----------------------------------------------------------------------------


@pytest.mark.parametrize("owner", ["user", "service_account"])
def test_a_key_reaches_only_its_own_tenant(world: _World, client: TestClient, owner: str) -> None:
    home = world.tenant(activate=False)
    # A child of the key's tenant is another tenant too.
    child = world.tenant(parent=home)
    transition_tenant_status(home, TenantStatus.ACTIVE, caller=PROVISIONING)
    other = world.tenant()
    if owner == "user":
        _, raw = world.user_key(home)
    else:
        _, _, raw = world.service_account_key(home)
    foreign = _widgets_of(client, other, key=raw)
    missing = _widgets_of(client, uuid.uuid4(), key=raw)
    assert foreign.status_code == 404
    assert (foreign.status_code, foreign.json()) == (missing.status_code, missing.json())
    assert _widgets_of(client, child, key=raw).status_code == 404


def test_a_child_tenants_key_does_not_reach_its_parent(world: _World, client: TestClient) -> None:
    parent = world.tenant(activate=False)
    child = world.tenant(parent=parent)
    transition_tenant_status(parent, TenantStatus.ACTIVE, caller=PROVISIONING)
    _, raw = world.user_key(child)
    assert _widgets_of(client, child, key=raw).status_code == 200
    assert _widgets_of(client, parent, key=raw).status_code == 404


@pytest.mark.parametrize("status", [TenantStatus.SUSPENDED, TenantStatus.DELETED])
def test_a_key_of_a_tenant_that_no_longer_admits_its_principals_does_not_authenticate(
    world: _World, client: TestClient, status: TenantStatus
) -> None:
    tenant = world.tenant()
    _, raw = world.user_key(tenant)
    _admin("UPDATE core.tenants SET status = :s WHERE id = :t", s=status.value, t=str(tenant))
    response = _widgets_of(client, tenant, key=raw)
    assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)


# --- authentication ------------------------------------------------------------------------


def test_every_key_that_does_not_authenticate_gets_the_same_401(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    revoked_id, revoked = world.user_key(tenant)
    (owner,) = _admin("SELECT user_id FROM core.api_keys WHERE id = :k", k=str(revoked_id))
    revoke_api_key(tenant, revoked_id, caller=UserCaller(owner[0]))
    expired_id, expired = world.user_key(tenant)
    _admin(
        "UPDATE core.api_keys SET expires_at = now() - interval '1 minute' WHERE id = :k",
        k=str(expired_id),
    )
    inactive_id, inactive = world.user_key(tenant)
    _admin(
        "UPDATE core.users SET is_active = false "
        "WHERE id = (SELECT user_id FROM core.api_keys WHERE id = :k)",
        k=str(inactive_id),
    )
    account, _, disabled = world.service_account_key(tenant)
    _admin("UPDATE core.service_accounts SET status = 'disabled' WHERE id = :a", a=str(account))

    for raw in (
        revoked,
        expired,
        inactive,
        disabled,
        API_KEY_PREFIX + "x" * 43,  # never issued
        "x" * 257,  # longer than any key
        "",
    ):
        response = _widgets_of(client, tenant, key=raw)
        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED), raw[:12]


def test_surrounding_whitespace_in_the_header_is_not_part_of_the_key(
    world: _World, client: TestClient
) -> None:
    """Whitespace around a header value is not part of it (RFC 9110); the
    key itself never contains any, so a padded value is the same key."""
    tenant = world.tenant()
    _, raw = world.user_key(tenant)
    assert _widgets_of(client, tenant, key=f"  {raw} ").status_code == 200


def test_a_key_issued_before_the_prefix_still_authenticates(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    key_id, _ = world.user_key(tenant)
    legacy = "legacy-" + uuid.uuid4().hex + uuid.uuid4().hex
    _admin(
        "UPDATE core.api_keys SET key_hash = :h WHERE id = :k",
        h=hashlib.sha256(legacy.encode("utf-8")).hexdigest(),
        k=str(key_id),
    )
    assert _widgets_of(client, tenant, key=legacy).status_code == 200


def test_a_key_with_a_session_credential_is_refused(world: _World, client: TestClient) -> None:
    tenant = world.tenant()
    _, raw = world.user_key(tenant)
    token = world.session(tenant)
    both = _widgets_of(client, tenant, key=raw, Authorization=f"Bearer {token}")
    assert (both.status_code, both.json()) == (401, _UNAUTHORIZED)

    application = _app()
    application.dependency_overrides[deps._session_cookie_token] = lambda: token
    with TestClient(application) as with_cookie:
        response = _widgets_of(with_cookie, tenant, key=raw)
    assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)


def test_the_same_origin_check_still_guards_a_cookie_on_a_route_that_accepts_keys(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0044 on the session path of an opted-in route: a cookie-
    authenticated mutation from another origin is 403; the same request
    from the application's own origin passes, so the 403 is the origin
    check, not the credential."""
    tenant = world.tenant()
    token = world.session(tenant)
    path = f"/v1/tenants/{tenant}/g3-widgets"
    # Cookie transport exists only where browser login is configured.
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://testserver/auth/callback")
    get_auth_http_config.cache_clear()
    try:
        with TestClient(_app(), base_url="https://testserver") as browser:
            browser.cookies.set("saas_os_session", token)
            foreign = browser.post(path, headers={"Origin": "https://attacker.example"})
            own = browser.post(path, headers={"Origin": "https://testserver"})
    finally:
        get_auth_http_config.cache_clear()
    assert foreign.status_code == 403
    assert own.status_code == 200, own.text


# --- rate limit ----------------------------------------------------------------------------


def test_a_key_request_is_limited_per_key_and_per_tenant(
    world: _World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = world.tenant()
    key_id, raw = world.user_key(tenant)
    token = world.session(tenant)
    seen: list[str] = []
    real = deps.enforce_rate_limit

    async def recording(key: str, **kwargs: Any) -> None:
        seen.append(key)
        await real(key, **kwargs)

    monkeypatch.setattr(deps, "enforce_rate_limit", recording)
    assert _widgets_of(client, tenant, key=raw).status_code == 200
    path = f"/v1/tenants/{tenant}/g3-widgets"
    assert seen == [f"{tenant}:{path}", f"api-key:{key_id}"]

    seen.clear()
    assert _widgets_of(client, tenant, Authorization=f"Bearer {token}").status_code == 200
    assert seen == [f"{tenant}:{path}"]


def test_a_key_over_its_own_limit_is_refused_with_429(
    world: _World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from saas_os.infra.ratelimit import RateLimitExceededError

    tenant = world.tenant()
    key_id, raw = world.user_key(tenant)
    real = deps.enforce_rate_limit

    async def per_key_exhausted(key: str, **kwargs: Any) -> None:
        if key == f"api-key:{key_id}":
            raise RateLimitExceededError(key, retry_after_seconds=7)
        await real(key, **kwargs)

    monkeypatch.setattr(deps, "enforce_rate_limit", per_key_exhausted)
    response = _widgets_of(client, tenant, key=raw)
    assert response.status_code == 429
    assert response.headers.get("Retry-After") == "7"


# --- lifetime over HTTP --------------------------------------------------------------------


def _self_managing_session(world: _World, tenant: uuid.UUID) -> dict[str, str]:
    user_id, _ = world.member(tenant, (("api_key", "self_manage"),))
    return {"Authorization": f"Bearer {issue_session(user_id)[1]}"}


def test_a_key_issued_over_http_is_prefixed_and_expires_within_a_year(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    headers = _self_managing_session(world, tenant)
    path = f"/v1/tenants/{tenant}/api-keys"

    default = client.post(path, json={"name": "ci"}, headers=headers)
    assert default.status_code == 201
    assert default.json()["key"].startswith(API_KEY_PREFIX)
    expires = datetime.fromisoformat(default.json()["expires_at"])
    assert timedelta(days=364) < expires - datetime.now(UTC) <= timedelta(days=365)

    short = client.post(path, json={"name": "ci", "expires_in_days": 7}, headers=headers)
    expires = datetime.fromisoformat(short.json()["expires_at"])
    assert timedelta(days=6) < expires - datetime.now(UTC) <= timedelta(days=7)

    for days in (0, 366, -1):
        refused = client.post(path, json={"name": "ci", "expires_in_days": days}, headers=headers)
        assert refused.status_code == 422


def test_rotating_a_key_that_never_expired_bounds_the_new_one(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    user_id, _ = world.member(tenant, (("api_key", "self_manage"),))
    headers = {"Authorization": f"Bearer {issue_session(user_id)[1]}"}
    old, _ = create_api_key(tenant, "legacy", caller=UserCaller(user_id))  # no expiry
    assert old.expires_at is None

    rotated = client.post(f"/v1/tenants/{tenant}/api-keys/{old.id}/rotate", headers=headers)
    assert rotated.status_code == 200
    expires = datetime.fromisoformat(rotated.json()["expires_at"])
    assert timedelta(days=364) < expires - datetime.now(UTC) <= timedelta(days=365)

    # An earlier expiry is kept.
    soon = datetime.now(UTC) + timedelta(days=3)
    short, _ = create_api_key(tenant, "short", caller=UserCaller(user_id), expires_at=soon)
    again = client.post(f"/v1/tenants/{tenant}/api-keys/{short.id}/rotate", headers=headers)
    assert datetime.fromisoformat(again.json()["expires_at"]) == soon
