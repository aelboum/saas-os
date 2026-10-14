"""Accepting an invitation over HTTP (ADR-0046) against real PostgreSQL and
Redis, through the real ingress chain.

What is proven here:

- **opt-in**: the route exists only where `invitation_acceptance_router`
  is registered, and its policy is `authenticated` -- no tenant
  permission;
- **bound to the person invited**: a session whose verified email equals
  the invited one (after trimming and case-folding) joins the tenant; a
  session with no verified email, or with another one, is refused, and
  the invitation stays pending for the right person;
- **one answer for every refusal**: unknown, used, revoked and expired
  tokens, the wrong tenant in the path, a suspended tenant, an existing
  suspended membership, no verified email and a different email are all
  the same `404` body;
- **the edge**: no credential is `401`; a cookie-authenticated request
  from another origin is `403` (ADR-0044); the per-user limit answers
  `429`, and a limiter failure `503`;
- **evidence**: an acceptance writes `invitation.accept` in the tenant's
  audit trail.

Negative control: with the route passing no email to Core, the person
the binding refuses joins the tenant.

Marked `integration`.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

import saas_os.api.v1.invitation_acceptance as acceptance_module
import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import PROVISIONING, platform_operator
from saas_os.api.auth.config import get_auth_http_config
from saas_os.api.platform import build_platform_app
from saas_os.api.route_policy import RoutePolicyKind, assert_route_policies
from saas_os.api.v1 import invitation_acceptance_router, register_capability_permissions
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import (
    accept_invitation,
    create_invitation,
    get_membership,
    revoke_invitation,
)
from saas_os.core.identity.errors import InvitationInvalidError
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.identity.sessions import issue_session, revoke_session
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError, InvalidPrincipalError
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import TenantStatus, create_tenant, transition_tenant_status
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope
from saas_os.infra.ratelimit import RateLimitBackendError, RateLimitExceededError
from saas_os.infra.ratelimit.config import get_ratelimit_config

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_INVITED = "ada.lovelace@example.test"
_REFUSED = {"detail": "invitation not found."}


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
            conn.execute(text("SELECT verified_email FROM core.sessions LIMIT 1"))
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

    def tenant(self) -> uuid.UUID:
        tenant = create_tenant(f"accept-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE, caller=PROVISIONING)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def person(self, verified_email: str | None) -> tuple[uuid.UUID, str]:
        """A user with a session, carrying `verified_email` as the login
        that issued it would have."""
        user = create_user()
        self.user_ids.append(user.id)
        _, token = issue_session(user.id, verified_email=verified_email)
        return user.id, token

    def inviter(self, tenant_id: uuid.UUID) -> UserCaller:
        user = create_user()
        self.user_ids.append(user.id)
        membership = add_tenant_membership(tenant_id, user.id, caller=_PROVISIONING)
        role = create_role(tenant_id, f"inviter-{uuid.uuid4().hex[:6]}", caller=_PROVISIONING)
        for action in ("create", "revoke"):
            grant_permission(
                tenant_id,
                role.id,
                register_permission("invitation", action).id,
                caller=_PROVISIONING,
            )
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=_PROVISIONING)
        return UserCaller(user.id)

    def invite(self, tenant_id: uuid.UUID, email: str = _INVITED) -> tuple[uuid.UUID, str]:
        invitation, token = create_invitation(tenant_id, email, caller=self.inviter(tenant_id))
        return invitation.id, token

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
def app() -> FastAPI:
    application = build_platform_app(title="invitation acceptance", version="test")
    application.include_router(invitation_acceptance_router)
    return application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def _accept(client: TestClient, tenant_id: uuid.UUID, token: str | None, raw: str) -> Any:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post(
        f"/v1/tenants/{tenant_id}/invitations/accept", json={"token": raw}, headers=headers
    )


def _status(invitation_id: uuid.UUID) -> tuple[Any, Any]:
    (row,) = _admin(
        "SELECT accepted_at, accepted_by_user_id FROM core.invitations WHERE id = :i",
        i=str(invitation_id),
    )
    return row[0], row[1]


# --- Opt-in and policy ---------------------------------------------------------------------


def test_the_route_is_opt_in_and_authenticated_not_permission_gated(world: _World) -> None:
    tenant = world.tenant()
    _, token = world.person(_INVITED)
    with TestClient(build_platform_app(title="bare", version="test")) as bare:
        response = _accept(bare, tenant, token, "anything")
        assert (response.status_code, response.json()) == (404, {"detail": "Not Found"})
    application = build_platform_app(title="policy", version="test")
    application.include_router(invitation_acceptance_router)
    policies = assert_route_policies(application, production=False)
    policy = policies["POST /v1/tenants/{tenant_id}/invitations/accept"]
    assert policy.kind is RoutePolicyKind.AUTHENTICATED


# --- The invited person joins --------------------------------------------------------------


def test_the_invited_person_joins_whatever_the_case_of_the_address(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    invitation_id, raw = world.invite(tenant)
    user_id, token = world.person("  Ada.Lovelace@EXAMPLE.test ")

    response = _accept(client, tenant, token, raw)

    assert response.status_code == 200, response.text
    assert response.json() == {"tenant_id": str(tenant), "status": "active"}
    membership = get_membership(tenant, user_id)
    assert membership is not None and membership.status == "active"
    accepted_at, accepted_by = _status(invitation_id)
    assert accepted_at is not None and accepted_by == user_id
    actions = _admin(
        "SELECT action, actor_user_id FROM core.audit_log WHERE tenant_id = :t "
        "AND resource_id = :i",
        t=str(tenant),
        i=str(invitation_id),
    )
    assert ("invitation.accept", user_id) in actions
    # The token is single-use, for the same person as for anyone else.
    assert (_accept(client, tenant, token, raw).json()) == _REFUSED


def test_no_verified_email_or_another_email_is_refused_and_the_invitation_stays_pending(
    world: _World, client: TestClient
) -> None:
    tenant = world.tenant()
    invitation_id, raw = world.invite(tenant)
    _, unverified = world.person(None)
    _, someone_else = world.person("grace.hopper@example.test")
    for token in (unverified, someone_else):
        response = _accept(client, tenant, token, raw)
        assert (response.status_code, response.json()) == (404, _REFUSED)
    assert _status(invitation_id) == (None, None)
    # The person it was meant for still can.
    _, right = world.person(_INVITED)
    assert _accept(client, tenant, right, raw).status_code == 200


def test_every_refusal_is_the_same_answer(world: _World, client: TestClient) -> None:
    tenant, other_tenant = world.tenant(), world.tenant()
    _, token = world.person(_INVITED)

    def refused(tenant_id: uuid.UUID, raw: str) -> None:
        response = _accept(client, tenant_id, token, raw)
        assert (response.status_code, response.json()) == (404, _REFUSED)

    refused(tenant, "not-a-token")  # unknown
    _, raw = world.invite(tenant)
    refused(other_tenant, raw)  # a tenant that is not the invitation's
    refused(uuid.uuid4(), raw)  # a tenant that does not exist

    revoked_id, revoked_raw = world.invite(tenant, "revoked@example.test")
    revoke_invitation(tenant, revoked_id, caller=world.inviter(tenant))
    _, revoked_token = world.person("revoked@example.test")
    response = _accept(client, tenant, revoked_token, revoked_raw)
    assert (response.status_code, response.json()) == (404, _REFUSED)

    expired_id, expired_raw = world.invite(tenant, "expired@example.test")
    _admin(
        "UPDATE core.invitations SET created_at = :c, expires_at = :e WHERE id = :i",
        c=datetime.now(UTC) - timedelta(hours=2),
        e=datetime.now(UTC) - timedelta(minutes=1),
        i=str(expired_id),
    )
    _, expired_token = world.person("expired@example.test")
    response = _accept(client, tenant, expired_token, expired_raw)
    assert (response.status_code, response.json()) == (404, _REFUSED)

    # A suspended tenant admits nobody.
    closed = world.tenant()
    _, closed_raw = world.invite(closed)
    transition_tenant_status(closed, TenantStatus.SUSPENDED, caller=platform_operator())
    refused(closed, closed_raw)

    # An existing suspended membership is not silently reactivated.
    suspended_user, suspended_token = world.person("returning@example.test")
    add_tenant_membership(tenant, suspended_user, caller=_PROVISIONING)
    _admin(
        "UPDATE core.tenant_memberships SET status = 'suspended' "
        "WHERE tenant_id = :t AND user_id = :u",
        t=str(tenant),
        u=str(suspended_user),
    )
    returning_id, returning_raw = world.invite(tenant, "returning@example.test")
    response = _accept(client, tenant, suspended_token, returning_raw)
    assert (response.status_code, response.json()) == (404, _REFUSED)
    assert _status(returning_id) == (None, None)  # rolled back with the refusal


# --- The edge ------------------------------------------------------------------------------


def test_no_credential_is_401_and_a_cross_origin_cookie_post_is_403(
    world: _World, client: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = world.tenant()
    _, raw = world.invite(tenant)
    assert _accept(client, tenant, None, raw).status_code == 401
    _, token = world.person(_INVITED)
    # Cookie transport exists only where browser login is configured.
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://testserver/auth/callback")
    get_auth_http_config.cache_clear()
    with TestClient(app, base_url="https://testserver") as browser:
        browser.cookies.set("saas_os_session", token)
        response = browser.post(
            f"/v1/tenants/{tenant}/invitations/accept",
            json={"token": raw},
            headers={"Origin": "https://attacker.example"},
        )
        # The same request from the application's own origin is accepted:
        # the refusal above is the origin check, not the credential.
        same_origin = browser.post(
            f"/v1/tenants/{tenant}/invitations/accept",
            json={"token": raw},
            headers={"Origin": "https://testserver"},
        )
    get_auth_http_config.cache_clear()
    assert response.status_code == 403
    assert same_origin.status_code == 200, same_origin.text


@pytest.mark.parametrize(
    ("failure", "expected"),
    [(RateLimitExceededError("k", 7), 429), (RateLimitBackendError("redis down"), 503)],
)
def test_the_per_user_limit_refuses_and_fails_closed(
    world: _World,
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    expected: int,
) -> None:
    tenant = world.tenant()
    invitation_id, raw = world.invite(tenant)
    user_id, token = world.person(_INVITED)
    keys: list[str] = []

    async def limiter(key: str, *, config: object) -> None:
        keys.append(key)
        raise failure

    monkeypatch.setattr(acceptance_module, "enforce_rate_limit", limiter)
    assert _accept(client, tenant, token, raw).status_code == expected
    assert keys == [f"invitation-accept:{user_id}"]  # per user, not per tenant or token
    assert _status(invitation_id) == (None, None)


# --- Negative control ----------------------------------------------------------------------


def test_without_the_email_binding_someone_else_joins(
    world: _World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = world.tenant()
    _, raw = world.invite(tenant)
    stranger, token = world.person("grace.hopper@example.test")
    assert _accept(client, tenant, token, raw).json() == _REFUSED

    real = acceptance_module.accept_invitation

    def unbound(raw_token: str, tenant_id: uuid.UUID, **kwargs: Any) -> Any:
        kwargs.pop("accepting_email")
        return real(raw_token, tenant_id, **kwargs)

    monkeypatch.setattr(acceptance_module, "accept_invitation", unbound)
    assert _accept(client, tenant, token, raw).status_code == 200
    assert get_membership(tenant, stranger) is not None


# --- Review findings: non-ASCII folding, late refusals, logout ------------------------------


def test_a_non_ascii_address_never_binds_an_invitation(world: _World) -> None:
    """`casefold()` makes `straße` and `strasse` equal; a different mailbox
    must not satisfy the binding, so a non-ASCII address matches nothing."""
    tenant = world.tenant()
    invitation_id, raw = world.invite(tenant, "victim@strasse.test")
    user = create_user()
    world.user_ids.append(user.id)
    with pytest.raises(InvitationInvalidError):
        accept_invitation(
            raw, tenant, caller=UserCaller(user.id), accepting_email="victim@straße.test"
        )
    assert _status(invitation_id) == (None, None)
    # And the session never keeps one in the first place.
    session, _ = issue_session(user.id, verified_email="victim@straße.test")
    assert session.verified_email is None


@pytest.mark.parametrize(
    "late_refusal",
    [
        AuthorityNotAuthorizedError("accept_invitation", uuid.uuid4()),
        InvalidPrincipalError("user", uuid.uuid4()),
    ],
)
def test_a_caller_deactivated_after_login_gets_the_same_404(
    world: _World,
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    late_refusal: Exception,
) -> None:
    tenant = world.tenant()
    _, raw = world.invite(tenant)
    _, token = world.person(_INVITED)

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise late_refusal

    monkeypatch.setattr(acceptance_module, "accept_invitation", refuse)
    response = _accept(client, tenant, token, raw)
    assert (response.status_code, response.json()) == (404, _REFUSED)


def test_logout_clears_the_verified_email(world: _World) -> None:
    user = create_user()
    world.user_ids.append(user.id)
    session, _ = issue_session(user.id, verified_email=_INVITED)
    assert session.verified_email == _INVITED
    revoke_session(session.id)
    (row,) = _admin("SELECT verified_email FROM core.sessions WHERE id = :s", s=str(session.id))
    assert row == (None,)
