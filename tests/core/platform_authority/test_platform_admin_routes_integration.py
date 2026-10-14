"""The opt-in platform-admin routes and the self-service suspension route
against real PostgreSQL and Redis, through the real ingress chain and Core
(docs/ADR/0045-installation-scoped-platform-authority.md sections 7 and 12).

For **every** route of the inventory, the denial matrix of the Phase D
plan: no credential (401), an ordinary user, a tenant administrator and an
administrator of the designated platform tenant (the 404 an unknown path
returns), a suspended and a revoked operator who hold the permission
(404), an operator holding every platform permission except the route's
own (403, with a `denied` platform audit row), and an operator holding
only that permission (success).

That last pair is the permission gate's negative control built into the
matrix: gate a route with the wrong permission and one of the two fails.
`test_swapping_a_routes_permission_fails_the_matrix` shows it.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from phase_c_helpers import PROVISIONING, REASON, P, Scene
from platform_helpers import PlatformWorld, join, start
from sqlalchemy import text

import saas_os.api.dependencies as deps
import saas_os.api.platform_admin.router as router_module
from saas_os.api.auth.config import get_auth_http_config
from saas_os.api.platform import build_platform_app
from saas_os.api.platform_admin import build_platform_admin_router, get_platform_admin_http_config
from saas_os.api.platform_admin.router import PLATFORM_ROUTES, PREFIX, PlatformRoute
from saas_os.api.v1 import register_tenant_suspension_permission, tenant_suspension_router
from saas_os.core.feature_flags import create_flag, set_tenant_override
from saas_os.core.identity.service import get_or_create_user_for_external_identity
from saas_os.core.platform_authority import (
    PLATFORM_OPERATIONS,
    PlatformOperationTimeoutError,
    get_platform_mutation_config,
    revoke_operator,
    suspend_operator,
)
from saas_os.core.rbac import create_delegation, register_permission
from saas_os.core.rbac.scope import RoleScope
from saas_os.core.tenancy import TenantStatus, get_tenancy_config
from saas_os.infra.ratelimit.config import get_ratelimit_config

pytestmark = pytest.mark.integration

_ISSUER = "https://issuer.platform-admin.test"
_APP_ORIGIN = "https://app.example.com"
_COOKIE = "saas_os_session"
_NOT_FOUND = {"detail": "Not Found"}
SELF_SUSPEND = ("tenant", "suspend")


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("PLATFORM_ADMIN_HTTP_ENABLED", "true")
    monkeypatch.delenv("PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS", raising=False)
    monkeypatch.delenv("PUBLIC_APP_ORIGIN", raising=False)
    monkeypatch.setenv("OIDC_REDIRECT_URI", f"{_APP_ORIGIN}/auth/callback")
    for cached in (get_platform_admin_http_config, get_auth_http_config, get_ratelimit_config):
        cached.cache_clear()
    try:
        config = get_ratelimit_config()
        import redis as redis_sync

        redis_sync.Redis.from_url(config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not configured or not reachable: {exc}")
    yield
    for cached in (
        get_platform_admin_http_config,
        get_auth_http_config,
        get_ratelimit_config,
        get_tenancy_config,
    ):
        cached.cache_clear()


def _client(*, mounted: bool = True) -> TestClient:
    app = build_platform_app(title="platform-admin", version="test")
    if mounted:
        app.include_router(build_platform_admin_router())
    app.include_router(tenant_suspension_router)
    return TestClient(app)


@dataclass
class Request:
    method: str
    url: str
    json: dict[str, Any] | None
    success: int


class Kit:
    """Everything one route needs to be called once, successfully."""

    def __init__(self, scene: Scene, platform: PlatformWorld) -> None:
        self.scene, self.platform = scene, platform
        self.owner, self.owner_operator = platform.owner()  # keeps the invariants satisfiable
        self.flags: list[str] = []
        self.subject = platform.user()
        scene.session_for(self.subject)
        self.external_subject = f"subject-{uuid.uuid4().hex}"
        self.external_user = get_or_create_user_for_external_identity(
            _ISSUER, self.external_subject
        ).id
        platform.users.append(self.external_user)
        self.inactive_user = platform.user()
        platform.set_user_active(self.inactive_user, False)
        self.active_tenant = scene.tenant(active=True)
        self.pending_tenant = scene.tenant()
        self.suspended_tenant = scene.tenant(active=True)
        scene.set_status(self.suspended_tenant, TenantStatus.SUSPENDED)
        self.flag = self.new_flag()
        _, self.target_operator = platform.operator([P.TENANT_READ])
        _, self.suspended_operator = platform.operator([P.TENANT_READ])
        suspend_operator(self.suspended_operator, caller=self.owner, reason=REASON)

    def new_flag(self) -> str:
        key = f"platform-admin.{uuid.uuid4().hex[:12]}"
        create_flag(key, caller=PROVISIONING)
        self.flags.append(key)
        return key

    def token(self, user_id: uuid.UUID) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.scene.session_for(user_id)}"}

    def request(self, route: PlatformRoute) -> Request:
        reason = {"reason": REASON}
        new_flag = f"platform-admin.{uuid.uuid4().hex[:12]}"
        self.flags.append(new_flag)
        table: dict[tuple[str, str], tuple[str, dict[str, Any] | None, int]] = {
            ("GET", "/tenants"): ("/tenants", None, 200),
            ("GET", "/tenants/{tenant_id}"): (f"/tenants/{self.active_tenant}", None, 200),
            ("GET", "/users/{user_id}"): (f"/users/{self.subject}", None, 200),
            ("POST", "/users/resolve"): (
                "/users/resolve",
                {"issuer": _ISSUER, "subject": self.external_subject},
                200,
            ),
            ("GET", "/operators"): ("/operators", None, 200),
            ("GET", "/grants"): ("/grants", None, 200),
            ("GET", "/audit"): ("/audit", None, 200),
            ("GET", "/billing/overview"): ("/billing/overview", None, 200),
            ("GET", "/feature-flags"): ("/feature-flags", None, 200),
            ("GET", "/tenants/{tenant_id}/feature-flags"): (
                f"/tenants/{self.active_tenant}/feature-flags",
                None,
                200,
            ),
            ("POST", "/tenants"): ("/tenants", {"name": f"pa-{uuid.uuid4().hex[:10]}"}, 201),
            ("POST", "/tenants/{tenant_id}/activate"): (
                f"/tenants/{self.pending_tenant}/activate",
                {},
                200,
            ),
            ("POST", "/tenants/{tenant_id}/suspend"): (
                f"/tenants/{self.active_tenant}/suspend",
                reason,
                200,
            ),
            ("POST", "/tenants/{tenant_id}/reactivate"): (
                f"/tenants/{self.suspended_tenant}/reactivate",
                reason,
                200,
            ),
            ("POST", "/users/{user_id}/deactivate"): (
                f"/users/{self.subject}/deactivate",
                reason,
                200,
            ),
            ("POST", "/users/{user_id}/reactivate"): (
                f"/users/{self.inactive_user}/reactivate",
                reason,
                200,
            ),
            ("POST", "/users/{user_id}/sessions/revoke"): (
                f"/users/{self.subject}/sessions/revoke",
                reason,
                200,
            ),
            ("POST", "/users/{user_id}/api-keys/revoke"): (
                f"/users/{self.subject}/api-keys/revoke",
                reason,
                200,
            ),
            ("POST", "/feature-flags"): ("/feature-flags", {"key": new_flag}, 201),
            ("PUT", "/tenants/{tenant_id}/feature-flags/{key}"): (
                f"/tenants/{self.active_tenant}/feature-flags/{self.flag}",
                {"enabled": True, "reason": REASON},
                200,
            ),
            ("DELETE", "/tenants/{tenant_id}/feature-flags/{key}"): (
                f"/tenants/{self.active_tenant}/feature-flags/{self.flag}",
                None,
                204,
            ),
            ("POST", "/operators"): (
                "/operators",
                {"user_id": str(self.platform.user()), "reason": REASON},
                201,
            ),
            ("POST", "/operators/{operator_id}/suspend"): (
                f"/operators/{self.target_operator}/suspend",
                reason,
                200,
            ),
            ("POST", "/operators/{operator_id}/reactivate"): (
                f"/operators/{self.suspended_operator}/reactivate",
                reason,
                200,
            ),
            ("POST", "/operators/{operator_id}/revoke"): (
                f"/operators/{self.target_operator}/revoke",
                reason,
                200,
            ),
            # A caller may grant only a permission they hold themselves.
            ("POST", "/operators/{operator_id}/grants"): (
                f"/operators/{self.target_operator}/grants",
                {"permission": "platform.authority:manage", "reason": REASON},
                201,
            ),
            ("POST", "/operators/{operator_id}/grants/revoke"): (
                f"/operators/{self.target_operator}/grants/revoke",
                {"permission": "platform.tenant:read", "reason": REASON},
                200,
            ),
        }
        if route.method == "DELETE":
            # Something to remove: removing an override that is not set is a
            # no-op that writes no row, and would prove nothing.
            set_tenant_override(
                self.active_tenant, self.flag, True, caller=self.owner, reason=REASON
            )
        path, body, success = table[(route.method, route.path)]
        return Request(route.method, PREFIX + path, body, success)

    def send(self, client: TestClient, request: Request, headers: dict[str, str]) -> Any:
        return client.request(request.method, request.url, json=request.json, headers=headers)

    def cleanup(self) -> None:
        execute = self.platform.execute
        execute(
            "DELETE FROM core.feature_flag_tenant_overrides WHERE flag_id IN "
            "(SELECT id FROM core.feature_flags WHERE key = ANY(:k))",
            {"k": self.flags},
        )
        execute("DELETE FROM core.feature_flags WHERE key = ANY(:k)", {"k": self.flags})
        execute("DELETE FROM core.external_identities WHERE issuer = :i", {"i": _ISSUER})


@pytest.fixture
def kit(scene: Scene, platform: PlatformWorld) -> Iterator[Kit]:
    built = Kit(scene, platform)
    try:
        yield built
    finally:
        built.cleanup()


_IDS = [f"{route.method} {route.path}" for route in PLATFORM_ROUTES]


def _evidence(platform: PlatformWorld, **filters: Any) -> list[dict[str, Any]]:
    """Platform audit rows, without the login events: issuing a session to
    a user who is an operator records `platform.operator.session_issued`,
    which says nothing about a request."""
    return [
        row
        for row in platform.audit(**filters)
        if row["action"] != "platform.operator.session_issued"
    ]


# --- the denial matrix, for every route ------------------------------------------------------


@pytest.mark.parametrize("route", PLATFORM_ROUTES, ids=_IDS)
def test_the_denial_matrix(
    kit: Kit, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, route: PlatformRoute
) -> None:
    client = _client()
    request = kit.request(route)
    action = PLATFORM_OPERATIONS[route.operation].audit_action
    unknown = client.get(f"{PREFIX}/no-such-route", headers=kit.token(platform.user()))
    assert unknown.status_code == 404 and unknown.json() == _NOT_FOUND

    # No credential.
    assert kit.send(client, request, {}).status_code == 401

    # People who are not operators: exactly what an unknown path returns.
    tenant_admin, _ = kit.scene.admin(kit.active_tenant)
    platform_tenant = kit.scene.tenant(active=True)
    platform_tenant_admin, _ = kit.scene.admin(platform_tenant)
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(platform_tenant))
    get_tenancy_config.cache_clear()
    suspended, suspended_id = platform.operator([route.permission])
    suspend_operator(suspended_id, caller=kit.owner, reason=REASON)
    revoked, revoked_id = platform.operator([route.permission])
    revoke_operator(revoked_id, caller=kit.owner, reason=REASON)
    others, _ = platform.operator([p for p in P if p is not route.permission])
    only, _ = platform.operator([route.permission])
    platform.clear_audit()
    for user_id in (
        platform.user(),
        tenant_admin.user_id,
        platform_tenant_admin.user_id,
        suspended.user_id,
        revoked.user_id,
    ):
        response = kit.send(client, request, kit.token(user_id))
        assert (response.status_code, response.json()) == (404, _NOT_FOUND)
    assert _evidence(platform) == []  # not operators: nothing is recorded about them

    # An operator with every platform permission but this route's.
    refused = kit.send(client, request, kit.token(others.user_id))
    assert (refused.status_code, refused.json()) == (403, {"detail": "Not authorized."})
    (denied,) = platform.audit(outcome="denied")
    assert denied["action"] == action and denied["reason"] == "not_authorized"
    assert denied["actor_user_id"] == others.user_id
    assert denied["target_type"] == "http_route"
    assert denied["target_id"] == f"{route.method} {PREFIX}{route.path}"  # as declared
    assert _evidence(platform, outcome="success") == []  # and nothing was done

    # An operator with only this route's permission.
    platform.clear_audit()
    response = kit.send(client, request, kit.token(only.user_id))
    assert response.status_code == request.success, response.text
    # Core performed this route's operation, and recorded that operator.
    done = _evidence(platform, outcome="success")
    assert {row["actor_user_id"] for row in done} == {only.user_id}
    assert action in {row["action"] for row in done}, [row["action"] for row in done]


def test_swapping_a_routes_permission_fails_the_matrix(
    kit: Kit, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: gate the tenant list with the billing permission.
    The operator who holds only `platform.tenant:read` -- the matrix's
    success case -- is now refused, and one who holds every permission but
    that one -- its 403 case -- is let through the gate."""
    swapped = tuple(
        PlatformRoute("GET", "/tenants", P.BILLING_READ, "billing.read")
        if (route.method, route.path) == ("GET", "/tenants")
        else route
        for route in PLATFORM_ROUTES
    )
    monkeypatch.setattr(router_module, "PLATFORM_ROUTES", swapped)
    client = _client()
    only, _ = platform.operator([P.TENANT_READ])
    others, _ = platform.operator([p for p in P if p is not P.TENANT_READ])
    assert client.get(f"{PREFIX}/tenants", headers=kit.token(only.user_id)).status_code == 403
    # Past the swapped gate, Core still decides: the read needs tenant:read.
    assert client.get(f"{PREFIX}/tenants", headers=kit.token(others.user_id)).status_code == 403
    assert platform.audit(action="platform.tenant.read", outcome="success") == []


def test_on_an_application_that_did_not_mount_the_router_no_platform_route_exists(
    kit: Kit,
) -> None:
    client = _client(mounted=False)
    for route in PLATFORM_ROUTES:
        response = kit.send(client, kit.request(route), kit.token(kit.owner.user_id))
        assert (response.status_code, response.json()) == (404, _NOT_FOUND), route


def test_with_both_opt_ins_the_application_starts(kit: Kit) -> None:
    app = build_platform_app(title="platform-admin", version="test")
    app.include_router(build_platform_admin_router())
    with TestClient(app) as client:  # the lifespan runs: route rules and configuration
        response = client.get(f"{PREFIX}/operators", headers=kit.token(kit.owner.user_id))
    assert response.status_code == 200


# --- what the routes return --------------------------------------------------------------------


def test_oversight_routes_return_the_fixed_projections_and_leave_two_rows(
    kit: Kit, platform: PlatformWorld
) -> None:
    client = _client()
    owner = kit.token(kit.owner.user_id)
    set_tenant_override(kit.active_tenant, kit.flag, True, caller=kit.owner, reason=REASON)
    platform.clear_audit()

    tenant = client.get(f"{PREFIX}/tenants/{kit.active_tenant}", headers=owner).json()
    assert set(tenant) == {"id", "name", "status", "parent_id", "created_at", "updated_at"}
    assert tenant["id"] == str(kit.active_tenant) and tenant["status"] == "active"

    by_id = client.get(f"{PREFIX}/users/{kit.external_user}", headers=owner).json()
    by_identity = client.post(
        f"{PREFIX}/users/resolve",
        json={"issuer": _ISSUER, "subject": kit.external_subject},
        headers=owner,
    )
    assert by_identity.status_code == 200 and by_identity.json() == by_id
    assert set(by_id) == {
        "id",
        "is_active",
        "created_at",
        "is_enrolled_operator",
        "live_sessions",
        "more_live_sessions",
        "sessions",
    }
    assert _ISSUER not in by_identity.text and kit.external_subject not in by_identity.text

    overrides = client.get(f"{PREFIX}/tenants/{kit.active_tenant}/feature-flags", headers=owner)
    assert overrides.json() == {
        "tenant_id": str(kit.active_tenant),
        "overrides": [{"key": kit.flag, "enabled": True}],
        "next_cursor": None,
    }
    operators = client.get(f"{PREFIX}/operators?limit=200", headers=owner).json()
    assert {entry["status"] for entry in operators["operators"]} == {"active", "suspended"}
    grants = client.get(f"{PREFIX}/grants?operator_id={kit.target_operator}", headers=owner).json()
    assert [grant["permission"] for grant in grants["grants"]] == ["platform.tenant:read"]

    # Each of the six calls: one attempt and one completion.
    rows = platform.audit()
    assert len(rows) == 12 and {row["outcome"] for row in rows} == {"success"}
    assert sum(row["action"].endswith("_attempt") for row in rows) == 6

    filtered = client.get(
        f"{PREFIX}/audit?action=platform.tenant.read&actor_user_id={kit.owner.user_id}&limit=200",
        headers=owner,
    ).json()
    assert len(filtered["entries"]) == 1
    assert filtered["entries"][0]["target_tenant_id"] == str(kit.active_tenant)


def test_core_errors_are_translated_to_fixed_responses(kit: Kit, platform: PlatformWorld) -> None:
    client = _client()
    owner = kit.token(kit.owner.user_id)
    reason = {"reason": REASON}
    missing = uuid.uuid4()

    def call(method: str, path: str, **kwargs: Any) -> tuple[int, Any]:
        response = client.request(method, PREFIX + path, headers=owner, **kwargs)
        return response.status_code, response.json()

    # Not found, by resource; never an identifier or an external identity.
    assert call("GET", f"/tenants/{missing}") == (404, {"detail": "tenant not found."})
    assert call("GET", f"/users/{missing}") == (404, {"detail": "user not found."})
    assert call("GET", f"/tenants/{missing}/feature-flags") == (
        404,
        {"detail": "tenant not found."},
    )
    assert call("POST", "/users/resolve", json={"issuer": _ISSUER, "subject": "nobody-here"}) == (
        404,
        {"detail": "user not found."},
    )
    assert call("POST", f"/operators/{missing}/suspend", json=reason) == (
        404,
        {"detail": "operator not found."},
    )
    # A request Core rejects: 400, never clamped.
    status, body = call("GET", "/tenants?limit=10000")
    assert status == 400 and "maximum" in body["detail"]
    assert call("GET", "/operators?limit=0")[0] == 400
    # A state the request does not fit: 409 with a fixed reason.
    assert call("POST", f"/tenants/{kit.pending_tenant}/suspend", json=reason) == (
        409,
        {"detail": "invalid_tenant_transition"},
    )
    # No self-service of authority: the fixed code Core recorded.
    assert call(
        "POST", "/operators", json={"user_id": str(kit.owner.user_id), "reason": REASON}
    ) == (409, {"detail": "self_authority_change"})
    assert call("POST", "/feature-flags", json={"key": kit.flag}) == (
        409,
        {"detail": "feature_flag_already_exists"},
    )
    # An invariant: the fixed code Core recorded.
    assert call("POST", f"/users/{kit.owner.user_id}/deactivate", json=reason) == (
        409,
        {"detail": "self_target"},
    )
    assert call("POST", f"/operators/{kit.owner_operator}/revoke", json=reason) == (
        409,
        {"detail": "self_authority_change"},
    )
    # Each lifecycle route performs its own operation and no other, even
    # for an operator who holds every permission.
    assert call("POST", f"/tenants/{kit.suspended_tenant}/activate", json={}) == (
        409,
        {"detail": "invalid_tenant_transition"},
    )
    assert call("POST", f"/tenants/{kit.pending_tenant}/reactivate", json=reason) == (
        409,
        {"detail": "invalid_tenant_transition"},
    )
    assert kit.scene.status(kit.suspended_tenant) == "suspended"
    assert kit.scene.status(kit.pending_tenant) == "pending"
    # Malformed input never reaches Core.
    assert call("GET", "/tenants/not-a-uuid")[0] == 422
    assert call("POST", f"/tenants/{kit.active_tenant}/suspend", json={})[0] == 422
    assert (
        call("POST", f"/tenants/{kit.active_tenant}/suspend", json={"reason": "a\x00b"})[0] == 422
    )
    assert kit.scene.status(kit.active_tenant) == "active"


@pytest.fixture
def short_mutation_timeout(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A 300 ms platform mutation timeout for one test. The cached setting
    is cleared on both sides, and nothing reads it between this teardown
    and `monkeypatch` restoring the environment, so it never leaks into a
    later test."""
    monkeypatch.setenv("PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS", "300")
    get_platform_mutation_config.cache_clear()
    yield
    get_platform_mutation_config.cache_clear()


@pytest.mark.usefixtures("short_mutation_timeout")
def test_a_request_held_by_a_lock_at_the_operator_check_is_answered_as_an_unknown_path(
    kit: Kit, platform: PlatformWorld
) -> None:
    """ADR-0045, amendment of 2026-10-14: the chain's operator check runs
    in a bounded transaction of its own. Whether the caller is an operator
    is then unknown, so the answer is the one a non-operator gets (section
    7): `404`. Nothing changes, and the request succeeds once the lock is
    gone. The request runs on a thread, so a regression fails the test
    instead of hanging it."""
    client = _client()
    owner = kit.token(kit.owner.user_id)
    path = PREFIX + f"/tenants/{kit.active_tenant}/suspend"
    connection = platform.admin.connect()
    transaction = connection.begin()
    try:
        connection.execute(
            text("SELECT id FROM core.users WHERE id = :u FOR NO KEY UPDATE"),
            {"u": kit.owner.user_id},
        )
        thread, outcome = start(
            lambda: client.post(path, headers=owner, json={"reason": REASON}), "held-request"
        )
        thread.join(timeout=15)
        finished = not thread.is_alive()
    finally:
        transaction.rollback()
        connection.close()
    join(thread)
    assert finished, "the request waited on the lock without limit"
    response = outcome["result"]
    assert response.status_code == 404
    assert response.json() == client.post(PREFIX + "/no-such-path", headers=owner).json()
    assert kit.scene.status(kit.active_tenant) == "active"

    assert client.post(path, headers=owner, json={"reason": REASON}).status_code == 200
    assert kit.scene.status(kit.active_tenant) == "suspended"


def test_a_permission_check_cancelled_by_its_timeout_is_answered_503(
    kit: Kit, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the operator check the caller is known to be an operator:
    nothing was decided, so `503` and `Retry-After`."""

    def times_out(**kwargs: Any) -> bool:
        raise PlatformOperationTimeoutError(kwargs["permission"].value, 300)

    monkeypatch.setattr(deps, "platform_can", times_out)
    client = _client()
    owner = kit.token(kit.owner.user_id)
    response = client.post(
        PREFIX + f"/tenants/{kit.active_tenant}/suspend", headers=owner, json={"reason": REASON}
    )
    assert response.status_code == 503
    assert response.headers.get("Retry-After")
    assert kit.scene.status(kit.active_tenant) == "active"


# --- the fresh-session rule, on real sessions -----------------------------------------------


def _age_session(platform: PlatformWorld, user_id: uuid.UUID, seconds: int) -> None:
    platform.execute(
        "UPDATE core.sessions SET created_at = now() - make_interval(secs => :s) "
        "WHERE user_id = :u",
        {"s": seconds, "u": user_id},
    )


def test_an_authority_change_needs_a_session_no_older_than_fifteen_minutes(
    kit: Kit, platform: PlatformWorld
) -> None:
    client = _client()
    manager, _ = platform.operator([P.AUTHORITY_MANAGE, P.OPERATOR_READ])
    token = kit.token(manager.user_id)
    suspend = f"{PREFIX}/operators/{kit.target_operator}/suspend"

    _age_session(platform, manager.user_id, 905)
    platform.clear_audit()
    old = client.post(suspend, json={"reason": REASON}, headers=token)
    assert old.status_code == 401 and old.headers["X-Error-Code"] == "session_not_fresh"
    assert platform.operator_status(kit.target_operator) == "active"  # nothing changed
    (denied,) = platform.audit()
    assert denied["outcome"] == "denied" and denied["reason"] == "session_not_fresh"
    assert denied["action"] == "platform.operator.suspend"
    assert denied["actor_user_id"] == manager.user_id
    # The same old session is accepted where authority is not changed.
    assert client.get(f"{PREFIX}/operators", headers=token).status_code == 200

    _age_session(platform, manager.user_id, 890)  # inside the limit
    fresh = client.post(suspend, json={"reason": REASON}, headers=token)
    assert fresh.status_code == 200 and fresh.json()["status"] == "suspended"
    assert platform.operator_status(kit.target_operator) == "suspended"


def test_a_cookie_authenticated_platform_mutation_from_another_origin_is_refused(
    kit: Kit, platform: PlatformWorld
) -> None:
    suspender, _ = platform.operator([P.TENANT_SUSPEND])
    raw = kit.scene.session_for(suspender.user_id)
    app = build_platform_app(title="platform-admin", version="test")
    app.include_router(build_platform_admin_router())
    client = TestClient(app, cookies={_COOKIE: raw})
    url = f"{PREFIX}/tenants/{kit.active_tenant}/suspend"

    for headers in ({"Origin": "https://evil.example.com"}, {}):
        assert client.post(url, json={"reason": REASON}, headers=headers).status_code == 403
    assert kit.scene.status(kit.active_tenant) == "active"

    same = client.post(
        url,
        json={"reason": REASON},
        headers={"Origin": _APP_ORIGIN, "Sec-Fetch-Site": "same-origin"},
    )
    assert same.status_code == 200 and kit.scene.status(kit.active_tenant) == "suspended"


# --- tenant self-service suspension (section 12) ----------------------------------------------


def test_a_tenants_own_role_holder_suspends_it_and_nobody_inside_can_undo_it(
    scene: Scene, platform: PlatformWorld
) -> None:
    register_tenant_suspension_permission()
    tenant = scene.tenant(active=True)
    scene.admin(tenant)  # the tenant keeps an administrator
    user_id, membership_id = scene.member(tenant)
    scene.role(tenant, membership_id, [SELF_SUSPEND])
    client = _client(mounted=False)
    headers = {"Authorization": f"Bearer {scene.session_for(user_id)}"}
    url = f"/v1/tenants/{tenant}/suspend"

    # The confirmation: the body repeats the path.
    mismatch = client.post(
        url, json={"tenant_id": str(uuid.uuid4()), "reason": REASON}, headers=headers
    )
    assert mismatch.status_code == 400
    assert client.post(url, json={"tenant_id": str(tenant)}, headers=headers).status_code == 422
    assert scene.status(tenant) == "active"

    response = client.post(url, json={"tenant_id": str(tenant), "reason": REASON}, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"id": str(tenant), "status": "suspended"}
    (own,) = scene.tenant_audit(tenant, "tenant.suspend")
    assert own["actor_user_id"] == user_id and own["metadata"]["self_service"] is True
    assert platform.audit(action="platform.tenant.suspend", outcome="success") == []

    # A suspended tenant admits none of its principals: the same member
    # now gets the tenant chain's 404, and there is no reactivation route
    # on this router.
    again = client.post(url, json={"tenant_id": str(tenant), "reason": REASON}, headers=headers)
    assert again.status_code == 404
    assert client.post(f"/v1/tenants/{tenant}/reactivate", headers=headers).status_code == 404
    assert scene.status(tenant) == "suspended"


def test_self_suspension_is_refused_for_everyone_the_rule_does_not_admit(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    register_tenant_suspension_permission()
    permission = register_permission(*SELF_SUSPEND)
    tenant = scene.tenant(active=True)
    client = _client(mounted=False)

    def attempt(user_id: uuid.UUID, target: uuid.UUID = tenant) -> int:
        return client.post(
            f"/v1/tenants/{target}/suspend",
            json={"tenant_id": str(target), "reason": REASON},
            headers={"Authorization": f"Bearer {scene.session_for(user_id)}"},
        ).status_code

    plain_member = scene.member(tenant)[0]
    assert attempt(plain_member) == 403  # the chain: no permission
    assert attempt(platform.user()) == 404  # not a member: the tenant is not found

    # A delegate satisfies the chain's `can()` and not Core's rule.
    delegator, _ = scene.admin(tenant, extra=[SELF_SUSPEND, ("delegation_grant", "create")])
    delegate = platform.user()
    scene.join(tenant, delegate)
    create_delegation(
        caller=delegator,
        delegate_user_id=delegate,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=permission.id,
    )
    assert attempt(delegate) == 403
    assert scene.status(tenant) == "active"

    # The designated platform tenant cannot be self-suspended, even by its
    # own role holder.
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(tenant))
    get_tenancy_config.cache_clear()
    assert attempt(delegator.user_id) == 403
    assert scene.status(tenant) == "active"
    monkeypatch.delenv("PLATFORM_TENANT_ID")
    get_tenancy_config.cache_clear()

    # An operator is not a member: the tenant route is not theirs.
    operator, _ = platform.operator(list(P))
    assert attempt(operator.user_id) == 404
    # And the route exists only where a product mounted it.
    bare = TestClient(build_platform_app(title="bare", version="test"))
    response = bare.post(
        f"/v1/tenants/{tenant}/suspend",
        json={"tenant_id": str(tenant), "reason": REASON},
        headers={"Authorization": f"Bearer {scene.session_for(delegator.user_id)}"},
    )
    assert response.status_code == 404
    assert scene.status(tenant) == "active"


def test_the_self_service_route_never_acts_under_platform_authority(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A person who holds `platform.tenant:suspend` and passes the tenant
    chain without being the tenant's own role holder is refused here: the
    route asks Core for the self-service rule alone. With the permission
    they suspend through the platform route, not through this one."""
    register_tenant_suspension_permission()
    permission = register_permission(*SELF_SUSPEND)
    tenant = scene.tenant(active=True)
    delegator, _ = scene.admin(tenant, extra=[SELF_SUSPEND, ("delegation_grant", "create")])
    operator, _ = platform.operator([P.TENANT_SUSPEND])
    scene.join(tenant, operator.user_id)
    create_delegation(
        caller=delegator,
        delegate_user_id=operator.user_id,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=permission.id,
    )
    client = _client()
    headers = {"Authorization": f"Bearer {scene.session_for(operator.user_id)}"}
    body = {"tenant_id": str(tenant), "reason": REASON}

    assert (
        client.post(f"/v1/tenants/{tenant}/suspend", json=body, headers=headers).status_code == 403
    )
    assert scene.status(tenant) == "active"
    assert platform.audit(action="platform.tenant.suspend", outcome="success") == []

    # The designated platform tenant: refused for its own role holder, even
    # one who is also an operator with the platform permission.
    holder, _ = platform.operator([P.TENANT_SUSPEND])
    membership = scene.join(tenant, holder.user_id)
    scene.role(tenant, membership, [SELF_SUSPEND])
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(tenant))
    get_tenancy_config.cache_clear()
    holder_headers = {"Authorization": f"Bearer {scene.session_for(holder.user_id)}"}
    refused = client.post(f"/v1/tenants/{tenant}/suspend", json=body, headers=holder_headers)
    assert refused.status_code == 403 and scene.status(tenant) == "active"

    # Through the platform route the same permission does what it carries.
    done = client.post(
        f"{PREFIX}/tenants/{tenant}/suspend", json={"reason": REASON}, headers=headers
    )
    assert done.status_code == 200 and scene.status(tenant) == "suspended"
