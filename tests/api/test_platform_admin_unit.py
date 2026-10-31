"""The opt-in platform-admin HTTP surface, without a database
(docs/ADR/0045-installation-scoped-platform-authority.md section 7).

Hermetic: the session lookup, the operator and permission lookups, the
rate limiter and the refusal writer are stubbed, so what is exercised is
the real route policy, the real dependency chain's order and answers, the
real startup checks and the real route inventory. The same routes against
PostgreSQL and Redis, through Core, are in
`tests/core/platform_authority/test_platform_admin_routes_integration.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

import saas_os.api.dependencies as deps
import saas_os.api.platform_admin.router as router_module
from saas_os.api.auth.config import get_auth_http_config
from saas_os.api.main import app as reference_app
from saas_os.api.platform import build_platform_app
from saas_os.api.platform_admin import (
    PlatformAdminHttpConfig,
    PlatformAdminHttpConfigurationError,
    build_platform_admin_router,
    get_platform_admin_http_config,
)
from saas_os.api.platform_admin.router import PLATFORM_ROUTES, PREFIX, PlatformRoute
from saas_os.api.route_policy import (
    RoutePolicy,
    RoutePolicyKind,
    RoutePolicyViolationError,
    assert_platform_route_rules,
    assert_route_policies,
    public_route,
)
from saas_os.core.platform_authority import PLATFORM_OPERATIONS, PlatformPermission

P = PlatformPermission
_APP_ORIGIN = "https://app.example.com"
_COOKIE = "saas_os_session"
_USER = uuid.uuid4()
_NOT_FOUND = {"detail": "Not Found"}


class _Session:
    def __init__(self, age_seconds: float = 0, *, multi_factor: bool = False) -> None:
        self.id = uuid.uuid4()
        self.user_id = _USER
        self.created_at = datetime.now(UTC) - timedelta(seconds=age_seconds)
        self.multi_factor = multi_factor


class _Chain:
    """What the stubbed lookups answer, and what the chain did."""

    def __init__(self) -> None:
        self.session: _Session | None = _Session()
        self.operator = True
        self.permissions: set[PlatformPermission] = set(P)
        self.refusals: list[dict[str, Any]] = []
        self.rate_limited_keys: list[str] = []
        self.calls: list[str] = []


@pytest.fixture
def chain(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Chain]:
    state = _Chain()
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("PUBLIC_APP_ORIGIN", raising=False)
    monkeypatch.setenv("OIDC_REDIRECT_URI", f"{_APP_ORIGIN}/auth/callback")
    monkeypatch.delenv("PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS", raising=False)
    monkeypatch.setenv("PLATFORM_ADMIN_HTTP_ENABLED", "true")
    get_auth_http_config.cache_clear()
    get_platform_admin_http_config.cache_clear()

    def validate_session(raw: str) -> _Session:
        state.calls.append("authenticate")
        if state.session is None:
            raise deps.SessionNotFoundError
        return state.session

    async def enforce_rate_limit(key: str, *, config: Any) -> None:
        state.calls.append("rate_limit")
        state.rate_limited_keys.append(key)

    def is_operator(*, user_id: uuid.UUID) -> bool:
        state.calls.append("operator")
        return state.operator

    def can(*, user_id: uuid.UUID, permission: PlatformPermission) -> bool:
        state.calls.append("permission")
        return permission in state.permissions

    def refused(**kwargs: Any) -> bool:
        state.refusals.append(kwargs)
        return True

    monkeypatch.setattr(deps, "validate_session", validate_session)
    monkeypatch.setattr(deps, "enforce_rate_limit", enforce_rate_limit)
    monkeypatch.setattr(deps, "get_ratelimit_config", lambda: None)
    monkeypatch.setattr(deps, "is_active_platform_operator", is_operator)
    monkeypatch.setattr(deps, "platform_can", can)
    monkeypatch.setattr(deps, "record_platform_refusal", refused)
    yield state
    get_auth_http_config.cache_clear()
    get_platform_admin_http_config.cache_clear()


def _probe_app(*, fresh_session: bool = False) -> FastAPI:
    """One GET and one POST route behind the real dependency."""
    app = build_platform_app(title="platform-admin", version="test")
    router = APIRouter(prefix=PREFIX)
    read = deps.require_platform_permission(P.TENANT_READ, operation="tenant.read")
    change = deps.require_platform_permission(
        P.AUTHORITY_MANAGE, operation="operator.enroll", fresh_session=fresh_session
    )

    @router.get("/probe/{item_id}")
    async def _read(
        item_id: uuid.UUID,
        context: deps.PlatformRequestContext = Depends(read),  # noqa: B008 -- FastAPI idiom
    ) -> dict[str, str]:
        return {"actor": str(context.actor_id), "session": str(context.session_id)}

    @router.post("/probe")
    async def _change(
        context: deps.PlatformRequestContext = Depends(change),  # noqa: B008 -- FastAPI idiom
    ) -> dict[str, str]:
        return {"actor": str(context.actor_id)}

    app.include_router(router)
    return app


_BEARER = {"Authorization": "Bearer raw-session-token"}


# --- the chain ---------------------------------------------------------------------------


def test_an_operator_with_the_permission_reaches_the_handler(chain: _Chain) -> None:
    client = TestClient(_probe_app())
    response = client.get(f"{PREFIX}/probe/{uuid.uuid4()}", headers=_BEARER)
    assert response.status_code == 200
    assert response.json() == {"actor": str(_USER), "session": str(chain.session.id)}  # type: ignore[union-attr]
    # The order of the chain, and nothing recorded for a success.
    assert chain.calls == ["authenticate", "rate_limit", "operator", "permission"]
    assert chain.refusals == []


def test_no_credential_is_a_401_before_anything_else(chain: _Chain) -> None:
    client = TestClient(_probe_app())
    assert client.get(f"{PREFIX}/probe/{uuid.uuid4()}").status_code == 401
    chain.session = None
    assert client.get(f"{PREFIX}/probe/{uuid.uuid4()}", headers=_BEARER).status_code == 401
    assert "operator" not in chain.calls and "rate_limit" not in chain.calls


def test_a_caller_who_is_not_an_operator_gets_exactly_what_an_unknown_path_gets(
    chain: _Chain,
) -> None:
    chain.operator = False
    client = TestClient(_probe_app())

    real = client.get(f"{PREFIX}/probe/{uuid.uuid4()}", headers=_BEARER)
    unknown = client.get(f"{PREFIX}/no-such-route", headers=_BEARER)

    assert real.status_code == unknown.status_code == 404
    assert real.json() == unknown.json() == _NOT_FOUND

    def headers(response: Any) -> dict[str, str]:
        return {k: v for k, v in response.headers.items() if k.lower() != "x-request-id"}

    assert headers(real) == headers(unknown)
    # Not an operator: no permission is evaluated and nothing is recorded.
    assert "permission" not in chain.calls and chain.refusals == []


def test_an_operator_without_the_permission_gets_403_and_a_denied_row(chain: _Chain) -> None:
    chain.permissions = set(P) - {P.TENANT_READ}
    item = uuid.uuid4()
    response = TestClient(_probe_app()).get(f"{PREFIX}/probe/{item}", headers=_BEARER)
    assert response.status_code == 403 and response.json() == {"detail": "Not authorized."}
    (refusal,) = chain.refusals
    assert refusal["action"] == "platform.tenant.read" and refusal["code"] == "not_authorized"
    assert refusal["caller"].user_id == _USER
    # The route as declared: the identifier from the URL is not recorded.
    assert refusal["target_type"] == "http_route"
    assert refusal["target_id"] == f"GET {PREFIX}/probe/{{item_id}}"
    assert str(item) not in repr(refusal)


def test_the_rate_limit_is_keyed_by_actor_and_path_and_runs_before_the_operator_lookup(
    chain: _Chain, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = TestClient(_probe_app())
    item = uuid.uuid4()
    client.get(f"{PREFIX}/probe/{item}", headers=_BEARER)
    # One bucket per actor per route as declared: the id in the path is not
    # part of the key, so varying it neither escapes the limit nor makes a
    # key per id.
    assert chain.rate_limited_keys == [f"platform:{_USER}:GET {PREFIX}/probe/{{item_id}}"]
    client.get(f"{PREFIX}/probe/{uuid.uuid4()}", headers=_BEARER)
    assert len(set(chain.rate_limited_keys)) == 1

    async def exceeded(key: str, *, config: Any) -> None:
        raise deps.RateLimitExceededError(key, 7)

    monkeypatch.setattr(deps, "enforce_rate_limit", exceeded)
    chain.calls.clear()
    limited = client.get(f"{PREFIX}/probe/{item}", headers=_BEARER)
    assert limited.status_code == 429 and "operator" not in chain.calls

    async def backend_down(key: str, *, config: Any) -> None:
        raise deps.RateLimitBackendError("redis unavailable")

    monkeypatch.setattr(deps, "enforce_rate_limit", backend_down)
    failed = client.get(f"{PREFIX}/probe/{item}", headers=_BEARER)
    assert failed.status_code == 503  # fail closed: never served unlimited
    assert "operator" not in chain.calls


def test_a_cookie_authenticated_mutation_from_another_origin_is_refused(chain: _Chain) -> None:
    app = _probe_app(fresh_session=True)
    client = TestClient(app, cookies={_COOKIE: "raw-session-token"})
    same = client.post(
        f"{PREFIX}/probe", headers={"Origin": _APP_ORIGIN, "Sec-Fetch-Site": "same-origin"}
    )
    assert same.status_code == 200
    for headers in (
        {"Origin": "https://evil.example.com"},
        {"Origin": "https://sibling.example.com", "Sec-Fetch-Site": "same-site"},
        {},
    ):
        chain.calls.clear()
        response = client.post(f"{PREFIX}/probe", headers=headers)
        assert response.status_code == 403
        assert chain.calls == []  # refused before authentication resolves anything


def test_with_the_deployment_setting_off_every_caller_gets_the_404_of_an_unknown_path(
    chain: _Chain, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deployment's opt-in holds at request time too, for an
    application whose startup check did not run (`TestClient` here is used
    without the lifespan): no credential, a non-operator and an operator
    holding the permission all get the same 404, and nothing else runs."""
    monkeypatch.setenv("PLATFORM_ADMIN_HTTP_ENABLED", "false")
    get_platform_admin_http_config.cache_clear()
    client = TestClient(_probe_app(fresh_session=True))
    url = f"{PREFIX}/probe/{uuid.uuid4()}"
    for headers in ({}, _BEARER):
        for response in (
            client.get(url, headers=headers),
            client.post(f"{PREFIX}/probe", headers=headers),
        ):
            assert (response.status_code, response.json()) == (404, _NOT_FOUND)
    assert chain.calls == [] and chain.refusals == []  # before authentication


def test_what_a_caller_can_still_tell_about_a_platform_path_is_only_what_is_documented(
    chain: _Chain,
) -> None:
    """Pinned, so that the list in ADR-0045 ("Implementation status",
    Phase D milestone 2) stays true. A caller with no authority gets the
    404 of an unknown path for a well-formed request to a real route. The
    framework answers three things before the chain runs, for anyone: a
    method the path does not serve (405), a body that is not JSON (422),
    and -- from the chain's first step -- a missing credential (401)."""
    chain.operator = False
    client = TestClient(_probe_app())
    item = uuid.uuid4()
    # Well-formed, by a non-operator: indistinguishable from an unknown path.
    assert client.get(f"{PREFIX}/probe/{item}", headers=_BEARER).status_code == 404
    assert client.get(f"{PREFIX}/probe/not-a-uuid", headers=_BEARER).status_code == 404
    assert client.post(f"{PREFIX}/probe", headers=_BEARER, json={"x": 1}).status_code == 404
    # Documented distinguishers.
    assert client.delete(f"{PREFIX}/probe/{item}", headers=_BEARER).status_code == 405
    assert client.get(f"{PREFIX}/probe/{item}").status_code == 401


def test_a_platform_path_registered_twice_with_different_policies_stops_startup() -> None:
    """A second route on the same method and path would be the one the
    startup rules see, while the router serves the first: it could hide an
    authority route declared without the fresh-session rule."""
    stale = deps.require_platform_permission(P.AUTHORITY_MANAGE, operation="operator.enroll")
    fresh = deps.require_platform_permission(
        P.AUTHORITY_MANAGE, operation="operator.enroll", fresh_session=True
    )
    app = FastAPI()

    async def handler() -> dict[str, str]:
        return {}

    app.add_api_route("/probe", handler, methods=["POST"], dependencies=[Depends(stale)])
    app.add_api_route("/probe", handler, methods=["POST"], dependencies=[Depends(fresh)])
    with pytest.raises(RoutePolicyViolationError, match="registered twice"):
        assert_route_policies(app, production=False)


# --- multi-factor login (ADR-0049) ---------------------------------------------------------


@pytest.mark.parametrize("fresh", [False, True])
@pytest.mark.parametrize(
    ("required", "multi_factor", "expected"),
    [
        (None, False, 200),  # unset: not required
        ("false", False, 200),
        ("true", True, 200),
        ("true", False, 401),
    ],
)
def test_a_deployment_can_require_a_multi_factor_login_for_every_platform_route(
    chain: _Chain,
    monkeypatch: pytest.MonkeyPatch,
    fresh: bool,
    required: str | None,
    multi_factor: bool,
    expected: int,
) -> None:
    if required is not None:
        monkeypatch.setenv("PLATFORM_OPERATOR_REQUIRE_MFA", required)
        get_platform_admin_http_config.cache_clear()
    chain.session = _Session(multi_factor=multi_factor)

    response = TestClient(_probe_app(fresh_session=fresh)).post(f"{PREFIX}/probe", headers=_BEARER)

    assert response.status_code == expected
    if expected == 401:
        assert response.headers["X-Error-Code"] == "multi_factor_required"
        assert response.json() == {"detail": "Authentication required."}
        (refusal,) = chain.refusals
        assert refusal["code"] == "multi_factor_required"
        assert "permission" not in chain.calls  # before platform_can()
    else:
        assert chain.refusals == []


def test_a_non_operator_learns_nothing_from_the_multi_factor_rule(
    chain: _Chain, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PLATFORM_OPERATOR_REQUIRE_MFA", "true")
    get_platform_admin_http_config.cache_clear()
    chain.operator = False
    chain.session = _Session(multi_factor=False)
    response = TestClient(_probe_app(fresh_session=False)).post(f"{PREFIX}/probe", headers=_BEARER)
    assert response.status_code == 404
    assert chain.refusals == []


@pytest.mark.parametrize(
    ("environment", "value", "required"),
    [
        ("production", None, True),  # production defaults to requiring it
        ("production", "false", False),
        ("development", None, False),
        ("test", "true", True),
    ],
)
def test_the_multi_factor_default_follows_the_environment(
    monkeypatch: pytest.MonkeyPatch, environment: str, value: str | None, required: bool
) -> None:
    monkeypatch.setenv("ENVIRONMENT", environment)
    if value is None:
        monkeypatch.delenv("PLATFORM_OPERATOR_REQUIRE_MFA", raising=False)
    else:
        monkeypatch.setenv("PLATFORM_OPERATOR_REQUIRE_MFA", value)
    get_platform_admin_http_config.cache_clear()
    try:
        assert get_platform_admin_http_config().require_multi_factor is required
    finally:
        get_platform_admin_http_config.cache_clear()


@pytest.mark.parametrize("value", ["yes", "TRUE", "1", ""])
def test_the_multi_factor_setting_is_exactly_true_or_false(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("PLATFORM_OPERATOR_REQUIRE_MFA", value)
    get_platform_admin_http_config.cache_clear()
    with pytest.raises(ValueError, match="PLATFORM_OPERATOR_REQUIRE_MFA"):
        get_platform_admin_http_config()
    get_platform_admin_http_config.cache_clear()


# --- the fresh-session rule (decision D2) ---------------------------------------------------


@pytest.mark.parametrize(
    ("age", "limit", "expected"),
    [
        (0, None, 200),
        (899, None, 200),  # one second inside the limit
        (901, None, 401),  # one second past it
        (86_400, None, 401),
        (59, "60", 200),
        (61, "60", 401),  # a deployment may lower the limit
    ],
)
def test_an_authority_route_requires_a_session_no_older_than_the_limit(
    chain: _Chain, monkeypatch: pytest.MonkeyPatch, age: int, limit: str | None, expected: int
) -> None:
    if limit is not None:
        monkeypatch.setenv("PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS", limit)
        get_platform_admin_http_config.cache_clear()
    chain.session = _Session(age_seconds=age)

    response = TestClient(_probe_app(fresh_session=True)).post(f"{PREFIX}/probe", headers=_BEARER)

    assert response.status_code == expected
    if expected == 401:
        assert response.headers["X-Error-Code"] == "session_not_fresh"
        assert response.json() == {"detail": "Authentication required."}
        (refusal,) = chain.refusals
        assert refusal["code"] == "session_not_fresh"
        assert refusal["action"] == "platform.operator.enroll"
        assert "permission" not in chain.calls  # before platform_can()
    else:
        assert chain.refusals == []


def test_an_old_session_is_accepted_on_a_route_that_does_not_change_authority(
    chain: _Chain,
) -> None:
    chain.session = _Session(age_seconds=86_400)
    client = TestClient(_probe_app(fresh_session=True))
    assert client.get(f"{PREFIX}/probe/{uuid.uuid4()}", headers=_BEARER).status_code == 200
    assert client.post(f"{PREFIX}/probe", headers=_BEARER).status_code == 401


def test_a_caller_who_is_not_an_operator_gets_404_even_with_an_old_session(chain: _Chain) -> None:
    """The route's existence is not confirmed to a non-operator by a
    session-age answer."""
    chain.session = _Session(age_seconds=86_400)
    chain.operator = False
    response = TestClient(_probe_app(fresh_session=True)).post(f"{PREFIX}/probe", headers=_BEARER)
    assert response.status_code == 404 and response.json() == _NOT_FOUND
    assert chain.refusals == []


# --- declaring a platform route ---------------------------------------------------------------


def test_a_route_cannot_be_declared_with_a_permission_its_operation_does_not_carry() -> None:
    with pytest.raises(ValueError, match="not gated by"):
        deps.require_platform_permission(P.BILLING_READ, operation="tenant.read")
    with pytest.raises(TypeError):
        deps.require_platform_permission("platform.tenant:read", operation="tenant.read")  # type: ignore[arg-type]
    with pytest.raises(LookupError):
        deps.require_platform_permission(P.TENANT_READ, operation="tenant.purge")
    with pytest.raises(TypeError):
        deps.require_platform_permission(
            P.TENANT_READ,
            operation="tenant.read",
            fresh_session="yes",  # type: ignore[arg-type]
        )


def _app_with(*dependencies: Any, method: str = "GET") -> FastAPI:
    app = FastAPI()

    async def handler() -> dict[str, str]:
        return {}

    app.add_api_route(
        "/probe", handler, methods=[method], dependencies=[Depends(d) for d in dependencies]
    )
    return app


def test_a_platform_route_resolves_to_the_platform_policy() -> None:
    gate = deps.require_platform_permission(P.TENANT_READ, operation="tenant.read")
    policies = assert_route_policies(_app_with(gate), production=False)
    assert policies == {
        "GET /probe": RoutePolicy(RoutePolicyKind.PLATFORM_PERMISSION, "platform.tenant:read")
    }


def test_a_platform_permission_conflicts_with_a_tenant_permission_and_with_another() -> None:
    platform = deps.require_platform_permission(P.TENANT_READ, operation="tenant.read")
    other = deps.require_platform_permission(P.BILLING_READ, operation="billing.read")
    fresh = deps.require_platform_permission(
        P.TENANT_READ, operation="tenant.read", fresh_session=True
    )
    tenant = deps.require_permission("tenant", "read_status")
    for conflicting in (
        (platform, tenant),
        (platform, other),
        (platform, fresh),  # the same permission, declared two ways
        (platform, public_route("deliberately public")),
    ):
        with pytest.raises(RoutePolicyViolationError):
            assert_route_policies(_app_with(*conflicting), production=False)


# --- the two opt-ins and the startup checks ------------------------------------------------


def _platform_policies(app: FastAPI) -> dict[str, RoutePolicy]:
    return {
        label: policy
        for label, policy in assert_route_policies(app, production=False).items()
        if policy.kind is RoutePolicyKind.PLATFORM_PERMISSION
    }


def test_nothing_mounts_the_router_by_default() -> None:
    """The default application and the reference application have no
    platform route, and no path under the platform prefix at all."""
    for app in (build_platform_app(title="default", version="test"), reference_app):
        assert _platform_policies(app) == {}
        assert not any(PREFIX in getattr(route, "path", "") for route in app.routes)


def test_mounted_without_the_setting_startup_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    app = build_platform_app(title="mounted", version="test")
    app.include_router(build_platform_admin_router())
    policies = assert_route_policies(app, production=False)

    with pytest.raises(RoutePolicyViolationError) as raised:
        assert_platform_route_rules(policies, enabled=False)
    # Every platform route is named, and nothing else is.
    assert len(raised.value.violations) == len(PLATFORM_ROUTES)
    assert all("PLATFORM_ADMIN_HTTP_ENABLED" in line for line in raised.value.violations)

    assert_platform_route_rules(policies, enabled=True)  # both opt-ins: it starts


def test_the_setting_alone_exposes_nothing() -> None:
    app = build_platform_app(title="default", version="test")
    policies = assert_route_policies(app, production=False)
    assert_platform_route_rules(policies, enabled=True)
    assert _platform_policies(app) == {}


def test_the_lifespan_runs_the_platform_route_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """The check is wired into startup, in the step that checks route
    policies: with the router mounted and the setting absent the
    application does not start."""
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("PLATFORM_ADMIN_HTTP_ENABLED", raising=False)
    get_platform_admin_http_config.cache_clear()
    app = build_platform_app(title="mounted", version="test")
    app.include_router(build_platform_admin_router())
    try:
        with pytest.raises(RoutePolicyViolationError, match="PLATFORM_ADMIN_HTTP_ENABLED"):
            with TestClient(app):
                pass
    finally:
        get_platform_admin_http_config.cache_clear()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_a_state_changing_authority_route_without_the_fresh_session_rule_stops_startup(
    method: str,
) -> None:
    stale = deps.require_platform_permission(P.AUTHORITY_MANAGE, operation="operator.enroll")
    fresh = deps.require_platform_permission(
        P.AUTHORITY_MANAGE, operation="operator.enroll", fresh_session=True
    )
    with pytest.raises(RoutePolicyViolationError, match="fresh session"):
        assert_platform_route_rules(
            assert_route_policies(_app_with(stale, method=method), production=False), enabled=True
        )
    assert_platform_route_rules(
        assert_route_policies(_app_with(fresh, method=method), production=False), enabled=True
    )
    # A read gated by the same permission needs no fresh session.
    assert_platform_route_rules(
        assert_route_policies(_app_with(stale, method="GET"), production=False), enabled=True
    )


@pytest.mark.parametrize("value", ["901", "59", "0", "-1", "3600", "fifteen", "", "900.0"])
def test_a_session_age_limit_outside_60_to_900_is_a_configuration_error(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS", value)
    get_platform_admin_http_config.cache_clear()
    try:
        with pytest.raises(PlatformAdminHttpConfigurationError):
            get_platform_admin_http_config()
    finally:
        get_platform_admin_http_config.cache_clear()


@pytest.mark.parametrize("value", ["901", "59"])
def test_an_invalid_session_age_limit_stops_startup_even_with_no_router_mounted(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS", value)
    get_platform_admin_http_config.cache_clear()
    try:
        with pytest.raises(PlatformAdminHttpConfigurationError):
            with TestClient(build_platform_app(title="default", version="test")):
                pass
    finally:
        get_platform_admin_http_config.cache_clear()


def test_the_configuration_defaults_and_accepts_only_exact_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def read(**env: str) -> PlatformAdminHttpConfig:
        for name in ("PLATFORM_ADMIN_HTTP_ENABLED", "PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS"):
            monkeypatch.delenv(name, raising=False)
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        get_platform_admin_http_config.cache_clear()
        try:
            return get_platform_admin_http_config()
        finally:
            get_platform_admin_http_config.cache_clear()

    assert read() == PlatformAdminHttpConfig(enabled=False, authority_session_max_age_seconds=900)
    assert read(PLATFORM_ADMIN_HTTP_ENABLED="true").enabled is True
    assert read(PLATFORM_ADMIN_HTTP_ENABLED="false").enabled is False
    assert (
        read(PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS="60").authority_session_max_age_seconds
        == 60
    )
    for typo in ("True", "TRUE", "1", "yes", "on", "", " true"):
        with pytest.raises(PlatformAdminHttpConfigurationError):
            read(PLATFORM_ADMIN_HTTP_ENABLED=typo)


# --- the route inventory, pinned ------------------------------------------------------------

# ADR-0045 section 7, written out: (method, path, permission, fresh session).
_CONTRACT: set[tuple[str, str, str, bool]] = {
    ("GET", "/tenants", "platform.tenant:read", False),
    ("GET", "/tenants/{tenant_id}", "platform.tenant:read", False),
    ("GET", "/users/{user_id}", "platform.user:read", False),
    ("POST", "/users/resolve", "platform.user:read", False),
    ("GET", "/operators", "platform.operator:read", False),
    ("GET", "/grants", "platform.operator:read", False),
    ("GET", "/audit", "platform.audit:read", False),
    ("GET", "/billing/overview", "platform.billing:read", False),
    ("GET", "/feature-flags", "platform.feature_flag:read", False),
    ("GET", "/tenants/{tenant_id}/feature-flags", "platform.feature_flag:read", False),
    ("POST", "/tenants", "platform.tenant:create", False),
    ("POST", "/tenants/{tenant_id}/activate", "platform.tenant:create", False),
    ("POST", "/tenants/{tenant_id}/suspend", "platform.tenant:suspend", False),
    ("POST", "/tenants/{tenant_id}/reactivate", "platform.tenant:reactivate", False),
    ("POST", "/users/{user_id}/deactivate", "platform.user:deactivate", False),
    ("POST", "/users/{user_id}/reactivate", "platform.user:reactivate", False),
    ("POST", "/users/{user_id}/sessions/revoke", "platform.session:revoke", False),
    ("POST", "/users/{user_id}/api-keys/revoke", "platform.api_key:revoke", False),
    ("POST", "/feature-flags", "platform.feature_flag:define", False),
    ("PUT", "/tenants/{tenant_id}/feature-flags/{key}", "platform.feature_flag:override", False),
    ("DELETE", "/tenants/{tenant_id}/feature-flags/{key}", "platform.feature_flag:override", False),
    ("POST", "/operators", "platform.authority:manage", True),
    ("POST", "/operators/{operator_id}/suspend", "platform.authority:manage", True),
    ("POST", "/operators/{operator_id}/reactivate", "platform.authority:manage", True),
    ("POST", "/operators/{operator_id}/revoke", "platform.authority:manage", True),
    ("POST", "/operators/{operator_id}/grants", "platform.authority:manage", True),
    ("POST", "/operators/{operator_id}/grants/revoke", "platform.authority:manage", True),
}


def _served(router: APIRouter) -> set[tuple[str, str, str, bool]]:
    """What the built router actually serves: every route with the policy
    its resolved dependency graph declares."""
    app = FastAPI()
    app.include_router(router)
    served = set()
    for label, policy in assert_route_policies(app, production=False).items():
        methods, path = label.split(" ", 1)
        assert policy.kind is RoutePolicyKind.PLATFORM_PERMISSION, label
        assert path.startswith(PREFIX), label
        for method in methods.split(","):
            served.add((method, path[len(PREFIX) :], policy.detail, policy.fresh_session))
    return served


def test_the_route_set_and_the_one_permission_of_each_route_are_the_contract() -> None:
    declared = {
        (route.method, route.path, route.permission.value, route.fresh_session)
        for route in PLATFORM_ROUTES
    }
    assert declared == _CONTRACT
    assert _served(build_platform_admin_router()) == _CONTRACT
    assert len(PLATFORM_ROUTES) == len(_CONTRACT) == 27  # no duplicate declaration


def test_every_route_names_an_operation_its_permission_gates() -> None:
    for route in PLATFORM_ROUTES:
        assert PLATFORM_OPERATIONS[route.operation].permission is route.permission, route


def test_every_permission_but_those_kept_off_the_network_has_a_route() -> None:
    """Tenant move and delete (section 7), the AI configuration
    permissions (ADR-0054 AI-C: operator command only, no HTTP route), and
    outbox replay (ADR-0045 amendment of 2026-10-31: operator command only)."""
    routed = {route.permission for route in PLATFORM_ROUTES}
    assert set(P) - routed == {
        P.TENANT_MOVE,
        P.TENANT_DELETE,
        P.AI_CONFIG_READ,
        P.AI_USAGE_READ,
        P.AI_PROVIDER_MANAGE,
        P.AI_ENDPOINT_TRUST_MANAGE,
        P.AI_POLICY_MANAGE,
        P.OUTBOX_REPLAY,
    }


def test_no_route_exists_for_what_stays_off_the_network() -> None:
    """Section 7: no HTTP route for move, delete, purge, erasure, owner
    bootstrap, recovery, migrations or backup."""
    paths = " ".join(route.path for route in PLATFORM_ROUTES)
    for word in ("move", "delete", "purge", "erase", "bootstrap", "recover", "migrat", "backup"):
        assert word not in paths, word
    # The only DELETE removes a flag override; it deletes no tenant or user.
    assert [route.path for route in PLATFORM_ROUTES if route.method == "DELETE"] == [
        "/tenants/{tenant_id}/feature-flags/{key}"
    ]


def test_every_state_changing_authority_route_requires_a_fresh_session() -> None:
    for route in PLATFORM_ROUTES:
        if route.permission is P.AUTHORITY_MANAGE and route.method != "GET":
            assert route.fresh_session, route
        else:
            assert not route.fresh_session, route


def test_swapping_one_routes_permission_fails_the_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative control for the pinned contract: gate the tenant list with
    the billing permission and the served set no longer matches."""
    swapped = tuple(
        PlatformRoute("GET", "/tenants", P.BILLING_READ, "billing.read")
        if (route.method, route.path) == ("GET", "/tenants")
        else route
        for route in PLATFORM_ROUTES
    )
    monkeypatch.setattr(router_module, "PLATFORM_ROUTES", swapped)
    served = _served(router_module.build_router())
    assert served != _CONTRACT
    assert ("GET", "/tenants", "platform.billing:read", False) in served
