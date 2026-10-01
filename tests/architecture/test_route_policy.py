"""Foundation Enforcement FE-4 -- secure-by-default route policy
(`api/route_policy.py`; docs/ADR/0030-foundation-enforcement.md).

Every route of every application built on `build_platform_app()` must
declare exactly one policy -- permission, authenticated, or explicitly
public with a reason -- read from FastAPI's resolved dependency graph, and
an application with an undeclared route must fail at startup. No database
is needed: the policy check runs before anything else in the lifespan.
"""

from __future__ import annotations

import ast
import functools
import sys
from pathlib import Path

import pytest
from api.dependencies import (
    get_current_actor,
    get_current_session,
    require_entitlement_and_quota,
    require_permission,
)
from api.main import create_app
from api.platform import build_platform_app
from api.route_policy import (
    RoutePolicy,
    RoutePolicyKind,
    RoutePolicyViolationError,
    _register_policy_dependency,
    assert_route_policies,
    public_route,
    route_policy_of,
)
from core.config import get_settings
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REFERENCE_CONSUMER_ROOT = _REPO_ROOT / "examples" / "reference-consumer"

P = RoutePolicyKind


def _app_with(router: APIRouter) -> FastAPI:
    app = build_platform_app(title="t", version="0")
    app.include_router(router)
    return app


def _policies(app: FastAPI) -> dict[str, tuple[RoutePolicyKind, str]]:
    return {
        route: (policy.kind, policy.detail)
        for route, policy in assert_route_policies(app, production=False).items()
    }


# --- Real applications ----------------------------------------------------------


def test_every_route_of_api_main_declares_exactly_one_policy() -> None:
    policies = _policies(create_app())
    assert {route: kind for route, (kind, _) in policies.items()} == {
        "GET /healthz": P.PUBLIC,
        "GET /readyz": P.PUBLIC,
        "GET /auth/login": P.PUBLIC,
        "GET /auth/callback": P.PUBLIC,
        "POST /auth/logout": P.AUTHENTICATED,
        "GET /auth/me": P.AUTHENTICATED,
        "GET /v1/tenants/{tenant_id}/status": P.PERMISSION,
    }
    assert policies["GET /v1/tenants/{tenant_id}/status"][1] == "tenant:read_status"
    for route, (kind, detail) in policies.items():
        if kind is P.PUBLIC:
            assert detail.strip(), route


def test_every_route_of_the_reference_consumer_declares_exactly_one_policy() -> None:
    if str(_REFERENCE_CONSUMER_ROOT) not in sys.path:
        sys.path.insert(0, str(_REFERENCE_CONSUMER_ROOT))
    from reference_consumer.app import create_app as create_reference_consumer_app

    policies = _policies(create_reference_consumer_app())
    assert policies["GET /widgets/{tenant_id}/{widget_id}"] == (
        P.PERMISSION,
        "reference_consumer.widgets:read",
    )
    assert all(kind is not None for kind, _ in policies.values())


def test_health_probes_are_public_not_authenticated() -> None:
    policies = _policies(create_app())
    assert policies["GET /healthz"][0] is P.PUBLIC
    assert policies["GET /readyz"][0] is P.PUBLIC


# --- Synthetic applications ---------------------------------------------------------


def test_unguarded_route_fails_the_validator() -> None:
    router = APIRouter()

    @router.get("/unguarded")
    def unguarded() -> dict[str, str]:
        return {}

    with pytest.raises(RoutePolicyViolationError, match="GET /unguarded: no route policy"):
        assert_route_policies(_app_with(router), production=False)


def test_unguarded_route_fails_application_startup_closed() -> None:
    """The lifespan check runs before anything else -- no request is ever
    served and no database is contacted."""
    router = APIRouter(prefix="/v1/new")

    @router.get("/things")
    def things() -> dict[str, str]:
        return {}

    app = _app_with(router)
    with pytest.raises(RoutePolicyViolationError, match="GET /v1/new/things"), TestClient(app):
        pass


def test_router_level_dependency_counts_for_every_route_it_covers() -> None:
    router = APIRouter(dependencies=[Depends(require_permission("widget", "read"))])

    @router.get("/a")
    def a() -> dict[str, str]:
        return {}

    app = build_platform_app(title="t", version="0")
    app.include_router(router, prefix="/v1/x")
    assert _policies(app)["GET /v1/x/a"] == (P.PERMISSION, "widget:read")


def test_valid_public_route_is_accepted() -> None:
    router = APIRouter()

    @router.get(
        "/open", dependencies=[Depends(public_route("status page for unauthenticated users"))]
    )
    def open_route() -> dict[str, str]:
        return {}

    assert _policies(_app_with(router))["GET /open"] == (
        P.PUBLIC,
        "status page for unauthenticated users",
    )


@pytest.mark.parametrize("dependency", [get_current_actor, get_current_session])
def test_valid_authenticated_route_is_accepted(dependency) -> None:  # type: ignore[no-untyped-def]
    router = APIRouter()

    @router.get("/mine", dependencies=[Depends(dependency)])
    def mine() -> dict[str, str]:
        return {}

    assert _policies(_app_with(router))["GET /mine"] == (P.AUTHENTICATED, "")


def test_valid_permission_route_is_accepted_and_names_its_permission() -> None:
    router = APIRouter()

    @router.get("/r/{tenant_id}", dependencies=[Depends(require_permission("report", "read"))])
    def report() -> dict[str, str]:
        return {}

    assert _policies(_app_with(router))["GET /r/{tenant_id}"] == (P.PERMISSION, "report:read")


def test_entitlement_and_quota_routes_resolve_to_their_permission() -> None:
    router = APIRouter()

    @router.post(
        "/q/{tenant_id}",
        dependencies=[Depends(require_entitlement_and_quota("widget", "create", quota_metric="m"))],
    )
    def quota_route() -> dict[str, str]:
        return {}

    assert _policies(_app_with(router))["POST /q/{tenant_id}"] == (P.PERMISSION, "widget:create")


def test_permission_route_that_also_reads_the_actor_is_one_permission_policy() -> None:
    router = APIRouter()

    @router.get(
        "/p/{tenant_id}",
        dependencies=[Depends(require_permission("report", "read")), Depends(get_current_actor)],
    )
    def both() -> dict[str, str]:
        return {}

    assert _policies(_app_with(router))["GET /p/{tenant_id}"] == (P.PERMISSION, "report:read")


@pytest.mark.parametrize(
    ("dependencies", "message"),
    [
        (
            [Depends(public_route("open")), Depends(get_current_actor)],
            "public conflicts with another policy",
        ),
        (
            [Depends(public_route("open")), Depends(require_permission("r", "a"))],
            "public conflicts with another policy",
        ),
        (
            [Depends(require_permission("r", "a")), Depends(require_permission("r", "b"))],
            "conflicting permissions",
        ),
    ],
)
def test_conflicting_policies_fail(dependencies, message: str) -> None:  # type: ignore[no-untyped-def]
    router = APIRouter()

    @router.get("/c/{tenant_id}", dependencies=dependencies)
    def conflicted() -> dict[str, str]:
        return {}

    with pytest.raises(RoutePolicyViolationError, match=message):
        assert_route_policies(_app_with(router), production=False)


@pytest.mark.parametrize("reason", ["", "   "])
def test_public_route_requires_a_reason(reason: str) -> None:
    with pytest.raises(ValueError):
        public_route(reason)


def test_a_public_marker_without_reason_fails_the_validator() -> None:
    async def sneaky_public() -> None:
        return None

    _register_policy_dependency(sneaky_public, RoutePolicy(P.PUBLIC, ""))
    router = APIRouter()

    @router.get("/sneaky", dependencies=[Depends(sneaky_public)])
    def sneaky() -> dict[str, str]:
        return {}

    with pytest.raises(RoutePolicyViolationError, match="public route without a reason"):
        assert_route_policies(_app_with(router), production=False)


def test_a_bare_starlette_route_has_no_policy_and_fails() -> None:
    app = build_platform_app(title="t", version="0")

    async def raw(request: Request) -> Response:
        return PlainTextResponse("")

    app.add_route("/raw", raw)
    with pytest.raises(RoutePolicyViolationError, match="/raw: Route has no route policy"):
        assert_route_policies(app, production=False)


def test_policies_belong_to_the_existing_dependencies() -> None:
    """No new auth engine: the policy is recorded against the exact
    dependency objects that already enforce authentication and RBAC."""
    assert route_policy_of(get_current_actor) == RoutePolicy(P.AUTHENTICATED)
    assert route_policy_of(get_current_session) == RoutePolicy(P.AUTHENTICATED)
    assert route_policy_of(require_permission("r", "a")) == RoutePolicy(P.PERMISSION, "r:a")


def test_a_wrapper_of_get_current_actor_inherits_no_policy() -> None:
    """Review finding F-1: `functools.wraps` copies the wrapped function's
    `__dict__`, so an attribute marker would make a weakened wrapper (here:
    one that never authenticates) look compliant. The identity registry
    does not."""

    @functools.wraps(get_current_actor)
    async def weakened(*args: object, **kwargs: object) -> None:
        return None

    assert route_policy_of(weakened) is None
    router = APIRouter()

    @router.get("/weakened", dependencies=[Depends(weakened)])
    def handler() -> dict[str, str]:
        return {}

    with pytest.raises(RoutePolicyViolationError, match="GET /weakened: no route policy"):
        assert_route_policies(_app_with(router), production=False)


def test_a_wrapper_of_a_permission_dependency_never_inherits_the_permission() -> None:
    """A `functools.wraps` wrapper of a `require_permission()` closure gets
    the closure's *signature* too (`__wrapped__`), so FastAPI still runs its
    real `get_tenant_context -> get_current_actor` sub-dependencies. The
    validator reports exactly what is enforced -- authentication -- and
    never the RBAC check the wrapper dropped."""

    @functools.wraps(require_permission("r", "a"))
    async def weakened(*args: object, **kwargs: object) -> None:
        return None

    assert route_policy_of(weakened) is None
    router = APIRouter()

    @router.get("/weakened", dependencies=[Depends(weakened)])
    def handler() -> dict[str, str]:
        return {}

    assert _policies(_app_with(router))["GET /weakened"] == (P.AUTHENTICATED, "")


def test_a_policy_attribute_on_a_plain_function_is_ignored() -> None:
    async def forged() -> None:
        return None

    forged.__saas_os_route_policy__ = RoutePolicy(P.PERMISSION, "r:a")  # type: ignore[attr-defined]
    router = APIRouter()

    @router.get("/forged", dependencies=[Depends(forged)])
    def handler() -> dict[str, str]:
        return {}

    with pytest.raises(RoutePolicyViolationError, match="GET /forged: no route policy"):
        assert_route_policies(_app_with(router), production=False)


def test_only_the_route_policy_and_dependency_modules_register_policies() -> None:
    """Registering a policy dependency is reserved for the modules that
    construct the enforcing dependencies; nothing else in the shipped code
    (Core, Infra, Control Plane, products, the reference consumer) may."""
    allowed = {Path("api/route_policy.py"), Path("api/dependencies.py")}
    offenders = []
    for top in ("api", "core", "infra", "control-plane", "products", "examples", "contracts"):
        for path in (_REPO_ROOT / top).rglob("*.py"):
            relative = path.relative_to(_REPO_ROOT)
            if relative in allowed:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                name = node.id if isinstance(node, ast.Name) else getattr(node, "attr", None)
                alias = node.name if isinstance(node, ast.alias) else None
                if "_register_policy_dependency" in (name, alias):
                    offenders.append(str(relative))
    assert offenders == []


# --- D1: API documentation is an explicit, environment-dependent policy -------------


@pytest.fixture
def environment(monkeypatch: pytest.MonkeyPatch):
    def _set(value: str) -> None:
        monkeypatch.setenv("ENVIRONMENT", value)
        get_settings.cache_clear()

    yield _set
    get_settings.cache_clear()


def test_api_documentation_is_served_outside_production(environment) -> None:  # type: ignore[no-untyped-def]
    environment("test")
    app = create_app()
    assert (app.openapi_url, app.docs_url, app.redoc_url) == ("/openapi.json", "/docs", "/redoc")
    assert_route_policies(app, production=False)


def test_api_documentation_is_disabled_in_production(environment) -> None:  # type: ignore[no-untyped-def]
    environment("production")
    app = create_app()
    assert (app.openapi_url, app.docs_url, app.redoc_url) == (None, None, None)
    paths = {getattr(route, "path", None) for route in app.routes}
    assert not paths & {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
    assert_route_policies(app, production=True)


def test_documentation_routes_fail_the_production_check() -> None:
    app = FastAPI()  # documentation enabled by FastAPI's defaults
    with pytest.raises(RoutePolicyViolationError, match="must be disabled in production"):
        assert_route_policies(app, production=True)
