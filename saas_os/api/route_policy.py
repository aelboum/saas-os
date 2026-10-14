"""Secure-by-default route policy (Foundation Enforcement, FE-4;
docs/ADR/0030-foundation-enforcement.md).

Every HTTP route must declare exactly one policy, read from its *resolved*
FastAPI dependency graph -- never from path strings:

    permission     the route depends (directly, or through a wrapper such as
                   `require_entitlement_and_quota`) on
                   `saas_os.api.dependencies.require_permission(resource, action)`:
                   authentication -> tenant resolution -> rate limit -> RBAC.
    authenticated  the route depends on `saas_os.api.dependencies.get_current_actor`
                   or `get_current_session` and nothing grants more.
    public         the route declares `public_route(reason)` -- a no-op
                   dependency whose only job is to state, in code, why the
                   route is deliberately reachable without credentials.
    platform_permission
                   the route depends on
                   `saas_os.api.dependencies.require_platform_permission(...)`
                   (ADR-0045 section 7): authentication -> rate limit ->
                   platform authority. No tenant is resolved.

This is not a second authentication or authorization system. The exact
dependency objects that already enforce authentication and RBAC in
`saas_os/api/dependencies.py` (plus every `public_route()` closure) are recorded in
a private identity registry; they enforce exactly what they enforced
before. The registry is keyed by object *identity*, never by an attribute
on the function: a wrapper of an enforcing dependency (e.g. one built with
`functools.wraps`, which copies the wrapped function's `__dict__`) is a
different object and carries no policy, so a weakened wrapper can never
inherit one. Only `saas_os/api/route_policy.py` and `saas_os/api/dependencies.py` may call
`_register_policy_dependency()` (pinned by
`tests/architecture/test_route_policy.py`).
`assert_route_policies(app)` only checks that every route opted into one of
them, and `saas_os/api/platform.py::_platform_lifespan` runs it first thing at
startup -- after every router, including a consumer's, has been mounted --
so an application with an undeclared route fails closed and never serves a
request.

Resolution rules (`route_policy_for()`):

- a permission policy implies authentication, so `authenticated` markers
  found inside (or next to) a permission dependency collapse into it;
- `public` together with any other marker is a conflict;
- two *different* permissions on one route is a conflict (one route, one
  permission);
- no marker at all is a missing policy;
- a public marker with an empty reason is invalid;
- a platform permission together with a tenant permission is a conflict: a
  platform route never takes authority from a tenant, and a tenant route
  never from platform authority;
- two *different* platform permissions on one route is a conflict, and so
  is the same one declared both with and without the fresh-session rule.

Two further rules apply to platform routes as a set
(`assert_platform_route_rules()`, run in the same startup step): none may
be served unless the deployment enabled the platform-admin surface, and a
state-changing route gated by `platform.authority:manage` must require a
fresh session.

FastAPI's own documentation routes (`openapi_url`, `docs_url`,
`swagger_ui_oauth2_redirect_url`, `redoc_url`) are plain Starlette routes
with no dependency graph. They are accepted only as exactly those
configured URLs and only outside production -- `build_platform_app()`
disables them when `ENVIRONMENT=production`, and a production app that
still exposes them fails this check. Any other route type (a `Mount`, a
bare Starlette `Route`, a websocket) has no policy and fails.
"""

from __future__ import annotations

import enum
import weakref
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts


class RoutePolicyKind(enum.StrEnum):
    PERMISSION = "permission"
    AUTHENTICATED = "authenticated"
    PUBLIC = "public"
    PLATFORM_PERMISSION = "platform_permission"


@dataclass(frozen=True)
class RoutePolicy:
    """`detail` is `"resource:action"` for a permission policy, the reason
    for a public policy, the platform permission's value for a platform
    policy, and empty for an authenticated one. `fresh_session` is set
    only by a platform policy that requires a recently issued session.
    `accepts_api_key` is set only by a permission policy that also admits
    an API key (ADR-0047)."""

    kind: RoutePolicyKind
    detail: str = ""
    fresh_session: bool = False
    accepts_api_key: bool = False


class RoutePolicyViolationError(RuntimeError):
    """Raised by `assert_route_policies()`; lists every violation."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        super().__init__(
            "Application routes without a valid route policy (docs/ADR/0030-"
            "foundation-enforcement.md): " + "; ".join(violations)
        )


# Identity registry: the exact dependency objects that declare a policy.
# Weak keys, so a `require_permission()`/`public_route()` closure that no
# route holds any more is dropped with it.
_POLICY_DEPENDENCIES: weakref.WeakKeyDictionary[Callable[..., Any], RoutePolicy] = (
    weakref.WeakKeyDictionary()
)


def _register_policy_dependency[F: Callable[..., Any]](dependency: F, policy: RoutePolicy) -> F:
    """Record that this exact `dependency` object enforces `policy`. Does not
    change what the dependency does. Private to `saas_os/api/route_policy.py` and
    `saas_os/api/dependencies.py` -- the only modules that construct enforcing
    dependencies."""
    _POLICY_DEPENDENCIES[dependency] = policy
    return dependency


def route_policy_of(dependency: object) -> RoutePolicy | None:
    """The policy this exact dependency object declares, or `None`."""
    try:
        return _POLICY_DEPENDENCIES.get(dependency)  # type: ignore[arg-type]
    except TypeError:  # not weak-referenceable: never registered
        return None


def public_route(reason: str) -> Callable[[], Any]:
    """A no-op dependency declaring the route deliberately public, e.g.
    `@router.get("/healthz", dependencies=[Depends(public_route("liveness
    probe"))])`. `reason` must say why no credential is required."""
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("public_route() requires a non-empty reason.")

    async def _public_route() -> None:
        return None

    return _register_policy_dependency(_public_route, RoutePolicy(RoutePolicyKind.PUBLIC, reason))


def _markers(dependant: Any) -> Iterator[RoutePolicy]:
    for sub in getattr(dependant, "dependencies", ()):
        policy = route_policy_of(sub.call)
        if policy is not None:
            yield policy
        yield from _markers(sub)


def route_policy_for(label: str, dependant: Any) -> RoutePolicy:
    """The single effective policy of a route whose resolved dependency
    graph is `dependant`, or `RoutePolicyViolationError` describing why it
    has none. `label` names the route in the error."""
    found = list(_markers(dependant))
    publics = {p for p in found if p.kind is RoutePolicyKind.PUBLIC}
    permissions = {p for p in found if p.kind is RoutePolicyKind.PERMISSION}
    platform = {p for p in found if p.kind is RoutePolicyKind.PLATFORM_PERMISSION}
    authenticated = any(p.kind is RoutePolicyKind.AUTHENTICATED for p in found)

    if publics and (permissions or authenticated or platform):
        raise RoutePolicyViolationError([f"{label}: public conflicts with another policy"])
    if platform and permissions:
        raise RoutePolicyViolationError(
            [f"{label}: a platform permission conflicts with a tenant permission"]
        )
    if len(platform) > 1:
        details = sorted((p.detail, p.fresh_session) for p in platform)
        raise RoutePolicyViolationError([f"{label}: conflicting platform permissions {details}"])
    if platform:
        return next(iter(platform))
    if len(publics) > 1:
        raise RoutePolicyViolationError([f"{label}: more than one public declaration"])
    if len(permissions) > 1:
        details = sorted(p.detail for p in permissions)
        raise RoutePolicyViolationError([f"{label}: conflicting permissions {details}"])
    if permissions:
        return next(iter(permissions))
    if authenticated:
        return RoutePolicy(RoutePolicyKind.AUTHENTICATED)
    if publics:
        policy = next(iter(publics))
        if not policy.detail.strip():
            raise RoutePolicyViolationError([f"{label}: public route without a reason"])
        return policy
    raise RoutePolicyViolationError([f"{label}: no route policy declared"])


def _documentation_paths(app: FastAPI) -> set[str]:
    paths = {app.openapi_url, app.docs_url, app.redoc_url}
    if app.docs_url:
        paths.add(app.swagger_ui_oauth2_redirect_url)
    return {path for path in paths if path}


def assert_route_policies(app: FastAPI, *, production: bool) -> dict[str, RoutePolicy]:
    """Check every route of the fully assembled `app`. Returns
    `{"METHODS path": policy}` for the API routes; raises
    `RoutePolicyViolationError` listing every violation otherwise."""
    violations: list[str] = []
    policies: dict[str, RoutePolicy] = {}
    documentation = _documentation_paths(app)
    # FastAPI's own resolution of the app's effective routes: included
    # routers are expanded with their prefixes and router-level
    # dependencies, exactly as they are served.
    for context in iter_route_contexts(app.routes):
        path = context.path or repr(context.original_route)
        if isinstance(context.original_route, APIRoute):
            label = f"{','.join(sorted(context.methods or []))} {path}"
            try:
                policy = route_policy_for(label, context.dependant)
            except RoutePolicyViolationError as exc:
                violations.extend(exc.violations)
                continue
            earlier = policies.get(label)
            if (
                earlier is not None
                and earlier != policy
                and RoutePolicyKind.PLATFORM_PERMISSION in (earlier.kind, policy.kind)
            ):
                # The router serves the first registration and this mapping
                # would keep the last: a second route on a platform path
                # could hide the first from `assert_platform_route_rules()`.
                violations.append(f"{label}: registered twice with different policies")
            policies[label] = policy
            continue
        if path in documentation and not production:
            continue
        if path in documentation:
            violations.append(f"{path}: API documentation must be disabled in production")
        else:
            violations.append(
                f"{path}: {type(context.original_route).__name__} has no route policy"
            )
    if violations:
        raise RoutePolicyViolationError(violations)
    return policies


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# `PlatformPermission.AUTHORITY_MANAGE.value`, written out: this module
# imports nothing from Core.
_AUTHORITY_PERMISSION = "platform.authority:manage"


def assert_platform_route_rules(policies: dict[str, RoutePolicy], *, enabled: bool) -> None:
    """The two rules of ADR-0045 section 7 that concern the platform routes
    as a set. `policies` is what `assert_route_policies()` returned for the
    fully assembled application; `enabled` is the deployment's
    `PLATFORM_ADMIN_HTTP_ENABLED`.

    - **Two opt-ins.** A platform route is served only if a product
      mounted it *and* the deployment enabled the surface. Mounted and not
      enabled fails startup: a stray `include_router` cannot expose it.
      (Enabled and not mounted is nothing: there is no route to serve.)
    - **Fresh session for authority changes.** A route with an unsafe
      method gated by `platform.authority:manage` must have been declared
      with `fresh_session=True`."""
    violations: list[str] = []
    for label, policy in sorted(policies.items()):
        if policy.kind is not RoutePolicyKind.PLATFORM_PERMISSION:
            continue
        if not enabled:
            violations.append(
                f"{label}: a platform route is mounted but PLATFORM_ADMIN_HTTP_ENABLED is not true"
            )
        methods = set(label.split(" ", 1)[0].split(","))
        if (
            policy.detail == _AUTHORITY_PERMISSION
            and not methods <= _SAFE_METHODS
            and not policy.fresh_session
        ):
            violations.append(
                f"{label}: a state-changing platform.authority:manage route must require a "
                "fresh session"
            )
    if violations:
        raise RoutePolicyViolationError(violations)
