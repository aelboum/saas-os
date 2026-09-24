"""ADR-0024 -- the single-origin routing contract (`infra/edge/routing.py`)
checked against the route table the application actually mounts, so the
declared contract and the real backend surface cannot drift apart. No
network, no database (the app is constructed, never started)."""

from __future__ import annotations

import pytest
from api.main import create_app

from infra.edge import BACKEND_EXACT_PATHS, BACKEND_ROUTE_PREFIXES, is_backend_path

# FastAPI mounts these itself. They are deliberately NOT part of the
# browser-facing contract: the production Caddyfile has never proxied them
# (its own "the backend's actual external route surface" comment), and the
# local edge matches that rather than publishing an API schema/explorer on
# the application origin. A developer reaches them on `backend`'s own
# direct host port (docker-compose.yml's documented escape hatch).
_FASTAPI_BUILTIN_DOC_PATHS = frozenset(
    {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
)


def _application_paths() -> set[str]:
    """Every path the built application actually serves.

    FastAPI's installed version keeps an `include_router()`ed router as one
    composite entry in `app.routes` rather than flattening its children into
    it, so both shapes are handled. An unrecognized third shape fails loudly
    -- a silently empty route set would make every assertion here pass
    vacuously, which is exactly the failure mode this module exists to
    prevent.
    """
    paths: set[str] = set()
    for route in create_app().routes:
        path = getattr(route, "path", None)
        if path is not None:
            paths.add(path)
            continue
        included = getattr(route, "original_router", None)
        if included is None:  # pragma: no cover -- guards a framework change
            raise AssertionError(
                f"Unrecognized route object {type(route).__name__}: cannot read its paths."
            )
        paths.update(child.path for child in included.routes if hasattr(child, "path"))
    return paths


def test_every_mounted_application_route_is_either_declared_or_a_doc_route() -> None:
    paths = _application_paths()
    undeclared = {
        path
        for path in paths
        if not is_backend_path(path) and path not in _FASTAPI_BUILTIN_DOC_PATHS
    }
    assert undeclared == set(), (
        "These mounted backend routes are not covered by infra/edge/routing.py's "
        "contract, so the single-origin edge would proxy them to the frontend: "
        f"{sorted(undeclared)}"
    )


def test_the_auth_and_health_routes_the_contract_promises_actually_exist() -> None:
    paths = _application_paths()
    assert {"/auth/login", "/auth/callback", "/auth/logout", "/auth/me"} <= paths
    assert set(BACKEND_EXACT_PATHS) <= paths
    assert any(path.startswith("/v1/") for path in paths)


def test_doc_routes_are_not_exposed_through_the_edge() -> None:
    """Asserted as an intentional property, not an accident."""
    for path in _FASTAPI_BUILTIN_DOC_PATHS:
        assert not is_backend_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "/auth/login",
        "/auth/callback",
        "/v1/tenants/00000000-0000-0000-0000-000000000000/status",
        "/healthz",
        "/readyz",
    ],
)
def test_backend_paths_route_to_the_backend(path: str) -> None:
    assert is_backend_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/favicon.ico",
        "/_next/static/chunk.js",
        # Product-owned routes SaaS-OS knows nothing about -- they reach the
        # frontend precisely because SaaS-OS never enumerates them.
        "/dashboard",
        "/app",
        "/t/2f1c/dashboard",
        # Near-misses that must NOT be treated as backend paths.
        "/authorize",
        "/auth",
        "/v1",
        "/v10/tenants",
        "/readyz-public",
    ],
)
def test_everything_else_routes_to_the_product_frontend(path: str) -> None:
    assert not is_backend_path(path)


def test_the_contract_declares_no_internal_service_path() -> None:
    """The edge must never grow a route to PostgreSQL, Redis, the worker,
    ZITADEL, or ZITADEL's own database -- they are reachable only over the
    Compose network, by the services that need them."""
    declared = " ".join(BACKEND_ROUTE_PREFIXES + BACKEND_EXACT_PATHS).lower()
    for forbidden in ("postgres", "redis", "zitadel", "worker", "temporal", "db"):
        assert forbidden not in declared
