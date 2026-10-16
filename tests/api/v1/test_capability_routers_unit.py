"""The contract of the opt-in capability routers (docs/ADR/0040-...), with no
database: what is reachable, what gates it, and what a response may carry.

Behavior against real PostgreSQL and Redis -- the denial matrix, tenant
isolation, one-time secrets, billing invariants -- is
`test_capability_routers_integration.py`.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from pydantic import BaseModel

import saas_os.api.v1 as v1
from saas_os.api.platform import build_platform_app
from saas_os.api.route_policy import RoutePolicyKind, assert_route_policies
from saas_os.api.v1 import api_keys, billing, invitations, members, usage
from saas_os.api.v1.permissions import CAPABILITY_PERMISSIONS
from saas_os.core.billing import FakeBillingProvider
from saas_os.core.rbac.authorization import AUTHORITY_RESOURCES

_V1_DIR = Path(v1.__file__).resolve().parent
_ROUTER_MODULES = ("members", "invitations", "api_keys", "billing", "usage")

# method + path -> the one permission that gates it. The whole approved
# surface: a route missing here, or here and not served, fails below.
_EXPECTED = {
    "GET /v1/tenants/{tenant_id}/members": "membership:read",
    "POST /v1/tenants/{tenant_id}/members/{membership_id}/suspend": "membership:suspend",
    "POST /v1/tenants/{tenant_id}/members/{membership_id}/reactivate": "membership:reactivate",
    "POST /v1/tenants/{tenant_id}/members/{membership_id}/revoke": "membership:revoke",
    "POST /v1/tenants/{tenant_id}/invitations": "invitation:create",
    "GET /v1/tenants/{tenant_id}/invitations": "invitation:read",
    "POST /v1/tenants/{tenant_id}/invitations/{invitation_id}/revoke": "invitation:revoke",
    "POST /v1/tenants/{tenant_id}/api-keys": "api_key:self_manage",
    "GET /v1/tenants/{tenant_id}/api-keys": "api_key:self_manage",
    "POST /v1/tenants/{tenant_id}/api-keys/{key_id}/rotate": "api_key:self_manage",
    "DELETE /v1/tenants/{tenant_id}/api-keys/{key_id}": "api_key:self_manage",
    "GET /v1/tenants/{tenant_id}/billing/entitlements": "billing.subscription:read",
    "GET /v1/tenants/{tenant_id}/billing/plans": "billing.subscription:create",
    "POST /v1/tenants/{tenant_id}/billing/subscriptions": "billing.subscription:create",
    "POST /v1/tenants/{tenant_id}/billing/subscriptions/{subscription_id}/cancel": (
        "billing.subscription:cancel"
    ),
    "POST /v1/tenants/{tenant_id}/billing/subscriptions/{subscription_id}/payment-page": (
        "billing.subscription:read"
    ),
    "GET /v1/tenants/{tenant_id}/billing/payer-subscriptions": "billing.account:read",
    "GET /v1/tenants/{tenant_id}/billing/payer-subscriptions/{subscription_id}": (
        "billing.account:read"
    ),
    "GET /v1/tenants/{tenant_id}/usage": "billing.subscription:read",
}


def _routers() -> list[APIRouter]:
    return [
        v1.members_router,
        v1.invitations_router,
        v1.api_keys_router,
        v1.build_billing_router(provider=FakeBillingProvider()),
        v1.usage_router,
    ]


def _app_with_every_capability() -> FastAPI:
    app = build_platform_app(title="capability contract", version="test")
    for router in _routers():
        app.include_router(router)
    return app


def _capability_routes(app: FastAPI) -> dict[str, tuple[APIRoute, object]]:
    """`METHOD path` -> (route, resolved dependant) for every `/v1` route the
    app serves, enumerated the way `assert_route_policies` does: FastAPI's
    own expansion of included routers."""
    routes: dict[str, tuple[APIRoute, object]] = {}
    for context in iter_route_contexts(app.routes):
        route = context.original_route
        if isinstance(route, APIRoute) and (context.path or "").startswith("/v1/"):
            for method in sorted(context.methods or []):
                routes[f"{method} {context.path}"] = (route, context.dependant)
    return routes


# --- Opt-in: nothing is reachable until a product registers it ---------------------------


def test_the_platform_app_mounts_no_capability_route() -> None:
    assert _capability_routes(build_platform_app(title="bare", version="test")) == {}


def test_this_repositorys_own_application_mounts_none_of_them_either() -> None:
    import saas_os.api.main as main

    assert set(_capability_routes(main.create_app())) == {"GET /v1/tenants/{tenant_id}/status"}


def test_registering_one_router_exposes_only_that_routers_routes() -> None:
    app = build_platform_app(title="one", version="test")
    app.include_router(v1.members_router)
    assert all(
        key.split(" ")[1].startswith("/v1/tenants/{tenant_id}/members")
        for key in (_capability_routes(app))
    )
    assert len(_capability_routes(app)) == 4


# --- Every route: exactly the approved surface, each behind one permission ---------------


def test_the_served_surface_is_exactly_the_approved_one() -> None:
    assert set(_capability_routes(_app_with_every_capability())) == set(_EXPECTED)


def test_every_capability_route_is_gated_by_its_one_expected_permission() -> None:
    policies = assert_route_policies(_app_with_every_capability(), production=False)
    for key, permission in _EXPECTED.items():
        policy = policies[key]
        assert policy.kind is RoutePolicyKind.PERMISSION, key
        assert policy.detail == permission, key


def test_no_capability_route_is_public_or_merely_authenticated() -> None:
    policies = assert_route_policies(_app_with_every_capability(), production=False)
    kinds = {policies[key].kind for key in _EXPECTED}
    assert kinds == {RoutePolicyKind.PERMISSION}


def test_every_gating_permission_is_registered_by_register_capability_permissions() -> None:
    registered = {f"{resource}:{action}" for resource, action in CAPABILITY_PERMISSIONS}
    assert set(_EXPECTED.values()) <= registered


def test_membership_invitation_and_api_key_routes_use_authority_resources() -> None:
    """So a support-access session can never satisfy them, whatever the
    action (`saas_os.core.rbac.authorization`)."""
    for key, permission in _EXPECTED.items():
        resource = permission.split(":")[0]
        if any(part in key for part in ("/members", "/invitations", "/api-keys")):
            assert resource in AUTHORITY_RESOURCES, key


# --- Handlers take the tenant from the verified context, never from the path -------------


def _handlers(module_name: str) -> list[ast.FunctionDef]:
    tree = ast.parse((_V1_DIR / f"{module_name}.py").read_text(encoding="utf-8"))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name)
            and d.func.value.id == "router"
            for d in node.decorator_list
        )
    ]


@pytest.mark.parametrize("module_name", _ROUTER_MODULES)
def test_no_handler_accepts_the_path_tenant_id(module_name: str) -> None:
    handlers = _handlers(module_name)
    assert handlers
    for handler in handlers:
        names = {a.arg for a in handler.args.args + handler.args.kwonlyargs}
        assert "tenant_id" not in names, f"{module_name}.{handler.name}"
        assert "context" in names, f"{module_name}.{handler.name}"


@pytest.mark.parametrize("module_name", (*_ROUTER_MODULES, "_common", "permissions"))
def test_routers_decide_nothing_themselves(module_name: str) -> None:
    """No database access and no direct policy evaluation in a router: the
    decision is `require_permission` at the edge and Core inside."""
    tree = ast.parse((_V1_DIR / f"{module_name}.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported |= {f"{node.module}.{alias.name}" for alias in node.names}
        elif isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
    assert not [name for name in imported if name.split(".")[0] in {"sqlalchemy", "psycopg"}]
    assert not [name for name in imported if name.startswith("saas_os.infra.db")]
    assert "saas_os.core.rbac.can" not in imported
    assert "saas_os.core.rbac.authorization.can" not in imported
    assert not [name for name in imported if name.startswith("saas_os.control_plane")]


# --- Responses: explicit models, and secrets only where they are issued -------------------

_NEVER = {"token_hash", "key_hash", "provider_subscription_id", "provider_customer_ref"}


def _response_models() -> dict[str, type[BaseModel]]:
    models: dict[str, type[BaseModel]] = {}
    for module in (members, invitations, api_keys, billing, usage):
        for name, value in vars(module).items():
            if isinstance(value, type) and issubclass(value, BaseModel) and value is not BaseModel:
                if name.endswith("Response"):
                    models[f"{module.__name__}.{name}"] = value
    return models


def test_no_response_model_carries_a_stored_hash_or_a_provider_reference() -> None:
    models = _response_models()
    assert len(models) >= 12
    for name, model in models.items():
        assert not set(model.model_fields) & _NEVER, name


def test_a_plaintext_secret_exists_only_in_the_two_issuing_responses() -> None:
    models = _response_models()
    with_token = {n.rsplit(".", 1)[1] for n, m in models.items() if "token" in m.model_fields}
    # `key` is also a plan's catalog key (`PlanResponse.key`); the API key
    # itself can only appear in the API-key module.
    with_api_key = {
        n.rsplit(".", 1)[1]
        for n, m in models.items()
        if "key" in m.model_fields and n.startswith(api_keys.__name__)
    }
    assert with_token == {"CreatedInvitationResponse"}
    assert with_api_key == {"IssuedApiKeyResponse"}


def test_every_route_declares_a_typed_response_model_or_no_body() -> None:
    for key, (route, _) in _capability_routes(_app_with_every_capability()).items():
        if key.startswith("DELETE "):
            assert route.status_code == 204, key
        else:
            assert route.response_model is not None, key


def test_list_routes_are_bounded() -> None:
    from saas_os.api.v1._common import MAX_PAGE_SIZE

    assert MAX_PAGE_SIZE <= 500
    listed = 0
    for key, (_, dependant) in _capability_routes(_app_with_every_capability()).items():
        if key.startswith("GET ") and not key.endswith(("}", "/entitlements", "/usage")):
            params = {p.name for p in dependant.query_params}  # type: ignore[attr-defined]
            assert {"limit", "offset"} <= params, key
            listed += 1
    assert listed == 5


# --- The guide's registration example names what actually exists --------------------------


def test_the_consumer_guide_names_only_real_routers() -> None:
    import re

    guide = (Path(__file__).resolve().parents[3] / "docs" / "CONSUMER-GUIDE.md").read_text(
        encoding="utf-8"
    )
    block = re.search(r"from saas_os\.api\.v1 import \((?P<names>[^)]*)\)", guide)
    assert block is not None
    names = {n.strip() for n in block["names"].split(",") if n.strip()}
    assert names == {
        "api_keys_router",
        "build_billing_router",
        "invitation_acceptance_router",
        "invitations_router",
        "members_router",
        "usage_router",
    }
    assert names <= set(v1.__all__)
    for path in re.findall(r"# (/v1/tenants/\{tenant_id\}/[a-z-]+)", guide):
        assert any(key.split(" ")[1].startswith(path) for key in _EXPECTED), path
