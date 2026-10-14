"""Foundation Authority & Evidence -- the static half of the contract
(`saas_os/core/authority`; docs/ADR/0031-foundation-authority-and-evidence.md).

- Every authority-changing Core operation takes a required, keyword-only
  `caller` -- no default, no legacy actor-id parameter beside it.
- None of them writes its audit entry with the separate-transaction
  `core.audit_log.record()`: evidence goes through
  `record_in_transaction()`, inside the mutation's own transaction.
- `saas_os.core.authority` is pure data: it imports nothing but the standard
  library, so authority can never be resolved from web or ambient state.
- Platform authority (`SystemCaller`) is constructed by shipped code in
  exactly the reviewed places.
- Support access can never satisfy an authority resource.
"""

from __future__ import annotations

import ast
import inspect
import uuid
from pathlib import Path

import pytest

from saas_os.core.api_keys import service as api_keys_service
from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
    require_caller,
)
from saas_os.core.identity import service as identity_service
from saas_os.core.rbac import service as rbac_service
from saas_os.core.rbac.authorization import (
    _SUPPORT_ACCESS_EXCLUDED_ACTIONS,
    _SUPPORT_ACCESS_EXCLUDED_RESOURCES,
    AUTHORITY_RESOURCES,
    BILLING_MUTATION_ACTIONS,
    TENANT_SELF_SUSPEND_ACTION,
)
from saas_os.core.webhooks import service as webhooks_service

_REPO = Path(__file__).resolve().parents[2]

AUTHORITY_OPERATIONS: dict[object, tuple[str, ...]] = {
    rbac_service: (
        "create_role",
        "delete_role",
        "grant_permission",
        "revoke_permission",
        "assign_role",
        "assign_first_role_for_new_tenant",
        "remove_role",
        "assign_service_account_role",
        "remove_service_account_role",
        "create_delegation",
        "create_delegation_to_service_account",
        "revoke_delegation",
        "create_deny",
        "create_deny_for_service_account",
        "revoke_deny",
        "create_support_access_request",
        "approve_support_access",
        "deny_support_access",
        "revoke_support_access",
        "revoke_tenant_support_access",
    ),
    identity_service: (
        "add_tenant_membership",
        "create_service_account",
        "disable_service_account",
        "enable_service_account",
        "suspend_membership",
        "reactivate_membership",
        "revoke_membership",
        "create_invitation",
        "revoke_invitation",
        "accept_invitation",
    ),
    api_keys_service: (
        "create_api_key",
        "create_service_account_api_key",
        "revoke_api_key",
        "revoke_service_account_api_key",
        "rotate_api_key",
    ),
    # RE-4: a webhook subscription is a standing outbound data channel.
    webhooks_service: ("subscribe", "unsubscribe"),
}
_LEGACY_ACTOR_PARAMETERS = {
    "actor_user_id",
    "delegator_user_id",
    "grantor_user_id",
    "revoker_user_id",
    "requester_user_id",
    "approver_user_id",
    "inviter_user_id",
    "accepting_user_id",
}
_OPERATIONS = [(module, name) for module, names in AUTHORITY_OPERATIONS.items() for name in names]


@pytest.mark.parametrize(("module", "name"), _OPERATIONS, ids=[name for _, name in _OPERATIONS])
def test_every_authority_operation_requires_an_explicit_keyword_only_caller(
    module: object, name: str
) -> None:
    signature = inspect.signature(getattr(module, name))
    caller = signature.parameters.get("caller")
    assert caller is not None, f"{name} has no caller parameter"
    assert caller.kind is inspect.Parameter.KEYWORD_ONLY, name
    assert caller.default is inspect.Parameter.empty, f"{name}'s caller has a default"
    assert not set(signature.parameters) & _LEGACY_ACTOR_PARAMETERS, name


def _function_source(module: object, name: str) -> ast.FunctionDef:
    tree = ast.parse(Path(inspect.getsourcefile(module)).read_text(encoding="utf-8"))  # type: ignore[arg-type]
    return next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _called_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for call in ast.walk(node):
        if isinstance(call, ast.Call):
            func = call.func
            names.add(func.id if isinstance(func, ast.Name) else getattr(func, "attr", ""))
    return names


@pytest.mark.parametrize(("module", "name"), _OPERATIONS, ids=[name for _, name in _OPERATIONS])
def test_no_authority_operation_audits_in_a_separate_transaction(module: object, name: str) -> None:
    """`record_audit_event` is `saas_os.core.audit_log.record()`: its own
    transaction, committed independently of the mutation."""
    assert "record_audit_event" not in _called_names(_function_source(module, name))


def test_core_authority_imports_only_the_standard_library() -> None:
    for path in (_REPO / "saas_os" / "core" / "authority").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module in {"__future__", "enum", "uuid", "dataclasses"} or (
                    node.module.startswith("saas_os.core.authority")
                ), (path.name, node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name in {"enum", "uuid"}, (path.name, alias.name)


_SYSTEM_CALLER_SITES = {
    Path("saas_os/api/tenant_bootstrap.py"),
    # ADR-0045: the platform owner bootstrap and recovery command constructs
    # `SystemCaller(SystemAuthority.PLATFORM_BOOTSTRAP)`, once, and nothing else.
    Path("saas_os/api/platform_bootstrap.py"),
    Path("saas_os/core/tenancy/service.py"),
    # Phase 5.3 step 1: the deprecated `trusted_system(reason)` compatibility
    # marker is mapped onto `SystemCaller(SystemAuthority.BILLING_OPERATIONS)`
    # -- the one purpose billing entry points accept -- and nothing else.
    Path("saas_os/core/billing/authorization.py"),
}


def test_system_authority_is_constructed_only_in_reviewed_places() -> None:
    """Shipped code (API, Core, Infra, Control Plane, products) may name
    platform authority only in the first-tenant bootstrap command, the
    tenant purge and the billing compatibility shim. A consumer's own
    provisioning code is its own decision."""
    found: set[Path] = set()
    for top in ("saas_os", "products"):
        for path in (_REPO / top).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "SystemCaller":
                    found.add(path.relative_to(_REPO))
    assert found == _SYSTEM_CALLER_SITES


# ADR-0031 amendment (2026-10-12) / ADR-0045 section 5a: the guard above
# matches only a bare-name `SystemCaller(...)` call. An aliased import, an
# attribute access or the deprecated `trusted_system()` helper would slip
# past it. This one matches the *import* instead, under any alias, and pins
# the set of importing modules.
#
# Static evidence about this repository's own source, and nothing more: it
# authenticates no `SystemCaller` at run time, and a consuming product's
# code is not scanned.
_SYSTEM_AUTHORITY_NAMES = {"SystemCaller", "SystemAuthority", "trusted_system"}

_SYSTEM_AUTHORITY_IMPORTERS = {
    # The type's own package.
    "saas_os/core/authority/__init__.py",
    # The two operator commands (not routers).
    "saas_os/api/tenant_bootstrap.py",
    "saas_os/api/platform_bootstrap.py",
    # Core functions that accept a named system purpose, or record one.
    "saas_os/core/audit_log/service.py",
    "saas_os/core/identity/service.py",
    "saas_os/core/rbac/service.py",
    "saas_os/core/tenancy/service.py",
    "saas_os/core/webhooks/service.py",
    "saas_os/core/billing/__init__.py",
    "saas_os/core/billing/authorization.py",
    "saas_os/core/billing/catalog.py",
    # ADR-0045: the declared operation table, the chokepoint, platform audit
    # actor derivation, the shared authority transaction, and the bootstrap
    # and recovery composite (which accepts PLATFORM_BOOTSTRAP only).
    "saas_os/core/platform_authority/operations.py",
    "saas_os/core/platform_authority/authorization.py",
    "saas_os/core/platform_authority/audit.py",
    "saas_os/core/platform_authority/service.py",
    "saas_os/core/platform_authority/bootstrap.py",
    # ADR-0045, amendment of 2026-10-14: the platform mutation transaction
    # exempts a system purpose from the statement timeout (a type check only).
    "saas_os/core/platform_authority/transactions.py",
}

_COMMAND_MODULES = {"saas_os/api/tenant_bootstrap.py", "saas_os/api/platform_bootstrap.py"}


def _system_authority_importers() -> set[str]:
    found: set[str] = set()
    for top in ("saas_os", "products"):
        for path in (_REPO / top).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and any(
                    alias.name in _SYSTEM_AUTHORITY_NAMES for alias in node.names
                ):
                    found.add(path.relative_to(_REPO).as_posix())
    return found


def test_system_authority_is_imported_only_by_reviewed_modules() -> None:
    assert _system_authority_importers() == _SYSTEM_AUTHORITY_IMPORTERS


def test_no_http_module_can_name_a_system_purpose() -> None:
    """Under `saas_os/api`, only the two operator commands import
    `SystemCaller` or `SystemAuthority`. No router, dependency or request
    model does, so no request input can be turned into a purpose there --
    and no module imports either command."""
    api_importers = {
        path for path in _system_authority_importers() if path.startswith("saas_os/api/")
    }
    assert api_importers == _COMMAND_MODULES
    for path in (_REPO / "saas_os").rglob("*.py"):
        relative = path.relative_to(_REPO).as_posix()
        if "__pycache__" in path.parts or relative in _COMMAND_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported = {node.module or "", *(alias.name for alias in node.names)}
            elif isinstance(node, ast.Import):
                imported = {alias.name for alias in node.names}
            else:
                continue
            assert not any(
                name.endswith(("tenant_bootstrap", "platform_bootstrap")) for name in imported
            ), relative


def test_system_authority_is_never_reached_by_attribute_or_alias() -> None:
    """No `authority.SystemCaller(...)`-style access and no `import ... as`
    rename of these names: either would hide a construction site from the
    bare-name guard above."""
    offenders = []
    for top in ("saas_os", "products"):
        for path in (_REPO / top).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name in _SYSTEM_AUTHORITY_NAMES and alias.asname:
                            offenders.append((path.relative_to(_REPO).as_posix(), alias.asname))
                elif (
                    isinstance(node, ast.Attribute)
                    and node.attr in ("SystemCaller", "trusted_system")
                    and not isinstance(node.ctx, ast.Store)
                ):
                    offenders.append((path.relative_to(_REPO).as_posix(), node.attr))
    assert offenders == []


def test_platform_bootstrap_purpose_is_accepted_by_no_tenant_side_function() -> None:
    """`PLATFORM_BOOTSTRAP` is named only by the platform-authority package
    and its command. No tenant RBAC, identity, tenancy, billing or webhook
    function lists it among the purposes it accepts."""
    naming = []
    for path in (_REPO / "saas_os").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if "PLATFORM_BOOTSTRAP" in path.read_text(encoding="utf-8"):
            naming.append(path.relative_to(_REPO).as_posix())
    assert sorted(naming) == [
        "saas_os/api/platform_bootstrap.py",
        "saas_os/core/authority/caller.py",
        "saas_os/core/platform_authority/bootstrap.py",
        "saas_os/core/platform_authority/operations.py",
    ]


def test_support_access_can_never_satisfy_an_authority_resource() -> None:
    assert _SUPPORT_ACCESS_EXCLUDED_RESOURCES == AUTHORITY_RESOURCES
    assert {
        "role",
        "role_permission",
        "membership",
        "membership_role",
        "invitation",
        "service_account",
        "service_account_role",
        "api_key",
        "delegation_grant",
        "deny_grant",
        "support_access_request",
        "webhook_subscription",
    } == AUTHORITY_RESOURCES


def test_support_access_can_never_satisfy_a_billing_mutation() -> None:
    """ADR-0031 amendment (2026-10-02): excluded by (resource, action), so
    billing reads stay ordinarily authorized."""
    # ADR-0045 section 12: tenant self-service suspension joins the
    # action-level exclusions; every other excluded action is a
    # billing mutation.
    assert _SUPPORT_ACCESS_EXCLUDED_ACTIONS == BILLING_MUTATION_ACTIONS | {
        TENANT_SELF_SUSPEND_ACTION
    }
    assert {
        ("billing.subscription", "create"),
        ("billing.subscription", "change"),
        ("billing.subscription", "cancel"),
        ("billing.subscription", "reactivate"),
        ("billing.account", "charge"),
        ("billing.account", "manage"),
        ("billing.catalog", "manage"),
        ("billing.merchant", "manage"),
    } == BILLING_MUTATION_ACTIONS


# --- The caller types themselves ------------------------------------------------------


def test_caller_types_refuse_untyped_identities() -> None:
    with pytest.raises(TypeError):
        UserCaller("not-a-uuid")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ServiceAccountCaller(uuid.uuid4(), "tenant")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SystemCaller("provisioning")  # type: ignore[arg-type]


@pytest.mark.parametrize("caller", [None, "user", uuid.uuid4(), True, {"user_id": uuid.uuid4()}])
def test_require_caller_rejects_anything_that_is_not_a_typed_caller(caller: object) -> None:
    with pytest.raises(CallerTypeError):
        require_caller("op", caller)


def test_require_caller_enforces_the_accepted_types() -> None:
    require_caller("op", UserCaller(uuid.uuid4()), (UserCaller,))
    with pytest.raises(CallerTypeError):
        require_caller("op", SystemCaller(SystemAuthority.PROVISIONING), (UserCaller,))


def test_require_caller_rejects_subclasses() -> None:
    class _Spoof(UserCaller):
        pass

    with pytest.raises(CallerTypeError):
        require_caller("op", _Spoof(uuid.uuid4()))
