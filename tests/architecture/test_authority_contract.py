"""Foundation Authority & Evidence -- the static half of the contract
(`core/authority`; docs/ADR/0031-foundation-authority-and-evidence.md).

- Every authority-changing Core operation takes a required, keyword-only
  `caller` -- no default, no legacy actor-id parameter beside it.
- None of them writes its audit entry with the separate-transaction
  `core.audit_log.record()`: evidence goes through
  `record_in_transaction()`, inside the mutation's own transaction.
- `core.authority` is pure data: it imports nothing but the standard
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
from core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
    require_caller,
)
from core.rbac.authorization import _SUPPORT_ACCESS_EXCLUDED_RESOURCES, AUTHORITY_RESOURCES

from core.api_keys import service as api_keys_service
from core.identity import service as identity_service
from core.rbac import service as rbac_service

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
    """`record_audit_event` is `core.audit_log.record()`: its own
    transaction, committed independently of the mutation."""
    assert "record_audit_event" not in _called_names(_function_source(module, name))


def test_core_authority_imports_only_the_standard_library() -> None:
    for path in (_REPO / "core" / "authority").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module in {"__future__", "enum", "uuid", "dataclasses"} or (
                    node.module.startswith("core.authority")
                ), (path.name, node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name in {"enum", "uuid"}, (path.name, alias.name)


_SYSTEM_CALLER_SITES = {
    Path("api/tenant_bootstrap.py"),
    Path("core/tenancy/service.py"),
}


def test_system_authority_is_constructed_only_in_reviewed_places() -> None:
    """Shipped code (API, Core, Infra, Control Plane, products) may name
    platform authority only in the first-tenant bootstrap command and the
    tenant purge. A consumer's own provisioning code is its own decision."""
    found: set[Path] = set()
    for top in ("api", "core", "infra", "control-plane", "products"):
        for path in (_REPO / top).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "SystemCaller":
                    found.add(path.relative_to(_REPO))
    assert found == _SYSTEM_CALLER_SITES


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
    } == AUTHORITY_RESOURCES


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
