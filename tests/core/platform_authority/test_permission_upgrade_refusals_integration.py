"""ADR 0060: `SystemAuthority.PERMISSION_UPGRADE` is accepted by
`grant_registered_permission_to_role` alone. Every other authority-changing
Core operation (the reviewed list of `tests/architecture/
test_authority_contract.py::AUTHORITY_OPERATIONS`) refuses it, before any
write: each is called with real ids of a real open tenant, so a refusal
cannot be a lookup failure in disguise. PostgreSQL."""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from phase_c_helpers import PROVISIONING, Scene

from saas_os.core.api_keys import service as api_keys_service
from saas_os.core.authority import CallerTypeError, SystemAuthority, SystemCaller
from saas_os.core.identity import service as identity_service
from saas_os.core.rbac import (
    RoleScope,
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.rbac import service as rbac_service
from saas_os.core.webhooks import service as webhooks_service

pytestmark = pytest.mark.integration

UPGRADE = SystemCaller(SystemAuthority.PERMISSION_UPGRADE)

# The reviewed authority operations, as in the architecture contract, less
# the one function that accepts the purpose.
OPERATIONS: dict[Any, tuple[str, ...]] = {
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
    webhooks_service: ("subscribe", "unsubscribe"),
}
_CASES = [(module, name) for module, names in OPERATIONS.items() for name in names]


def _is_refusal(error: BaseException) -> bool:
    return isinstance(error, CallerTypeError) or type(error).__name__.endswith("NotAuthorizedError")


@pytest.mark.parametrize(("module", "name"), _CASES, ids=[name for _, name in _CASES])
def test_every_other_authority_operation_refuses_the_permission_upgrade_purpose(
    scene: Scene, module: Any, name: str
) -> None:
    tenant = scene.tenant(active=True)
    member, membership = scene.member(tenant)
    other_user, _ = scene.member(tenant)
    role = create_role(tenant, f"r-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
    permission = register_permission("grt_upgrade_probe", "read")
    grant_permission(tenant, role.id, permission.id, caller=PROVISIONING)
    assign_first_role_for_new_tenant(tenant, membership, role.id, caller=PROVISIONING)
    service_account = identity_service.create_service_account(
        tenant, f"sa-{uuid.uuid4().hex[:8]}", caller=PROVISIONING
    )
    soon = datetime.now(UTC) + timedelta(hours=1)
    values: dict[str, Any] = {
        "tenant_id": tenant,
        "name": f"n-{uuid.uuid4().hex[:8]}",
        "role_id": role.id,
        "permission_id": permission.id,
        "membership_id": membership,
        "user_id": other_user,
        "delegate_user_id": other_user,
        "principal_user_id": other_user,
        "service_account_id": service_account.id,
        "service_account_tenant_id": tenant,
        "scope_mode": RoleScope.SELF,
        "reason": "probe",
        "requested_expires_at": soon,
        "invited_email": "probe@example.com",
        "raw_token": "probe-token",  # pragma: allowlist secret -- not a credential
        "url": "https://hooks.example.com/probe",
        # Ids of rows that do not exist: a function must refuse the caller
        # before it looks for them.
        "delegation_grant_id": uuid.uuid4(),
        "deny_grant_id": uuid.uuid4(),
        "request_id": uuid.uuid4(),
        "invitation_id": uuid.uuid4(),
        # A real key: revocation and rotation find the key first, then
        # refuse a caller that may not change it.
        "key_id": scene.api_key(tenant, member)[0] if "api_key" in name else uuid.uuid4(),
        "subscription_id": uuid.uuid4(),
    }
    function: Callable[..., Any] = getattr(module, name)
    parameters = inspect.signature(function).parameters
    positional = [
        values[p.name]
        for p in parameters.values()
        if p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD and p.default is p.empty
    ]
    keywords = {
        p.name: values[p.name]
        for p in parameters.values()
        if p.kind is inspect.Parameter.KEYWORD_ONLY and p.default is p.empty and p.name != "caller"
    }
    audit = scene.platform.scalar(
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t", {"t": tenant}
    )

    with pytest.raises(Exception) as raised:  # noqa: PT011 -- classified below
        function(*positional, caller=UPGRADE, **keywords)

    assert _is_refusal(raised.value), (name, type(raised.value).__name__, raised.value)
    assert (
        scene.platform.scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t", {"t": tenant}
        )
        == audit
    )
