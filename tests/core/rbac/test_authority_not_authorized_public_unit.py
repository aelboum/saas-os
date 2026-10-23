"""Issue #97 -- `AuthorityNotAuthorizedError` is part of `saas_os.core.rbac`'s
public API, exported as the existing class with its existing contract, and
that contract still does not tell a caller *why* it was refused (ADR-0031:
a capability denial, a failed anti-amplification check, an inactive
principal and an unaccepted `SystemCaller` purpose are never
distinguished). No database needed.
"""

from __future__ import annotations

import importlib
import inspect
import uuid
from typing import cast

import pytest
from sqlalchemy.orm import Session

import saas_os.core.rbac as rbac
from saas_os.core.authority import ServiceAccountCaller, SystemAuthority, SystemCaller
from saas_os.core.rbac import errors as rbac_errors
from saas_os.core.rbac import service as rbac_service
from saas_os.core.rbac.scope import RoleScope

_TENANT = uuid.UUID("00000000-0000-0000-0000-000000000097")
_OPERATION = "assign_role"


def test_public_import_succeeds() -> None:
    from saas_os.core.rbac import AuthorityNotAuthorizedError  # noqa: F401


def test_listed_in_all() -> None:
    assert "AuthorityNotAuthorizedError" in rbac.__all__


def test_public_name_is_the_existing_class() -> None:
    assert rbac.AuthorityNotAuthorizedError is rbac_errors.AuthorityNotAuthorizedError


def test_existing_contract_is_unchanged() -> None:
    cls = rbac.AuthorityNotAuthorizedError
    assert cls.__bases__ == (PermissionError,)
    assert list(inspect.signature(cls.__init__).parameters) == ["self", "operation", "tenant_id"]
    exc = cls(_OPERATION, _TENANT)
    assert str(exc) == f"Caller is not authorized to {_OPERATION} in tenant {_TENANT}."


@pytest.mark.parametrize(
    "name",
    [
        "RoleAssignmentNotAuthorizedError",
        "ServiceAccountRoleNotAuthorizedError",
        "DelegationNotAuthorizedError",
        "DenyNotAuthorizedError",
        "SupportAccessNotAuthorizedError",
        "SupportAccessSelfApprovalError",
    ],
)
def test_existing_refusal_exports_are_unchanged(name: str) -> None:
    assert name in rbac.__all__
    assert getattr(rbac, name) is getattr(rbac_errors, name)


def test_public_attributes_are_only_operation_and_tenant_id() -> None:
    exc = rbac.AuthorityNotAuthorizedError(_OPERATION, _TENANT)
    assert vars(exc) == {"operation": _OPERATION, "tenant_id": _TENANT}


@pytest.mark.parametrize(
    "module",
    [
        "saas_os.core.rbac.service",
        "saas_os.core.api_keys.service",
        "saas_os.control_plane.inference.config.tenant_policy",
        "saas_os.api.v1.api_keys",
        "saas_os.api.v1.members",
        "saas_os.api.v1.invitation_acceptance",
        "saas_os.control_plane.inference.service",
    ],
)
def test_raise_and_catch_sites_use_the_public_class(module: str) -> None:
    assert importlib.import_module(module).AuthorityNotAuthorizedError is (
        rbac.AuthorityNotAuthorizedError
    )


def test_no_cause_specific_subclass_exists() -> None:
    """Every raise and catch site imported (the test above), and still no
    subclass: a refusal's type never names its cause."""
    for module in (
        "saas_os.core.rbac.service",
        "saas_os.core.api_keys.service",
        "saas_os.control_plane.inference.config.tenant_policy",
        "saas_os.api.v1.api_keys",
        "saas_os.api.v1.members",
        "saas_os.api.v1.invitation_acceptance",
        "saas_os.control_plane.inference.service",
    ):
        importlib.import_module(module)
    assert rbac.AuthorityNotAuthorizedError.__subclasses__() == []


def test_two_different_refusal_causes_are_indistinguishable() -> None:
    """An unaccepted `SystemCaller` purpose and a caller that can never pass
    the anti-amplification check are different causes; both reach the
    caller as the same type with the same attributes and message. Both
    refusals happen before the session is used."""
    session = cast(Session, object())

    with pytest.raises(rbac.AuthorityNotAuthorizedError) as unaccepted_purpose:
        rbac_service.authorize_caller(
            SystemCaller(SystemAuthority.BILLING_OPERATIONS),
            session=session,
            operation=_OPERATION,
            tenant_id=_TENANT,
            resource="roles",
            action="assign",
            system_authorities=frozenset({SystemAuthority.PROVISIONING}),
        )

    with pytest.raises(rbac.AuthorityNotAuthorizedError) as amplification:
        rbac_service._require_no_amplification(  # pyright: ignore[reportPrivateUsage]
            ServiceAccountCaller(service_account_id=uuid.uuid4(), tenant_id=_TENANT),
            session=session,
            operation=_OPERATION,
            tenant_id=_TENANT,
            permissions=[],
            scope=RoleScope.SELF,
        )

    first, second = unaccepted_purpose.value, amplification.value
    assert type(first) is type(second) is rbac.AuthorityNotAuthorizedError
    assert vars(first) == vars(second)
    assert first.args == second.args
    assert str(first) == str(second)
