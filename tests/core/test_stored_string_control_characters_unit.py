"""Core write functions refuse a control character in a caller's string
with their own invalid-input error, before any database read or write
(2026-10-29 sweep for NUL characters in stored strings). PostgreSQL cannot
hold a NUL in `text`; without these checks a product calling the library
directly got a raw `sqlalchemy.exc.DataError` instead. No database: each
check runs before the first query, so reaching the database would raise
something else and fail the test.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import cast

import pytest

from lifecycle_callers import PROVISIONING
from saas_os.core.audit_log import ActorType, AuditOutcome, InvalidActionOrResourceError
from saas_os.core.audit_log import record as record_audit_event
from saas_os.core.audit_log.service import (
    _validate_action_and_resource,  # pyright: ignore[reportPrivateUsage]
)
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.identity import (
    InvalidExternalIdentityError,
    InvalidServiceAccountNameError,
    create_service_account,
    find_external_identity,
    get_or_create_user_for_external_identity,
    link_external_identity,
)
from saas_os.core.platform_authority import InvalidPlatformRequestError
from saas_os.core.rbac import (
    InvalidPermissionNameError,
    InvalidRoleNameError,
    create_role,
    register_permission,
)
from saas_os.core.tenancy import create_tenant
from saas_os.core.usage import InvalidUsageEventError, ingest_event
from saas_os.core.usage.service import _validate_metric  # pyright: ignore[reportPrivateUsage]
from saas_os.core.webhooks import InvalidWebhookUrlError, subscribe
from saas_os.core.webhooks.service import _validate_url  # pyright: ignore[reportPrivateUsage]
from saas_os.infra.db import Session

_SYSTEM = SystemCaller(SystemAuthority.PROVISIONING)
_TENANT = uuid.uuid4()
# NUL is the one PostgreSQL refuses; the others are refused with it, the
# same rule as the API's `PRINTABLE` pattern.
_CONTROL = pytest.mark.parametrize("char", ["\x00", "\t", "\n", "\x1f", "\x7f"])


@_CONTROL
def test_create_tenant_refuses_a_control_character_in_the_name(char: str) -> None:
    with pytest.raises(InvalidPlatformRequestError, match="control characters"):
        create_tenant(f"acme{char}", caller=PROVISIONING)


@_CONTROL
def test_create_role_refuses_a_control_character_in_the_name(char: str) -> None:
    with pytest.raises(InvalidRoleNameError, match="control characters"):
        create_role(_TENANT, f"editor{char}", caller=_SYSTEM)


@_CONTROL
@pytest.mark.parametrize("which", ["resource", "action"])
def test_register_permission_refuses_a_control_character(char: str, which: str) -> None:
    resource, action = ("widget", "read")
    if which == "resource":
        resource += char
    else:
        action += char
    with pytest.raises(InvalidPermissionNameError, match="control characters"):
        register_permission(resource, action)
    with pytest.raises(InvalidPermissionNameError, match="control characters"):
        register_permission(resource, action, session=cast(Session, object()))


@_CONTROL
def test_create_service_account_refuses_a_control_character_in_the_name(char: str) -> None:
    with pytest.raises(InvalidServiceAccountNameError, match="control characters"):
        create_service_account(_TENANT, f"ci{char}", caller=_SYSTEM)


@_CONTROL
@pytest.mark.parametrize("which", ["issuer", "subject"])
def test_an_external_identity_with_a_control_character_is_refused(char: str, which: str) -> None:
    issuer, subject = ("https://idp.example.test", "subject-1")
    if which == "issuer":
        issuer += char
    else:
        subject += char
    for call in (
        lambda: find_external_identity(issuer, subject),
        lambda: link_external_identity(uuid.uuid4(), issuer, subject),
        lambda: get_or_create_user_for_external_identity(issuer, subject),
    ):
        with pytest.raises(InvalidExternalIdentityError, match="control characters"):
            call()


@_CONTROL
def test_subscribe_refuses_a_control_character_in_the_url(char: str) -> None:
    with pytest.raises(InvalidWebhookUrlError):
        subscribe(_TENANT, f"https://hooks.example.com/hook{char}", caller=_SYSTEM)


@_CONTROL
def test_ingest_event_refuses_a_control_character_in_the_metric(char: str) -> None:
    with pytest.raises(InvalidUsageEventError, match="control characters"):
        ingest_event(cast(Session, object()), _TENANT, f"api.calls{char}", Decimal(1))


@_CONTROL
@pytest.mark.parametrize("field", ["action", "resource_type", "resource_id", "correlation_id"])
def test_an_audit_record_with_a_control_character_is_refused(char: str, field: str) -> None:
    values = {
        "action": "widget.read",
        "resource_type": "widget",
        "resource_id": "w-1",
        "correlation_id": "req-1",
    }
    values[field] += char
    with pytest.raises(InvalidActionOrResourceError, match=f"{field} must not contain control"):
        record_audit_event(
            tenant_id=_TENANT,
            actor_type=ActorType.SYSTEM,
            outcome=AuditOutcome.SUCCESS,
            action=values["action"],
            resource_type=values["resource_type"],
            resource_id=values["resource_id"],
            correlation_id=values["correlation_id"],
        )


def test_printable_text_beyond_ascii_is_still_accepted() -> None:
    _validate_metric("api.calls.é名")
    _validate_url("https://hooks.example.com/hook/é")
    _validate_action_and_resource("widget.read", "widget", "w-é名 1")
