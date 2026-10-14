"""`user_caller()` and `request_caller()` (ADR-0047) -- hermetic. A
service account's API key is never turned into a user."""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from saas_os.api.context import RequestContext, RequestPrincipal
from saas_os.api.v1._common import request_caller, user_caller
from saas_os.core.authority import ServiceAccountCaller, UserCaller

_TENANT = uuid.uuid4()
_ACTOR = uuid.uuid4()


def _context(principal: RequestPrincipal) -> RequestContext:
    service_account = principal is RequestPrincipal.SERVICE_ACCOUNT
    return RequestContext(
        actor_id=_ACTOR,
        tenant_id=_TENANT,
        membership_id=None if service_account else uuid.uuid4(),
        principal=principal,
        api_key_id=uuid.uuid4(),
    )


def test_a_user_principal_is_a_user_caller_either_way() -> None:
    context = _context(RequestPrincipal.USER)
    assert user_caller(context) == UserCaller(_ACTOR)
    assert request_caller(context) == UserCaller(_ACTOR)


def test_a_service_account_principal_is_never_a_user_caller() -> None:
    context = _context(RequestPrincipal.SERVICE_ACCOUNT)
    with pytest.raises(HTTPException) as refused:
        user_caller(context)
    assert refused.value.status_code == 403
    assert request_caller(context) == ServiceAccountCaller(_ACTOR, _TENANT)


def test_a_context_without_a_principal_is_a_user_with_no_key() -> None:
    context = RequestContext(actor_id=_ACTOR, tenant_id=_TENANT, membership_id=uuid.uuid4())
    assert context.principal is RequestPrincipal.USER
    assert context.api_key_id is None
