"""A platform mutation cancelled by its statement timeout (ADR-0045,
amendment of 2026-10-14) is answered over HTTP as `503` with
`Retry-After`, like an oversight read's timeout: nothing was decided and
the request can be repeated. Hermetic."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import HTTPException

import saas_os.api.platform_admin.router as router_module
import saas_os.api.v1.tenant_suspension as suspension_module
from saas_os.api.context import RequestContext
from saas_os.core.platform_authority import PlatformOperationTimeoutError


def test_the_platform_router_answers_a_mutation_timeout_with_503() -> None:
    translated = router_module._translated(PlatformOperationTimeoutError("tenant.suspend", 300))
    assert translated is not None
    assert translated.status_code == 503
    assert translated.headers is not None and "Retry-After" in translated.headers
    # The operation and the limit are not disclosed.
    assert "tenant.suspend" not in str(translated.detail)
    assert "300" not in str(translated.detail)


def test_the_self_suspension_route_answers_a_transition_timeout_with_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def times_out(*args: Any, **kwargs: Any) -> Any:
        raise PlatformOperationTimeoutError("tenant.suspend", 300)

    monkeypatch.setattr(suspension_module, "transition_tenant_status", times_out)
    tenant_id = uuid.uuid4()
    context = RequestContext(actor_id=uuid.uuid4(), tenant_id=tenant_id, membership_id=uuid.uuid4())
    body = suspension_module.SuspendOwnTenantRequest(tenant_id=tenant_id, reason="incident")

    with pytest.raises(HTTPException) as raised:
        suspension_module.suspend_own_tenant(tenant_id, body, context)

    assert raised.value.status_code == 503
    assert raised.value.headers is not None and "Retry-After" in raised.value.headers
