"""Opt-in tenant self-service suspension
(docs/ADR/0045-installation-scoped-platform-authority.md section 12).

`POST /v1/tenants/{tenant_id}/suspend` lets a tenant's own member, holding
the tenant permission `tenant:suspend` through an ordinary role of their
own membership, suspend that tenant. It is a tenant route under the
existing tenant chain (authentication, tenant resolution, rate limit,
RBAC), not a platform route, and not part of the platform-admin router.
A product mounts it explicitly:

    app.include_router(tenant_suspension_router)

**The route decides nothing.** `require_permission("tenant", "suspend")`
refuses earlier; `saas_os.core.tenancy.transition_tenant_status` applies
the rule. Core's rule is narrower than the chain's `can()`: a delegation,
a role inherited from an ancestor and a support-access grant satisfy
`can()` for some permissions and never satisfy this one, the designated
platform tenant cannot be self-suspended, and a descendant may not be left
without an administrator. Each of those is refused by Core, here as `403`
or `409`.

**Only the self-service rule.** The route asks Core for suspension under
that rule alone (`self_service=True`): a caller who also holds
`platform.tenant:suspend` gains nothing from it here, and the designated
platform tenant is refused for everyone.

**Safeguards (section 12).** A reason is required. The caller confirms by
giving the tenant id in the body as well as in the path; a mismatch is a
`400` and nothing is attempted. **Nobody inside a suspended tenant can
reactivate it**: once this succeeds, the tenant admits none of its own
principals, and only an operator holding `platform.tenant:reactivate` can
bring it back.

**Not granted by default.** No role receives `tenant:suspend`.
`register_tenant_suspension_permission()` puts the pair in the shared
catalog so that a tenant's roles can be granted it; it grants nothing.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from saas_os.api.context import RequestContext
from saas_os.api.dependencies import require_permission
from saas_os.api.errors import conflict, invalid_request, not_found
from saas_os.api.v1._common import PRINTABLE, TENANT_UNAVAILABLE, denied, user_caller
from saas_os.core.identity.errors import LastTenantAdministratorError
from saas_os.core.platform_authority import (
    InvalidPlatformRequestError,
    PlatformNotAuthorizedError,
)
from saas_os.core.rbac import register_permission
from saas_os.core.tenancy import (
    InvalidTenantTransitionError,
    TenantStatus,
    transition_tenant_status,
)

RESOURCE = "tenant"
ACTION = "suspend"

router = APIRouter(prefix="/v1/tenants", tags=["tenant-suspension"])


class SuspendOwnTenantRequest(BaseModel):
    """`tenant_id` repeats the path: the confirmation step."""

    tenant_id: uuid.UUID
    reason: Annotated[str, Field(min_length=1, max_length=500, pattern=PRINTABLE)]


class SuspendedTenantResponse(BaseModel):
    id: uuid.UUID
    status: str


def register_tenant_suspension_permission() -> None:
    """Idempotent. Registers `tenant:suspend` in the permission catalog.
    Grants nothing."""
    register_permission(RESOURCE, ACTION)


@router.post("/{tenant_id}/suspend", response_model=SuspendedTenantResponse)
def suspend_own_tenant(
    tenant_id: uuid.UUID,
    body: SuspendOwnTenantRequest,
    context: RequestContext = Depends(require_permission(RESOURCE, ACTION)),
) -> SuspendedTenantResponse:
    if body.tenant_id != context.tenant_id:
        raise invalid_request("The tenant id in the body must repeat the one in the path.")
    try:
        tenant = transition_tenant_status(
            context.tenant_id,
            TenantStatus.SUSPENDED,
            caller=user_caller(context),
            reason=body.reason,
            # The self-service rule alone: platform authority is not
            # consulted here, whatever the same person may hold. An
            # operator suspends a tenant through the platform route.
            self_service=True,
        )
    except PlatformNotAuthorizedError:
        # Core's rule is narrower than the chain's: not the tenant's own
        # role holder, or the designated platform tenant.
        raise denied() from None
    except InvalidPlatformRequestError:
        raise invalid_request("Invalid reason.") from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    except InvalidTenantTransitionError:
        raise conflict("tenant_not_active") from None
    except LastTenantAdministratorError:
        raise conflict("descendant_without_administrator") from None
    return SuspendedTenantResponse(id=tenant.id, status=tenant.status)
