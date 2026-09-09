"""The first external API route (docs/IMPLEMENTATION-ROADMAP.md Phase
8.2's own Objective: "expose a minimal, low-risk external route (e.g.,
authenticated tenant status) at `/v1/...` to validate the full request
path end-to-end").

`GET /v1/tenants/{tenant_id}/status` -- deliberately the exact route
shape the roadmap's own Objective names as an example. Read-only, no
state mutation (this phase's own Rollback Strategy: "this route carries
no state-mutation risk").

`TenantStatusResponse` is a typed Pydantic model, never
`core.tenancy.Tenant` (the ORM entity) returned directly -- this
checkpoint's own Step 12: "avoid leaking internal ORM models directly".
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.context import RequestContext
from api.dependencies import require_permission
from core.tenancy import get_tenant

RESOURCE = "tenant"
ACTION = "read_status"

router = APIRouter(prefix="/v1/tenants", tags=["tenant-status"])


class TenantStatusResponse(BaseModel):
    id: uuid.UUID
    name: str
    status: str


@router.get("/{tenant_id}/status", response_model=TenantStatusResponse)
async def get_tenant_status(
    tenant_id: uuid.UUID,
    context: RequestContext = Depends(require_permission(RESOURCE, ACTION)),
) -> TenantStatusResponse:
    tenant = get_tenant(context.tenant_id)
    return TenantStatusResponse(id=tenant.id, name=tenant.name, status=tenant.status)
