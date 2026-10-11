"""This product's HTTP routes.

Every route declares exactly one route policy, or the application refuses
to start (`saas_os.api.route_policy.assert_route_policies`, ADR-0030).
`require_permission()` is the policy for tenant data. It runs SaaS OS's
whole ingress chain, in order: authentication, tenant resolution (the
tenant must exist and admit principals, and the caller must be a member
-- otherwise one identical 404), per-tenant rate limiting, then
`saas_os.core.rbac.can()` for the declared permission, with denials audited.

The `tenant_id` in the path is only an input to that chain. The handler
reads the tenant from the verified `RequestContext`, never from the path.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends

from my_product.items import get_item
from my_product.permissions import ITEMS_RESOURCE, READ
from saas_os.api.context import RequestContext
from saas_os.api.dependencies import require_permission
from saas_os.api.errors import not_found

router = APIRouter(prefix="/v1/tenants/{tenant_id}/items", tags=["items"])

_read_item = require_permission(ITEMS_RESOURCE, READ)


@router.get("/{item_id}")
def read_item(
    item_id: uuid.UUID,
    context: RequestContext = Depends(_read_item),  # noqa: B008 -- FastAPI's own dependency idiom
) -> dict[str, object]:
    item = get_item(context.tenant_id, item_id)
    if item is None:
        raise not_found("item")
    return {"id": str(item.id), "name": item.name, "status": item.status}
