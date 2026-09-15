"""The reference consumer's one project-specific API route (ADR-0018).

Secured through SaaS OS's own ingress chain (PRIV-03 P12, privacy
re-audit RA-08): `api.dependencies.require_permission()` composes
authentication (session bearer/cookie) -> tenant resolution (the tenant
must exist, admit tenant principals -- ACTIVE/PENDING, never SUSPENDED/
DELETED/PURGING/PURGED -- and the caller must be a member; otherwise the
identical non-enumerating 404) -> per-tenant rate limiting -> RBAC
(`core.rbac.can()` for `reference_consumer.widgets:read`, denials audited
as `api.access_denied`). This is the same contract SaaS OS's own
`api/v1/tenant_status.py` route uses -- a consumer route is in exactly
the same position and gets exactly the same chain, not a weaker one.

The `tenant_id` in the URL is only ever *input* to that chain. The
handler never reads it: the tenant it queries is the verified
`RequestContext.tenant_id`, so no caller can choose a tenant context by
editing the path. Row-Level Security (`reference_consumer/migrations/`)
still scopes the read underneath, and `get_widget()` adds an explicit
ownership check; a foreign or nonexistent widget is the same 404.
"""

from __future__ import annotations

import uuid

from api.context import RequestContext
from api.dependencies import require_permission
from api.errors import not_found
from fastapi import APIRouter, Depends

from reference_consumer.tools import ACTION, RESOURCE
from reference_consumer.widgets import get_widget

router = APIRouter(prefix="/widgets", tags=["reference-consumer"])

# Built once at module scope -- the dependency is a closure over the
# fixed (resource, action) pair, exactly like `api/v1/tenant_status.py`.
_read_widget = require_permission(RESOURCE, ACTION)


@router.get("/{tenant_id}/{widget_id}")
def get_widget_status(
    widget_id: uuid.UUID,
    context: RequestContext = Depends(_read_widget),  # noqa: B008 -- FastAPI's own dependency idiom
) -> dict[str, object]:
    widget = get_widget(context.tenant_id, widget_id)
    if widget is None:
        raise not_found("widget")
    return {"id": str(widget.id), "name": widget.name, "status": widget.status}
