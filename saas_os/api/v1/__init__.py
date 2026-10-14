"""`/v1` external API routes (docs/ADR/0006-api-style-and-versioning.md:
"versioned from the first released route using a URL path segment").

**Opt-in capability routers (docs/ADR/0040-...).** None of the routers
below is mounted by `saas_os.api.platform.build_platform_app()`. A route
exists in a product's application only if that product registers its
router:

    app = build_platform_app(title="My Product", version="1.0.0")
    app.include_router(members_router)
    app.include_router(invitations_router)
    app.include_router(api_keys_router)
    app.include_router(build_billing_router(provider=my_billing_provider))
    app.include_router(usage_router)

`register_capability_permissions()` (`saas_os/api/v1/permissions.py`)
registers the permissions these routes gate on, once per deployment.

`invitation_acceptance_router` (ADR-0046) is opt-in in the same way and
gates on no tenant permission: the invited person is not yet a member.
It is mounted next to `invitations_router` by a product that lets people
accept invitations over HTTP.

`tenant_suspension_router` (ADR-0045 section 12) is opt-in in the same
way and has its own permission, `tenant:suspend`, registered by
`register_tenant_suspension_permission()` and granted to no role by
default.
"""

from saas_os.api.v1.api_keys import router as api_keys_router
from saas_os.api.v1.billing import build_billing_router
from saas_os.api.v1.invitation_acceptance import router as invitation_acceptance_router
from saas_os.api.v1.invitations import router as invitations_router
from saas_os.api.v1.members import router as members_router
from saas_os.api.v1.permissions import CAPABILITY_PERMISSIONS, register_capability_permissions
from saas_os.api.v1.tenant_status import router as tenant_status_router
from saas_os.api.v1.tenant_suspension import (
    register_tenant_suspension_permission,
)
from saas_os.api.v1.tenant_suspension import router as tenant_suspension_router
from saas_os.api.v1.usage import router as usage_router

__all__ = [
    "CAPABILITY_PERMISSIONS",
    "api_keys_router",
    "build_billing_router",
    "invitation_acceptance_router",
    "invitations_router",
    "members_router",
    "register_capability_permissions",
    "tenant_status_router",
    "tenant_suspension_router",
    "register_tenant_suspension_permission",
    "usage_router",
]
