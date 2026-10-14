"""The verified identity context every downstream route handler receives
(docs/SECURITY.md section 2: "Session/token verification happens once,
at the API/Infra ingress layer ... producing that verified identity
context for all downstream code").

`RequestContext` is deliberately minimal: `actor_id` (the authenticated
`saas_os.core.identity.User`), `tenant_id` (the tenant this request has been
validated to act within -- a genuine `saas_os.core.identity.TenantMembership`
was confirmed to exist, `saas_os/api/dependencies.py`), and `membership_id` (the
specific membership row, in case a route needs it for a further
`saas_os.core.rbac` call). Route handlers trust this object completely -- it is
only ever constructed by `saas_os/api/dependencies.py`'s own ingress chain, never
by a route handler itself.

**API keys (ADR-0047).** On a route that accepts an API key
(`require_permission(..., api_key=True)`), the request may be a key's:
`api_key_id` names the key, and `principal` says whose it is. A user's key
gives the same context a session would, with `api_key_id` set. A service
account's key gives `principal=SERVICE_ACCOUNT`, `actor_id` = the service
account's id, and `membership_id=None` (a service account has no
membership). A route that does not accept keys only ever receives a user
with a membership.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass


class RequestPrincipal(enum.StrEnum):
    """Who `RequestContext.actor_id` is."""

    USER = "user"
    SERVICE_ACCOUNT = "service_account"


@dataclass(frozen=True)
class RequestContext:
    actor_id: uuid.UUID
    tenant_id: uuid.UUID
    membership_id: uuid.UUID | None
    principal: RequestPrincipal = RequestPrincipal.USER
    api_key_id: uuid.UUID | None = None
