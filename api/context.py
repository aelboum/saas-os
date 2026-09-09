"""The verified identity context every downstream route handler receives
(docs/SECURITY.md section 2: "Session/token verification happens once,
at the API/Infra ingress layer ... producing that verified identity
context for all downstream code").

`RequestContext` is deliberately minimal: `actor_id` (the authenticated
`core.identity.User`), `tenant_id` (the tenant this request has been
validated to act within -- a genuine `core.identity.TenantMembership`
was confirmed to exist, `api/dependencies.py`), and `membership_id` (the
specific membership row, in case a route needs it for a further
`core.rbac` call). Route handlers trust this object completely -- it is
only ever constructed by `api/dependencies.py`'s own ingress chain, never
by a route handler itself.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    actor_id: uuid.UUID
    tenant_id: uuid.UUID
    membership_id: uuid.UUID
