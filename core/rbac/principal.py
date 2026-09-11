"""Delegation principal type (architecture research: universal
multi-tenant tenancy, Phase C -- "Do NOT create a physical unified
Principal table... use the architecture convention... principal_type /
principal_id, with supported types limited to the identities that
actually exist today").

`DelegationGrant` (`core/rbac/models.py`) names its delegator and delegate
as a `(principal_type, principal_id)` pair rather than a bare `user_id`,
so the schema is not hard-wired to "a delegation party is always a
`core.identity` User" -- but this phase deliberately supports only the
two kinds that already have a grounded meaning elsewhere in this
codebase, mirroring `core/audit_log/models.py::ActorType`'s own
"Do NOT add actor types merely speculatively" discipline exactly:

    USER   -- a `core.identity` User. The only kind
              `core/rbac/service.py::create_delegation()` actually
              constructs in this phase.
    SYSTEM -- reserved for a platform-internal actor with no associated
              User row, matching `ActorType.SYSTEM`'s own meaning. No
              code path in this phase constructs a SYSTEM-principal
              delegation -- the value exists so the schema does not need
              a breaking change if a legitimate system-delegation need is
              identified later, not because one exists now.

Explicitly NOT added here (later-phase concerns, architecture research):
SERVICE_ACCOUNT, PLATFORM_OPERATOR. Adding either now would be exactly
the "invent a platform operator/service account in this phase"
speculation the research warns against.
"""

from __future__ import annotations

import enum


class PrincipalType(enum.StrEnum):
    USER = "user"
    SYSTEM = "system"
