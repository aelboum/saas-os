"""Delegation/deny/role-assignment principal type (architecture research:
universal multi-tenant tenancy, Phase C -- "Do NOT create a physical
unified Principal table... use the architecture convention...
principal_type / principal_id, with supported types limited to the
identities that actually exist today"; Phase E -- "Principal +
Service Accounts + API Key Hardening").

`DelegationGrant`/`DenyGrant` (`saas_os/core/rbac/models.py`) name their
principals as `(principal_type, principal_id)` pairs rather than a bare
`user_id`, so the schema is not hard-wired to "a principal is always a
`saas_os.core.identity` User" -- this phase supports exactly the three kinds that
have a grounded meaning elsewhere in this codebase, mirroring
`saas_os/core/audit_log/models.py::ActorType`'s own "Do NOT add actor types
merely speculatively" discipline exactly:

    USER             -- a `saas_os.core.identity` User. The kind
                        `saas_os/core/rbac/service.py::create_delegation()`/
                        `create_deny()` construct.
    SYSTEM           -- reserved for a platform-internal actor with no
                        associated User row, matching `ActorType.SYSTEM`'s
                        own meaning. No code path in this phase
                        constructs a SYSTEM-principal delegation/deny --
                        the value exists so the schema does not need a
                        breaking change if a legitimate system-principal
                        need is identified later, not because one exists
                        now.
    SERVICE_ACCOUNT  -- a `saas_os.core.identity.ServiceAccount`: a tenant-scoped
                        machine identity (architecture research Phase E).
                        Participates as an actor in `saas_os/core/rbac/authorization.py
                        ::can()` and as a delegate/deny-target in
                        `DelegationGrant`/`DenyGrant`, exactly like a USER
                        principal -- never a second, parallel
                        authorization mechanism. A service account is
                        NOT a `saas_os.core.identity.User`: it is never inserted
                        into `core.users`, and it never receives an
                        ordinary `TenantMembership` (`saas_os/core/identity/models.py
                        ::ServiceAccount`'s own docstring).

Explicitly NOT added here (still out of scope, architecture research):
PLATFORM_OPERATOR, AGENT, BOT, ORGANIZATION, WORKSPACE, or any other
speculative kind. Existing USER/SYSTEM rows and code paths are entirely
unaffected by this addition -- `SERVICE_ACCOUNT` is a new, additive enum
member, never a replacement for the two that already existed.
"""

from __future__ import annotations

import enum


class PrincipalType(enum.StrEnum):
    USER = "user"
    SYSTEM = "system"
    SERVICE_ACCOUNT = "service_account"
