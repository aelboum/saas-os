"""Membership-role authorization scope (architecture research: universal
multi-tenant tenancy, Phase B -- "RBAC + role scope: self, subtree").

A `MembershipRole` (`core/rbac/models.py`) declares which of a tenant's
descendants, if any, its assignment reaches -- structural hierarchy
(`Tenant.parent_id`/`core.tenant_ancestry`, Phase A) grants no
authorization by itself; a role assignment must explicitly opt into
reaching beyond its own membership's tenant.

    SELF    -- the assignment authorizes only the membership's own tenant.
               The default, and the only value any assignment could ever
               have meant before this phase existed.
    SUBTREE -- the assignment additionally authorizes every *current*
               descendant of the membership's tenant, per the live
               `core.tenant_ancestry` closure table (`core/rbac/authorization.py
               ::can()`) -- never a snapshot taken at assignment time. If a
               descendant is later moved out of the subtree (or a new one
               moved in), the assignment's reach changes automatically,
               with no rewrite of the assignment row itself
               (`core/tenancy/service.py::move_tenant()`'s own docstring:
               hierarchy moves never rewrite unrelated data).

Mirrors `core/tenancy/lifecycle.py`'s `TenantStatus` shape exactly: a
plain `enum.StrEnum`, stored as its `.value` in a `String` column
(`core/rbac/models.py`), with a database-level `CHECK` constraint
restricting the column to exactly these values
(`infra/db/migrations/versions/`, this phase's migration) -- so an
invalid scope is rejected by PostgreSQL itself, not merely by this
module's own type system.
"""

from __future__ import annotations

import enum


class RoleScope(enum.StrEnum):
    SELF = "self"
    SUBTREE = "subtree"
