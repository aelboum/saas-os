"""FeatureFlag and FeatureFlagTenantOverride entities
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.2; docs/ARCHITECTURE.md section 4:
"core/feature-flags -- Flag definitions, targeting rules, evaluation").

Two isolation postures, mirroring `core/rbac`'s `Permission`/`RolePermission`
split (`core/rbac/models.py`):

    core.feature_flags                 -- GLOBAL, not RLS-scoped. A flag
                                           definition (its `key` and global
                                           `enabled_by_default`) is a
                                           platform capability declaration,
                                           not tenant-owned data -- the same
                                           reasoning `core.permissions`
                                           already established in Phase 3.3.
    core.feature_flag_tenant_overrides -- tenant-owned, RLS-protected.
                                           Whether a specific tenant's
                                           evaluation of a flag deviates
                                           from the global default -- the
                                           roadmap's own "targeted per
                                           tenant" Acceptance Criteria.

`flag_id` on the override table is a plain (non-composite) foreign key to
`core.feature_flags.id` -- unlike `core/rbac`'s `role_permissions`/
`membership_roles`, there is no tenant-owned parent entity here to guard a
composite FK against: the flag itself is global, the same reason
`RolePermission.permission_id` is a plain FK to the global `permissions`
table rather than a composite one.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid

from infra.db import (
    Base,
    Boolean,
    ForeignKey,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class FeatureFlag(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A global flag definition. `enabled_by_default` is the evaluation
    result for any tenant with no row in `FeatureFlagTenantOverride` --
    the roadmap's own "documented safe default" (docs/IMPLEMENTATION-
    ROADMAP.md Phase 4.2 Rollback Strategy: "flags default to a documented
    safe default on read failure" -- `core/feature_flags/service.py::evaluate_flag`
    also falls back to this same shape on an unknown key or a database
    read failure).
    """

    __tablename__ = "feature_flags"
    __table_args__ = ({"schema": "core"},)

    key: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    enabled_by_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class FeatureFlagTenantOverride(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One tenant's explicit override of a flag's evaluation result --
    tenant-owned, RLS-protected. A row here always wins over
    `FeatureFlag.enabled_by_default` (`core/feature_flags/service.py::evaluate_flag`).
    """

    __tablename__ = "feature_flag_tenant_overrides"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "flag_id", name="uq_feature_flag_tenant_overrides_tenant_flag"
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    flag_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.feature_flags.id"), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
