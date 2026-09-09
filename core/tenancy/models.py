"""Tenant entity (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1;
docs/MULTI-TENANCY.md section 1: "a tenant *is* the customer organization";
docs/DATA-ARCHITECTURE.md section 1: `core.tenants`, owned exclusively by
this module).

`core.tenants` is the FK target every tenant-owned table across the
platform will reference -- it is deliberately *not* itself Row-Level-
Security-scoped: resolving which tenant a session belongs to must be
possible before any tenant context can be set (a chicken-and-egg problem
RLS on the registry table itself would create). Row-level isolation
(`infra.db.tenant_session_scope`, `infra.db.rls`) applies to tenant-*owned*
data, not to the tenant registry itself.

Uses `infra.db.orm`'s shared declarative base and mixins -- this module
never imports `sqlalchemy` directly (`pyproject.toml`'s "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

from core.tenancy.lifecycle import TenantStatus
from infra.db import Base, Mapped, String, TimestampMixin, UUIDPrimaryKeyMixin, mapped_column


class Tenant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tenants"
    __table_args__ = {"schema": "core"}

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=TenantStatus.PENDING.value
    )
