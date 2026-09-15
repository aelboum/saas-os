"""The reference consumer's own ORM model for its own table
(`reference_consumer.widgets`, created by `reference_consumer/migrations/`).

Declared on the installed `saas-os` package's shared `infra.db` base and
primitives -- exactly the way every Core module declares its own tables
-- so the fixture never imports `sqlalchemy` directly (PRIV-03 P12,
privacy re-audit RA-08 finding 3: a consumer that reaches for
`sqlalchemy.text` sits outside the `infra.db` chokepoint SaaS OS's own
tenant-isolation and no-raw-SQL discipline is built on). Row-Level
Security on this table is established by the migration
(`infra.db.tenant_rls_statements`); this model only maps the columns.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from infra.db import Base, DateTime, ForeignKey, Mapped, String, mapped_column, now


class Widget(Base):
    __tablename__ = "widgets"
    __table_args__ = {"schema": "reference_consumer"}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
