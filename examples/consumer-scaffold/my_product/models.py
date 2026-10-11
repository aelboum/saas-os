"""This product's own tables, in this product's own schema (ADR-0016).

Declared on SaaS OS's shared `saas_os.infra.db` base and column primitives, so
product code never imports `sqlalchemy` directly: `saas_os.infra.db` is the one
database-access chokepoint tenant isolation is built on. The table
itself, its Row-Level Security policy and its grants are created by
`my_product/migrations/`; this module only maps columns.

Every tenant-owned table carries a non-null `tenant_id` foreign key to
`core.tenants.id`. That column is what the RLS policy keys on.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from saas_os.infra.db import Base, DateTime, ForeignKey, Mapped, String, mapped_column, now

SCHEMA = "my_product"


class Item(Base):
    __tablename__ = "items"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
