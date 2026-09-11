"""Shared SQLAlchemy ORM primitives (docs/IMPLEMENTATION-ROADMAP.md Phase
3.1; docs/ARCHITECTURE.md section 2: "Infrastructure has zero knowledge of
business concepts").

This module knows nothing about what a "tenant" or any other entity is --
it only provides the mechanical building blocks (a declarative base, a
UUID-primary-key mixin, a created/updated-timestamp mixin) that Core and
Product modules use to define their *own* tables. Core/Product modules
import these from `infra.db`, never from `sqlalchemy` directly --
`pyproject.toml`'s "Only infra/db may import SQLAlchemy or psycopg
directly" contract forbids it (with a narrow, documented `ignore_imports`
for exactly this module's own internal use of sqlalchemy). This is what
lets `core/tenancy` own its own schema (docs/DATA-ARCHITECTURE.md section
1: "core.* -- owned exclusively by the corresponding core/* module")
without infra/db ever needing to know what a tenant is.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = [
    "Base",
    "UUIDPrimaryKeyMixin",
    "TimestampMixin",
    "Mapped",
    "mapped_column",
    "String",
    "Text",
    "Integer",
    "Numeric",
    "Boolean",
    "CheckConstraint",
    "DateTime",
    "ForeignKey",
    "ForeignKeyConstraint",
    "UniqueConstraint",
    "Index",
    "JSON",
    "func",
    "select",
    "text",
    "IntegrityError",
    "OperationalError",
]


class Base(DeclarativeBase):
    pass


class UUIDPrimaryKeyMixin:
    """A random (non-sequential, non-guessable) UUID primary key --
    the standard choice for a multi-tenant platform's externally-visible
    identifiers (docs/MULTI-TENANCY.md section 1: a stable `tenant_id`).
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
