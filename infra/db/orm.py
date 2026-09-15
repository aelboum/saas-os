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

CP-07 J-INFRA-05: the raw `sqlalchemy.func` namespace is deliberately
never re-exported (imported below as `_func`, never bound to the bare
name `func` at module scope, so `from infra.db.orm import func` fails
the same way `from infra.db import func` does). `func.<anything>`
compiles to a call to *any* PostgreSQL function -- a live audit proved
that a tenant-scoped session combined with `func.set_config(...)` (built
from nothing but `select`/`func`, both previously re-exported here) lets
ordinary Core/Product code overwrite the current session's
`app.tenant_id`, bypassing Row-Level Security for the rest of that
transaction and, because `set_config`'s third argument controls
transaction- vs. session-scoping, potentially for whatever the pooled
connection is reused for next. `now()`/`sum_()` below are the two
`func` calls every current consumer of this module actually needs --
named, single-purpose, and incapable of expressing a call to anything
else in the PostgreSQL function catalog.

PRIV-03 P6 (privacy re-audit finding RA-01): the generic `sqlalchemy.text`
constructor is not re-exported either. It had been, for one declarative
use only -- a partial-index predicate (`Index(..., postgresql_where=...)`)
-- but a live audit proved it reopened the exact J-INFRA-05 capability
class: `session.execute(text("SELECT set_config('app.tenant_id', :t,
false)"))` inside a tenant-scoped session reads another tenant's rows and,
with `is_local=false`, poisons the pooled connection past COMMIT. A
partial-index predicate needs no SQL-execution primitive at all: SQLAlchemy
accepts a plain string for `postgresql_where` (coerced to the same DDL
text at `CREATE INDEX` time, never executable through a session), so the
models pass the predicate string directly. Raw statement execution stays
inside `infra/db` (`session.py`, `role_guard.py`, the migration
environment), which imports `sqlalchemy.text` itself. `update` remains
exported: `control_plane.approvals`' CP-01 atomic execution claim is a
compare-and-set `UPDATE ... WHERE status = 'approved'` over an ORM-mapped
table, which expresses no function call and cannot rewrite a session
setting.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ColumnElement,
    ColumnExpressionArgument,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    select,
    update,
)
from sqlalchemy import func as _func
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
    "now",
    "sum_",
    "select",
    "update",
    "IntegrityError",
    "OperationalError",
]


def now() -> ColumnElement[datetime]:
    """The database server's current transaction timestamp, as a SQL
    expression -- `sqlalchemy.func.now()`, named and narrowed (module
    docstring, CP-07 J-INFRA-05). The one `func` call `TimestampMixin`
    below (and every current `server_default=`/`onupdate=` call site)
    needs."""
    return _func.now()


def sum_(column: ColumnExpressionArgument[Any]) -> ColumnElement[Any]:
    """SQL `SUM(column)`, as a SQL expression -- `sqlalchemy.func.sum()`,
    named and narrowed (module docstring, CP-07 J-INFRA-05). The one
    aggregate `core.usage`'s quota-consumption queries need. `NULL` when
    no rows match, exactly like the underlying SQL `SUM` -- callers
    already handle that (e.g. `core.usage.service.aggregate_usage()`).
    `ColumnExpressionArgument` (the same type `sqlalchemy.func.sum()`'s
    own signature accepts) rather than a plain `ColumnElement`: it also
    covers an ORM `Mapped`/`InstrumentedAttribute` column reference like
    `UsageEvent.quantity`, the shape every current caller passes."""
    return _func.sum(column)


class Base(DeclarativeBase):
    pass


class UUIDPrimaryKeyMixin:
    """A random (non-sequential, non-guessable) UUID primary key --
    the standard choice for a multi-tenant platform's externally-visible
    identifiers (docs/MULTI-TENANCY.md section 1: a stable `tenant_id`).
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=now(), onupdate=now()
    )
