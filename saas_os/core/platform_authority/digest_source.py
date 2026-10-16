"""Read-only access to `core.platform_audit_log` for the audit digests
(docs/ADR/0053-audit-digests-in-external-logs.md).

The platform models are touched only inside this package (ADR-0045), so
the digest module (`saas_os.core.audit_digest`) reads platform evidence
through these three functions. They read rows by creation time and
nothing else: no operation, no authorization decision, no write. The
table is global and carries the tenant-context exclusion policy, so the
reads run in an untenanted session, as every other platform read does."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from saas_os.core.platform_authority.models import PlatformAuditLogEntry
from saas_os.infra.db import Text, select, session_scope


def platform_audit_rows(
    columns: Sequence[str], start: datetime, end: datetime
) -> list[tuple[Any, ...]]:
    """The named columns of every platform audit row created in
    `[start, end)`, in `(created_at, id)` order. `metadata` is returned as
    its stored text, never as a decoded JSON value."""
    table = PlatformAuditLogEntry.__table__
    selected = [
        table.c[name].cast(Text).label(name) if name == "metadata" else table.c[name]
        for name in columns
    ]
    with session_scope() as session:
        rows = session.execute(
            select(*selected)
            .where(table.c.created_at >= start, table.c.created_at < end)
            .order_by(table.c.created_at, table.c.id)
        ).all()
    return [tuple(row) for row in rows]


def platform_audit_earliest() -> datetime | None:
    """When the oldest platform audit row was created, if there is one."""
    table = PlatformAuditLogEntry.__table__
    with session_scope() as session:
        return session.execute(
            select(table.c.created_at).order_by(table.c.created_at).limit(1)
        ).scalar_one_or_none()


def platform_audit_count(low: datetime | None, high: datetime, *, limit: int) -> int:
    """How many platform audit rows were created in `[low, high)` (from
    the beginning when `low` is `None`), counting at most `limit`."""
    table = PlatformAuditLogEntry.__table__
    query = select(table.c.id).where(table.c.created_at < high)
    if low is not None:
        query = query.where(table.c.created_at >= low)
    with session_scope() as session:
        return len(session.execute(query.limit(limit)).all())


def platform_audit_columns() -> tuple[str, ...]:
    """Every column of `core.platform_audit_log`, for the digest's check
    that its fixed column list is complete."""
    return tuple(column.name for column in PlatformAuditLogEntry.__table__.columns)
