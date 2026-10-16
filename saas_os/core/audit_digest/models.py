"""`core.audit_digests` -- where the audit-digest job resumes
(docs/ADR/0053-audit-digests-in-external-logs.md, decision 6).

One row per digested window: the record exactly as it was logged, and its
digest, which the next window's record names as `previous`. The row is a
cursor, not evidence: the evidence is the log line the deployment ships to
an append-only store outside the database. Global (no `tenant_id`), and
unreachable from a tenant-scoped transaction, because a record names
tenants and their row counts. The application role may only `SELECT` and
`INSERT` (migration `d3e9a1c47b20`)."""

from __future__ import annotations

from datetime import datetime

from saas_os.infra.db import Base, DateTime, Mapped, String, Text, mapped_column, now


class AuditDigest(Base):
    __tablename__ = "audit_digests"
    __table_args__ = {"schema": "core"}

    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    record: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=now()
    )
