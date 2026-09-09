"""Approval request entity (docs/IMPLEMENTATION-ROADMAP.md Phase 7.2;
docs/AI-CONTROL-PLANE.md section 5: "tier 1 -- propose + approval").

`control_plane.approval_requests` is tenant-owned and RLS-protected.
Every proposed action -- even one whose tool is environment- or
repository-scoped, not tenant-scoped (docs/AI-CONTROL-PLANE.md section 7)
-- is still attributed to a real `tenant_id`: `core.audit_log.record()`
requires one on every row (`core/audit_log/models.py`'s own docstring:
"Phase 3.4 does not implement a separate global/system (tenant-less)
audit table ... if global audit events are not required, do not invent
them"), and this table's own tenant_id is what `control_plane.orchestration
._execute_tool()` is eventually called with once an approval is granted.
A repository-scoped proposal is still audited *within* whichever
tenant's operational context proposed it -- never a tenant-less row.

`tool_key`/`payload`/`agent_scope_value` are a snapshot of what
`invoke_tool()` (docs/IMPLEMENTATION-ROADMAP.md Phase 7.1) would need to
actually execute the proposed action once approved -- `payload` is a
plain `JSON` dict; callers must never place a secret value in it
(`core/webhooks`/`core/notifications`'s own "never a secret in a job
payload" convention, applied here to a proposal payload for the same
reason: it is persisted, queryable state, not an ephemeral call
argument).

Separation of duties (docs/IMPLEMENTATION-ROADMAP.md Phase 7.2's own
Security Requirement: "an approval cannot be self-granted by the same
identity that proposed the action") is enforced twice: once at the
application layer (`control_plane/approvals/service.py::approve()`) and
once here, as a `CHECK` constraint -- the same "database as the real
guarantee, application check as fail-fast" discipline `core/rbac`'s
composite foreign keys already establish for tenant isolation.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from infra.db import (
    JSON,
    Base,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Mapped,
    String,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class ApprovalRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One proposed, tier>=1 tool invocation awaiting (or having
    received) human approval. `status` is a plain string
    (`"pending"`/`"approved"`/`"rejected"`/`"executed"`) rather than a
    database enum -- mirrors `core.notifications.Notification.status`'s
    own convention: new statuses are added by extending
    `control_plane/approvals/service.py`, never by a schema migration.
    """

    __tablename__ = "approval_requests"
    __table_args__ = (
        CheckConstraint(
            "approver_user_id IS NULL OR approver_user_id != proposer_user_id",
            name="ck_approval_requests_no_self_approval",
        ),
        {"schema": "control_plane"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    proposer_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.users.id"), nullable=False)
    tool_key: Mapped[str] = mapped_column(String(200), nullable=False)
    agent_scope_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    approver_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.users.id"), nullable=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
