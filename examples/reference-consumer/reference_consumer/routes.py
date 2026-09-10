"""The reference consumer's one project-specific API route (ADR-0018).

Deliberately outside `api.dependencies`'s enforced ingress chain --
`api/v1/tenant_status.py` (SaaS OS's own one existing external route) is
in exactly the same position (ADR-0017: not yet classified as reusable or
product-specific), so this route follows that same, already-established
shape rather than inventing a second convention. `infra.db.tenant_session_scope()`
still enforces RLS tenant isolation regardless -- the ingress chain adds
authentication/RBAC on top, which this fixture route does not need to
demonstrate (`reference_consumer/tools.py` already proves the RBAC path,
via the AI Control Plane).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from sqlalchemy import text

from infra.db import tenant_session_scope

router = APIRouter(prefix="/widgets", tags=["reference-consumer"])


@router.get("/{tenant_id}/{widget_id}")
def get_widget_status(tenant_id: uuid.UUID, widget_id: uuid.UUID) -> dict[str, object]:
    with tenant_session_scope(tenant_id) as session:
        row = (
            session.execute(
                text("SELECT id, name, status FROM reference_consumer.widgets WHERE id = :id"),
                {"id": str(widget_id)},
            )
            .mappings()
            .first()
        )
    if row is None:
        raise HTTPException(status_code=404, detail="widget not found")
    return {"id": str(row["id"]), "name": row["name"], "status": row["status"]}
