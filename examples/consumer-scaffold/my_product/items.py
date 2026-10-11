"""Data access for `my_product.items` -- the only module that touches the
table.

Every function takes a *verified* tenant id: the `RequestContext` the
ingress chain produced, a `TenantJobContext` the worker validated, or the
tenant Core is purging. Never a value read from a URL, a body or a job
payload's free-form data.

Every function runs inside `saas_os.infra.db.tenant_session_scope(tenant_id)`,
which binds the session to that tenant for Row-Level Security, and also
states the tenant predicate explicitly. RLS is the guarantee; the
predicate is defence in depth.
"""

from __future__ import annotations

import uuid

from my_product.models import Item
from saas_os.infra.db import select, tenant_session_scope

NEW = "new"
PROCESSED = "processed"


def create_item(tenant_id: uuid.UUID, name: str) -> Item:
    with tenant_session_scope(tenant_id) as session:
        item = Item(tenant_id=tenant_id, name=name, status=NEW)
        session.add(item)
        session.flush()
        session.refresh(item)
        session.expunge(item)
        return item


def get_item(tenant_id: uuid.UUID, item_id: uuid.UUID) -> Item | None:
    """The tenant's item, or `None`. An item of another tenant and an item
    that does not exist are indistinguishable to the caller, by design."""
    with tenant_session_scope(tenant_id) as session:
        item = session.execute(
            select(Item).where(Item.id == item_id, Item.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if item is not None:
            session.expunge(item)
        return item


def mark_item_processed(tenant_id: uuid.UUID, item_id: uuid.UUID) -> bool:
    """Idempotent: marking an already-processed item again changes nothing
    and still returns `True`. `False` means the tenant has no such item."""
    with tenant_session_scope(tenant_id) as session:
        item = session.execute(
            select(Item).where(Item.id == item_id, Item.tenant_id == tenant_id).with_for_update()
        ).scalar_one_or_none()
        if item is None:
            return False
        item.status = PROCESSED
        return True
