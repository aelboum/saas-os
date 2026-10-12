"""What happens to this product's data when a tenant is purged.

`saas_os.core.tenancy.purge_tenant()` runs every registered participant while the
tenant is locked in `PURGING`. Core never imports this module; this module
registers itself with Core (`Product -> Core`, the only allowed
direction). A product that registers no participant leaves its rows
behind a purged tenant.

The contract (`saas_os.core.tenancy.purge_participants.TenantPurgeParticipant`):
idempotent -- it runs again on every retry, including after it already
succeeded -- and it reports failure by raising. Deleting is this
scaffold's choice; anonymizing or retaining is equally valid if that is
the product's documented policy.
"""

from __future__ import annotations

import uuid

from my_product.models import Item
from saas_os.core.tenancy.purge_participants import (
    DuplicateTenantPurgeParticipantError,
    TenantPurgeParticipantRegistry,
    default_registry,
)
from saas_os.infra.db import select, tenant_session_scope


class ItemPurgeParticipant:
    @property
    def name(self) -> str:
        return "my_product.items"

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None:
        with tenant_session_scope(tenant_id) as session:
            rows = (
                session.execute(select(Item).where(Item.tenant_id == tenant_id).with_for_update())
                .scalars()
                .all()
            )
            for row in rows:
                session.delete(row)


def register(registry: TenantPurgeParticipantRegistry | None = None) -> None:
    """Called once from `my_product.app.create_app()` and from any other
    process that may run `purge_tenant()`. Registering the same class twice
    in one process is a no-op; a different participant under the same name
    is still an error."""
    active = registry if registry is not None else default_registry()
    try:
        active.register(ItemPurgeParticipant())
    except DuplicateTenantPurgeParticipantError:
        if not any(isinstance(p, ItemPurgeParticipant) for p in active.list()):
            raise
