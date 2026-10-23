"""What happens to this product's data when a tenant is purged.

`saas_os.core.tenancy.purge_tenant()` runs every registered participant while the
tenant is locked in `PURGING`. Core never imports this module; this module
registers itself with Core (`Product -> Core`, the only allowed
direction). A product that registers no participant leaves its rows
behind a purged tenant.

The contract (`saas_os.core.tenancy.TenantPurgeParticipant`): idempotent --
it runs again on every retry, including after it already succeeded -- and
it reports failure by raising. Deleting is this scaffold's choice;
anonymizing or retaining is equally valid if that is the product's
documented policy.
"""

from __future__ import annotations

import uuid

from my_product.models import Item
from saas_os.core.tenancy import register_purge_participant
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


# One instance per process: registering the same object again is a no-op.
ITEM_PURGE_PARTICIPANT = ItemPurgeParticipant()


def register_purge_participants() -> None:
    """Register this product's purge participants in the current process.

    The registry is per process. Call this in every process that runs
    `purge_tenant()`: `create_app()` calls it, and the operator command
    calls it through `saas-os-operator purge-tenant --setup
    my_product.purge:register_purge_participants`. Registering in the API
    process does not register in the operator's process."""
    register_purge_participant(ITEM_PURGE_PARTICIPANT)
