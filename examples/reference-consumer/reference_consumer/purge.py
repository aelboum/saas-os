"""RA-12-2 -- the reference consumer's own tenant purge participant
(proof implementation of `saas_os.core.tenancy.purge_participants`).

Registers `reference_consumer.widgets`' own tenant-scoped deletion with
Core's purge orchestration, proving the Product-owned-data purge contract
end to end: `saas_os.core.tenancy` never imports this module, or
`reference_consumer` at all (`tests/architecture/test_layer_boundaries.py`'s
"Core does not depend on Products" contract, unchanged) -- this module
implements Core's published `TenantPurgeParticipant` interface and registers
an instance of it through `saas_os.core.tenancy.register_purge_participant()`,
the inverse direction the dependency rule requires (`docs/ARCHITECTURE.md`
section 2: "Product -> SaaS Core -> Infrastructure").

Deletion, not retention, is this Product's own deliberate choice for this
one table (module docstring of `reference_consumer/models.py::Widget`:
it carries no PII of its own beyond an operator-chosen `name`) -- nothing
about the contract itself requires deletion; a different Product could
just as legitimately register a participant that anonymizes or retains
its own data instead, as its own documented policy.
"""

from __future__ import annotations

import uuid

from reference_consumer.models import Widget
from saas_os.core.tenancy import register_purge_participant
from saas_os.infra.db import select, tenant_session_scope


class WidgetPurgeParticipant:
    """Deletes every `reference_consumer.widgets` row belonging to the
    tenant being purged. Idempotent: a second call (or a Core purge
    retry) finds nothing left and deletes zero rows -- never an error.
    Reads under `saas_os.infra.db.tenant_session_scope(tenant_id)`, the same
    RLS-backed, tenant-scoped access pattern
    `reference_consumer/widgets.py::get_widget()` already establishes;
    never a raw or unscoped SQL statement, and never a row belonging to
    any other tenant."""

    @property
    def name(self) -> str:
        return "reference_consumer.widgets"

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None:
        with tenant_session_scope(tenant_id) as session:
            rows = (
                session.execute(
                    select(Widget).where(Widget.tenant_id == tenant_id).with_for_update()
                )
                .scalars()
                .all()
            )
            for row in rows:
                session.delete(row)


# One instance per process: registering the same object again is a no-op,
# so `create_app()` may run more than once in one process (this repository's
# own tests call it repeatedly) without error. A *different* object under the
# same name still raises `DuplicateTenantPurgeParticipantError`.
WIDGET_PURGE_PARTICIPANT = WidgetPurgeParticipant()


def register_purge_participants() -> None:
    """Register this Product's purge participant in the current process --
    called from `reference_consumer/app.py::create_app()` (this Product's own
    composition root, the same place `widgets_router` is mounted). The
    registry is per process: a process that runs `purge_tenant()` without
    building the app (the operator command) calls this itself, through
    `saas-os-operator purge-tenant --setup
    reference_consumer.purge:register_purge_participants`. A test that wants
    full isolation passes its own `registry=` to `purge_tenant()` instead."""
    register_purge_participant(WIDGET_PURGE_PARTICIPANT)
