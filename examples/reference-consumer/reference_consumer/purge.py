"""RA-12-2 -- the reference consumer's own tenant purge participant
(proof implementation of `saas_os.core.tenancy.purge_participants`).

Registers `reference_consumer.widgets`' own tenant-scoped deletion with
Core's purge orchestration, proving the Product-owned-data purge contract
end to end: `saas_os.core.tenancy` never imports this module, or
`reference_consumer` at all (`tests/architecture/test_layer_boundaries.py`'s
"Core does not depend on Products" contract, unchanged) -- this module
imports Core's published `TenantPurgeParticipant` interface and registers
an instance of it, the inverse direction the dependency rule requires
(`docs/ARCHITECTURE.md` section 2: "Product -> SaaS Core -> Infrastructure").

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
from saas_os.core.tenancy.purge_participants import (
    DuplicateTenantPurgeParticipantError,
    TenantPurgeParticipantRegistry,
    default_registry,
)
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


def register(registry: TenantPurgeParticipantRegistry | None = None) -> None:
    """Register this Product's purge participant against the process-wide
    default registry -- called from `reference_consumer/app.py::create_app()`
    (this Product's own composition root, the same place `widgets_router`
    is mounted). A real process calls `create_app()` once; this
    repository's own test suite calls it repeatedly against the *same*
    process-wide registry (`create_app()` is exercised directly by
    several test modules, unlike a real deployment), so re-registering
    the identically-named participant is treated as already-done, not an
    error -- `TenantPurgeParticipantRegistry.register()` itself still
    raises `DuplicateTenantPurgeParticipantError` for two *different*
    participant instances that collide on `name`, which remains a real
    bug this only swallows for the exact same class registering itself
    again. A test that wants full isolation (its own fake participant, or
    none at all) passes its own `registry=` to `purge_tenant()` instead of
    relying on this process-wide one.
    """
    active_registry = registry if registry is not None else default_registry()
    try:
        active_registry.register(WidgetPurgeParticipant())
    except DuplicateTenantPurgeParticipantError:
        if not any(
            isinstance(p, WidgetPurgeParticipant) for p in active_registry.list()
        ):  # pragma: no cover -- would mean a *different* type reused this name
            raise
