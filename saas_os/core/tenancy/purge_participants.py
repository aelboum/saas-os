"""RA-12-2 -- the Product-owned tenant purge participant contract.

`saas_os.core.tenancy.purge_tenant()` empties every `core.*` table `PURGE_STEPS`
names, but a Product built on this platform (e.g. `examples/reference-
consumer`) owns tenant-associated tables of its own, in its own schema,
outside `core`'s reach entirely (its own, separately-versioned Alembic
environment -- ADR-0016). Nothing about the dependency direction this
codebase enforces (`docs/ARCHITECTURE.md` section 2: "Product -> SaaS
Core -> Infrastructure"; `tests/architecture/test_layer_boundaries.py`'s
"Core does not depend on Products" contract) lets `saas_os.core.tenancy` import
a Product module to purge it directly -- so this module defines the
inverse: a narrow interface a Product implements and registers, which
`purge_tenant()` calls back through without ever knowing which Product,
if any, is listening.

Mirrors this repository's own established provider-abstraction pattern
exactly (`saas_os.infra.db.backup.destination.BackupDestination`;
`saas_os.control_plane.orchestration.tools.ToolRegistry`): one
`@runtime_checkable Protocol`, one explicit registry class (so a test can
construct an isolated instance instead of mutating shared global state),
and one module-level `default_registry()` for the single real registry a
running process uses. `purge_tenant()` accepts an optional `registry=`
override for exactly that isolation; real callers get the process-wide
default.

What this contract deliberately does NOT do: it does not hand a Product
participant a SQLAlchemy `Session`, a connection, or any other way to run
arbitrary SQL against this platform's own database (`saas_os/core/tenancy` has no
idea what tables a Product owns, and must never gain one) -- a
participant receives only the opaque `tenant_id` being purged and is
responsible for its own data access, exactly the way `reference_consumer`
already accesses its own table today (`reference_consumer/widgets.py`'s
own `saas_os.infra.db.tenant_session_scope(tenant_id)` pattern -- available to a
Product because *Products* may depend on `infra`, never the reverse for
`core`). It also does not decide *whether* a Product's data should be
deleted, retained, or handled some other way on purge -- that remains
each Product's own, separately documented policy; this module only makes
"the Product's own answer actually runs, in the right lifecycle window,
with a failure that fails closed" an enforced mechanism instead of an
unenforced aspiration (`docs/MULTI-TENANCY.md` section 6's own "Product
modules react to tenant lifecycle transitions").
"""

from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable


@runtime_checkable
class TenantPurgeParticipant(Protocol):
    """A Product-owned participant in `saas_os.core.tenancy.purge_tenant()`.

    `name` is a short, stable, human-readable identifier (e.g.
    `"reference_consumer.widgets"`) -- it appears only in bounded
    `tenant.purge_failed` audit metadata (`failed_step`) if this
    participant raises, and in `TenantPurgeResult.participant_names` on
    success; it is never customer content and must not contain one.

    `purge_tenant_data()` is called by `purge_tenant()` **only** while the
    tenant is locked in `PURGING` (the same row lock `_run_purge_pass()`'s
    own Core steps run under -- see that function's docstring): no
    concurrent lifecycle transition can be in flight, and the tenant
    cannot be "live" (`ACTIVE`/`SUSPENDED`/`PENDING`) when this runs. A
    participant does not need to re-check tenant status itself.

    **Idempotency is this method's own responsibility, by contract, not
    something Core enforces or verifies**: `purge_tenant()` is itself
    safely re-callable after a crash or a failure (its own docstring), and
    every registered participant runs again on every retry -- including
    one that already fully completed. Deleting rows that are already gone
    must be a silent no-op, exactly like every existing `PURGE_STEPS`
    entry (`purge_tenant_invitations()`, etc.) already is.

    Report failure by raising (any exception); Core classifies it as a
    bounded, opaque `"participant_error"` and does not transition the
    tenant to `PURGED` (see `saas_os.core.tenancy.service.purge_tenant()`'s own
    docstring) -- never store the exception's own message anywhere
    durable, only its type name, exactly like every existing purge step
    failure. Report success by returning normally, including when there
    was nothing to purge.
    """

    @property
    def name(self) -> str: ...

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None: ...


class DuplicateTenantPurgeParticipantError(ValueError):
    """Raised by `TenantPurgeParticipantRegistry.register()` when
    `participant.name` is already registered -- two participants sharing
    one identifier would make `tenant.purge_failed`'s `failed_step` and
    `TenantPurgeResult.participant_names` ambiguous about which one ran."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"A tenant purge participant named {name!r} is already registered.")


class TenantPurgeParticipantRegistry:
    """An in-process registry of `TenantPurgeParticipant`s. Not a database
    table -- a participant is fundamentally code, not data (mirrors
    `saas_os.control_plane.orchestration.tools.ToolRegistry`'s own module
    docstring for the identical reasoning). An explicit class, not a bare
    module-level dict, so a test can construct its own isolated registry
    -- containing exactly the fake participant it wants to exercise --
    instead of mutating the one shared process-wide registry every other
    test also runs against."""

    def __init__(self) -> None:
        self._participants: dict[str, TenantPurgeParticipant] = {}

    def register(self, participant: TenantPurgeParticipant) -> TenantPurgeParticipant:
        name = participant.name
        if not name or not name.strip():
            raise ValueError("A tenant purge participant's name must be a non-empty string.")
        if name in self._participants:
            raise DuplicateTenantPurgeParticipantError(name)
        self._participants[name] = participant
        return participant

    def list(self) -> list[TenantPurgeParticipant]:
        """Every registered participant, in registration order --
        `purge_tenant()`'s own iteration order, so which participant's
        failure is reported first is deterministic."""
        return list(self._participants.values())


_default_registry = TenantPurgeParticipantRegistry()


def default_registry() -> TenantPurgeParticipantRegistry:
    """The single, process-wide registry `purge_tenant()` consults when a
    caller does not pass its own -- the one a real application's own
    composition root (e.g. `reference_consumer/app.py::create_app()`)
    registers its participants into."""
    return _default_registry
