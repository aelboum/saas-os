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

The supported Product-facing surface is re-exported from
`saas_os.core.tenancy`: `TenantPurgeParticipant`,
`register_purge_participant()`, `registered_purge_participant_names()`,
`DuplicateTenantPurgeParticipantError` and
`InvalidTenantPurgeParticipantError` (docs/CONSUMER-GUIDE.md section 11).
Registration is explicit: there is no discovery of participants from
installed packages or entry points.

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

import re
import threading
import uuid
from typing import Protocol, runtime_checkable

# The participant-name grammar: lowercase ASCII letters, digits, `.`, `_` and
# `-`, starting with a letter or digit, at most 100 characters -- the same
# shape as an AI use-case name (`saas_os.control_plane.inference.use_cases`).
# The name is written into bounded `tenant.purge_failed` audit metadata
# (`failed_step`), so it must never be free text.
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")


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
    """Raised by `TenantPurgeParticipantRegistry.register()` when a
    *different* participant object is already registered under
    `participant.name` -- two participants sharing one identifier would make
    `tenant.purge_failed`'s `failed_step` and
    `TenantPurgeResult.participant_names` ambiguous about which one ran.
    Registering the *same* object again is not an error (see `register()`)."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"A tenant purge participant named {name!r} is already registered.")


class InvalidTenantPurgeParticipantError(ValueError):
    """Raised by `TenantPurgeParticipantRegistry.register()` when the object
    does not implement `TenantPurgeParticipant` or its `name` does not match
    the participant-name grammar (`_NAME`). Nothing is registered."""


class TenantPurgeParticipantRegistry:
    """An in-process registry of `TenantPurgeParticipant`s. Not a database
    table -- a participant is fundamentally code, not data (mirrors
    `saas_os.control_plane.orchestration.tools.ToolRegistry`'s own module
    docstring for the identical reasoning). An explicit class, not a bare
    module-level dict, so a test can construct its own isolated registry
    -- containing exactly the fake participant it wants to exercise --
    instead of mutating the one shared process-wide registry every other
    test also runs against.

    Each participant's `name` is read once, validated and stored at
    registration; `purge_tenant()` reports that stored name, so a `name`
    property that later returns something else cannot change what the audit
    trail records."""

    def __init__(self) -> None:
        self._participants: dict[str, TenantPurgeParticipant] = {}
        self._lock = threading.Lock()

    def register(self, participant: TenantPurgeParticipant) -> TenantPurgeParticipant:
        """Register `participant` and return it. Registering the same object
        again is a no-op, so a composition root that runs more than once in
        one process (an application factory called by several tests) stays
        correct; a different object under an already-registered name raises
        `DuplicateTenantPurgeParticipantError`."""
        if not isinstance(participant, TenantPurgeParticipant) or not callable(
            participant.purge_tenant_data
        ):
            raise InvalidTenantPurgeParticipantError(
                "A tenant purge participant must have a `name` and a callable "
                "`purge_tenant_data(tenant_id)`."
            )
        name = participant.name
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise InvalidTenantPurgeParticipantError(
                "A tenant purge participant's name must be a non-empty string of at most 100 "
                "characters: lowercase letters, digits, '.', '_' or '-', starting with a "
                "letter or digit."
            )
        with self._lock:
            existing = self._participants.get(name)
            if existing is participant:
                return participant
            if existing is not None:
                raise DuplicateTenantPurgeParticipantError(name)
            self._participants[name] = participant
        return participant

    def list(self) -> list[TenantPurgeParticipant]:
        """Every registered participant, in registration order --
        `purge_tenant()`'s own iteration order, so which participant's
        failure is reported first is deterministic."""
        with self._lock:
            return list(self._participants.values())

    def entries(self) -> tuple[tuple[str, TenantPurgeParticipant], ...]:
        """`(name, participant)` pairs in registration order, `name` being the
        value validated at registration. A snapshot: `purge_tenant()` takes it
        once, when its participant steps start, so a participant registered
        after that point does not join that attempt."""
        with self._lock:
            return tuple(self._participants.items())

    def names(self) -> tuple[str, ...]:
        """Every registered name, in registration order."""
        with self._lock:
            return tuple(self._participants)


_default_registry = TenantPurgeParticipantRegistry()


def default_registry() -> TenantPurgeParticipantRegistry:
    """The single, process-wide registry `purge_tenant()` consults when a
    caller does not pass its own -- the one a real application's own
    composition root (e.g. `reference_consumer/app.py::create_app()`)
    registers its participants into. Products use
    `register_purge_participant()` and `registered_purge_participant_names()`
    instead of this accessor."""
    return _default_registry


def register_purge_participant(participant: TenantPurgeParticipant) -> TenantPurgeParticipant:
    """The public way for a Product to take part in tenant purge: register
    `participant` in this process's registry, the one `purge_tenant()` uses.
    Returns `participant`. Same rules as `TenantPurgeParticipantRegistry.register()`:
    the same object again is a no-op, a different object under a registered
    name raises `DuplicateTenantPurgeParticipantError`, and an invalid
    participant or name raises `InvalidTenantPurgeParticipantError`.

    The registry is per process. Registering in the API process does not
    register in the worker or in a `saas-os-operator purge-tenant` process:
    every process that runs `purge_tenant()` must register for itself (the
    operator command does it through `--setup`)."""
    return default_registry().register(participant)


def registered_purge_participant_names() -> tuple[str, ...]:
    """The names registered in this process, in registration order -- the
    order `purge_tenant()` runs them in."""
    return default_registry().names()
