"""System actor attribution (ADR 0061, option B; step 1 of
`docs/architecture/SYSTEM-ACTOR-MIGRATION-PLAN.md`).

A `SystemActor` names the system component that *executes* an action no
member performed -- a worker job, a scheduled job, a webhook or
provider-event processor, an inbound processor, a public link, a
maintenance command, a billing process. It is attribution only, never
authorization:

- It is **not** a `Caller`. `require_caller()` refuses it and no Core
  operation accepts it as its `caller`, so it can never satisfy an
  authorization check.
- When a system action also needs Core authority, it keeps its existing
  `SystemCaller` purpose; the actor is attached to that caller
  (`SystemCaller(authority, actor=...)`) for attribution only and changes
  nothing about what the caller is allowed to do.
- The kinds are a closed list owned by Core (`SystemActorKind`). A product
  names its actor with `name`; it cannot add a kind.

Owner decision C (2026-11-01) separates three roles that the audit trail
records distinctly (`saas_os/core/authority/attribution.py`):

1. the **executing actor** -- this `SystemActor` (`kind`, `name`), the job
   or component that runs the action;
2. the **initiating actor** -- an `Initiator`: the user, service account or
   system actor that originally requested it, or explicitly "unavailable";
3. the **correlation identity** -- a `SystemCorrelation`: the arq job id,
   the outbox event id, the request id.

So a `SystemActor` carries no initiator and no job id: an arq job id
identifies an execution and correlates it, it never stands in for who
initiated the action.

Every field is validated at construction, so an invalid actor never reaches
an audit write. Pure data, standard library only, like the rest of this
package.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class InvalidSystemActorError(ValueError):
    """An attribution value (`SystemActor`, `Initiator`,
    `SystemCorrelation`) has an invalid field. Raised at construction,
    before any audit write. The message names the field, never the rejected
    value (which might be a credential handed over by mistake)."""

    def __init__(self, field: str, reason: str, *, owner: str = "SystemActor") -> None:
        self.field = field
        super().__init__(f"{owner}.{field} {reason}.")


class SystemActorKind(enum.StrEnum):
    """The closed, Core-owned list of system actor kinds (ADR 0061)."""

    WORKER_JOB = "worker_job"
    SCHEDULED_JOB = "scheduled_job"
    WEBHOOK_PROCESSOR = "webhook_processor"
    PROVIDER_EVENT_PROCESSOR = "provider_event_processor"
    INBOUND_PROCESSOR = "inbound_processor"
    PUBLIC_LINK = "public_link"
    MAINTENANCE = "maintenance"
    BILLING_PROCESS = "billing_process"


MAX_IDENTIFIER_LENGTH = 100
LOWER_IDENTIFIER_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_.:-")
OPAQUE_IDENTIFIER_CHARACTERS = LOWER_IDENTIFIER_CHARACTERS | frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

# Owner decision D2 (2026-11-02): an attribution value that is not a user
# initiator must not encode one. SaaS OS user ids are UUIDs, so an
# identifier that names a component or a record *type* never embeds one:
# not in its canonical form, not as 32 hex digits. (Standard library only,
# without `re`: tests/architecture/test_authority_contract.py.)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_UUID_HEX_LENGTH = 32


def embeds_an_id(value: str) -> bool:
    """Whether `value` contains a UUID: 32 hex digits in a row once hyphens
    are ignored (so the canonical hyphenated form and the bare form)."""
    run = 0
    for character in value.replace("-", ""):
        run = run + 1 if character in _HEX_DIGITS else 0
        if run >= _UUID_HEX_LENGTH:
            return True
    return False


def check_identifier(
    field: str, value: object, allowed: frozenset[str], *, owner: str = "SystemActor"
) -> str:
    """`value` as a 1-to-100-character str drawn from `allowed`, or
    `InvalidSystemActorError` naming `owner.field`."""
    if not isinstance(value, str):
        raise InvalidSystemActorError(
            field, f"must be a str, got {type(value).__name__}", owner=owner
        )
    if not 1 <= len(value) <= MAX_IDENTIFIER_LENGTH:
        raise InvalidSystemActorError(
            field, f"must be 1 to {MAX_IDENTIFIER_LENGTH} characters", owner=owner
        )
    if not set(value) <= allowed:
        raise InvalidSystemActorError(
            field, "contains a character outside the allowed set", owner=owner
        )
    return value


@dataclass(frozen=True)
class SystemActor:
    """The executing system component: `kind` (Core-owned) and `name`
    (product-chosen, `[a-z0-9_.:-]{1,100}`). Attribution only; never a
    caller, never an initiator by itself, never a correlation id."""

    kind: SystemActorKind
    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SystemActorKind):
            raise InvalidSystemActorError(
                "kind", f"must be a SystemActorKind, got {type(self.kind).__name__}"
            )
        check_identifier("name", self.name, LOWER_IDENTIFIER_CHARACTERS)
        if embeds_an_id(self.name):
            # A component name, never an id (D2: no user id rides in a
            # system actor or a system initiator).
            raise InvalidSystemActorError("name", "must name a component, never embed an id")

    def as_metadata(self) -> dict[str, object]:
        """The fixed audit-metadata shape recorded under `system_actor`."""
        return {"kind": self.kind.value, "name": self.name}

    @classmethod
    def from_job_actor(cls, job_actor: object) -> SystemActor:
        """Convert the plain-data actor `saas_os.infra.jobs` derives for a
        job execution (`TenantJobContext.system_actor` /
        `SystemJobContext.system_actor`) into a validated `SystemActor`.
        Infrastructure does not import Core, so the job context carries the
        actor as data and this is the one Core-side conversion. Only the two
        job kinds are accepted; anything else fails closed."""
        kind = getattr(job_actor, "kind", None)
        if kind not in (SystemActorKind.WORKER_JOB.value, SystemActorKind.SCHEDULED_JOB.value):
            raise InvalidSystemActorError(
                "kind", "of a job actor must be worker_job or scheduled_job"
            )
        return cls(kind=SystemActorKind(kind), name=getattr(job_actor, "name", None))  # type: ignore[arg-type]
