"""System actor attribution (ADR 0061, option B; step 1 of
`docs/architecture/SYSTEM-ACTOR-MIGRATION-PLAN.md`).

A `SystemActor` says *who or what* performed an action no member performed
-- a worker job, a scheduled job, a webhook or provider-event processor, an
inbound processor, a public link, a maintenance command, a billing process
-- and *on what trigger* (an optional initiator record). It is attribution
only, never authorization:

- It is **not** a `Caller`. `require_caller()` refuses it and no Core
  operation accepts it as its `caller`, so it can never satisfy an
  authorization check.
- When a system action also needs Core authority, it keeps its existing
  `SystemCaller` purpose; the actor is attached to that caller
  (`SystemCaller(authority, actor=...)`) for attribution only and changes
  nothing about what the caller is allowed to do.
- The kinds are a closed list owned by Core (`SystemActorKind`). A product
  names its actor with `name`; it cannot add a kind.

Every field is validated at construction, so an invalid actor never reaches
an audit write. The checks are fixed and deterministic, not a secret
scanner: `name` and `initiator_type` are short lower-case identifiers; an
`initiator_id` is a UUID or a short opaque identifier; an initiator type
naming a credential (a link's `token`, a `secret`) and an initiator id in a
known bearer-credential shape (a SaaS OS API key, a JOSE/JWT value) are
refused. The initiator names the *record* that triggered the action (an
outbox event, a provider event, a job id, a link record), never the bearer
value itself.

Pure data, standard library only, like the rest of this package.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass


class InvalidSystemActorError(ValueError):
    """A `SystemActor` field is invalid. Raised at construction, before any
    audit write. The message names the field, never the rejected value
    (which might be a credential handed over by mistake)."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        super().__init__(f"SystemActor.{field} {reason}.")


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


_MAX_LENGTH = 100
_LOWER_IDENTIFIER_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_.:-")
_OPAQUE_IDENTIFIER_CHARACTERS = _LOWER_IDENTIFIER_CHARACTERS | frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
# An initiator *type* names a record kind. One naming a credential means the
# id beside it would be the credential itself (ADR 0061 rule 7: a public
# link's initiator names the link record, never the bearer token).
_CREDENTIAL_WORDS = (
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "bearer",
    "cookie",
    "api_key",
    "apikey",
    "private_key",
    "signing_key",
)
# Known bearer-credential shapes that would otherwise fit the opaque-id
# character set: a SaaS OS API key (`saas_os.core.api_keys`) and a JOSE/JWT
# value (base64url of `{"`).
_CREDENTIAL_PREFIXES = ("sok_", "eyJ")


def _check_identifier(field: str, value: object, allowed: frozenset[str]) -> str:
    if not isinstance(value, str):
        raise InvalidSystemActorError(field, f"must be a str, got {type(value).__name__}")
    if not 1 <= len(value) <= _MAX_LENGTH:
        raise InvalidSystemActorError(field, f"must be 1 to {_MAX_LENGTH} characters")
    if not set(value) <= allowed:
        raise InvalidSystemActorError(field, "contains a character outside the allowed set")
    return value


@dataclass(frozen=True)
class SystemActor:
    """Who or what performed a system action: `kind` (Core-owned),
    `name` (product-chosen, `[a-z0-9_.:-]{1,100}`), and an optional
    initiator reference -- `initiator_type` (`[a-z0-9_.:-]{1,100}`) and
    `initiator_id` (a `uuid.UUID`, or `[A-Za-z0-9_.:-]{1,100}`), given
    together or not at all. Attribution only; never a caller."""

    kind: SystemActorKind
    name: str
    initiator_type: str | None = None
    initiator_id: uuid.UUID | str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SystemActorKind):
            raise InvalidSystemActorError(
                "kind", f"must be a SystemActorKind, got {type(self.kind).__name__}"
            )
        _check_identifier("name", self.name, _LOWER_IDENTIFIER_CHARACTERS)
        if (self.initiator_type is None) != (self.initiator_id is None):
            raise InvalidSystemActorError(
                "initiator_type", "and initiator_id must be given together or not at all"
            )
        if self.initiator_type is None:
            return
        initiator_type = _check_identifier(
            "initiator_type", self.initiator_type, _LOWER_IDENTIFIER_CHARACTERS
        )
        if any(word in initiator_type for word in _CREDENTIAL_WORDS):
            raise InvalidSystemActorError(
                "initiator_type", "must name a record, never a credential"
            )
        if isinstance(self.initiator_id, uuid.UUID):
            return
        initiator_id = _check_identifier(
            "initiator_id", self.initiator_id, _OPAQUE_IDENTIFIER_CHARACTERS
        )
        if initiator_id.startswith(_CREDENTIAL_PREFIXES):
            raise InvalidSystemActorError(
                "initiator_id", "must identify a record, never carry a credential"
            )

    def as_metadata(self) -> dict[str, object]:
        """The fixed audit-metadata shape recorded under `system_actor`."""
        value: dict[str, object] = {"kind": self.kind.value, "name": self.name}
        if self.initiator_type is not None:
            value["initiator_type"] = self.initiator_type
            value["initiator_id"] = str(self.initiator_id)
        return value

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
        return cls(
            kind=SystemActorKind(kind),
            name=getattr(job_actor, "name", None),  # type: ignore[arg-type]
            initiator_type=getattr(job_actor, "initiator_type", None),
            initiator_id=getattr(job_actor, "initiator_id", None),
        )
