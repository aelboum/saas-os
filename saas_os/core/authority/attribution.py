"""Initiating actor and correlation identity for system actions (ADR 0061,
owner decision C of 2026-11-01).

An audit row for a system action records three distinct things:

- **executing actor** (`metadata["system_actor"]`): the `SystemActor`
  (`saas_os/core/authority/system_actor.py`) -- which job or component ran it;
- **initiating actor** (`metadata["initiated_by"]`): an `Initiator` --
  who or what originally requested it: a user, a service account, or a
  system actor (a schedule, an inbound provider event, a public link). When
  it is genuinely unknown the row says so explicitly, with the string
  `"unavailable"` (`INITIATOR_UNAVAILABLE`); the executing actor is never
  substituted for it, and a user id appears only when a user initiated it;
- **correlation identity** (`metadata["correlation"]`): a
  `SystemCorrelation` -- the arq job id, the outbox event id and the request
  id, each under its own key. An arq job id identifies an execution and
  correlates it; it never replaces the initiator.

All three are attribution only. None is a `Caller`, none is accepted by any
authorization check, and none carries a tenant. Pure data, standard library
plus this package only.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass

from saas_os.core.authority.caller import ServiceAccountCaller, UserCaller, require_caller
from saas_os.core.authority.system_actor import (
    LOWER_IDENTIFIER_CHARACTERS,
    MAX_IDENTIFIER_LENGTH,
    OPAQUE_IDENTIFIER_CHARACTERS,
    InvalidSystemActorError,
    SystemActor,
    SystemActorKind,
    check_identifier,
    embeds_an_id,
)

INITIATOR_UNAVAILABLE = "unavailable"
"""The exact value recorded under `metadata["initiated_by"]` when the
initiating actor is not known (a direct job, an outbox event whose producer
supplied none, an event stored before the initiator was captured)."""

# An initiator's *record type* names a record kind. One naming a credential
# means the id beside it would be the credential itself (ADR 0061 rule 7: a
# public link's initiator names the link record, never the bearer token).
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
# Owner decision D2: a system initiator never carries a user id, so its
# record reference may not name a principal. The rule is closed and works
# on the words of the identifier (split at `_ . : -`): a record type or a
# string record id with a word that names a person or principal -- any
# word starting with `user` (user, users, user_id, userid, username), or
# one of the words below -- is refused, as is an `account` that is not
# qualified by a non-principal word (`account`, `service_account`; a
# `billing_account` or `merchant_account` is a record, not a principal).
# Record types are product-chosen (`provider_event`, `unsubscribe_link`),
# so an allowlist is not possible; a principal initiator is recorded with
# `Initiator.user()` / `Initiator.service_account()` instead.
_PRINCIPAL_WORDS = frozenset(
    {
        "member",
        "members",
        "membership",
        "memberships",
        "principal",
        "principals",
        "operator",
        "operators",
        "person",
        "persons",
        "people",
        "identity",
        "identities",
        "subject",
        "subjects",
        "owner",
        "owners",
        "actor",
        "actors",
    }
)
_WORD_SEPARATORS = str.maketrans("_.:-", "    ")


def _names_a_principal(value: str, *, prefix_only: bool = False) -> bool:
    """Whether `value` names a principal (the rule above). With
    `prefix_only`, only its first word counts: a record id is a prefix and
    an opaque tail (`evt_...`, `user:...`), and a random tail must not be
    read as a word."""
    words = value.lower().translate(_WORD_SEPARATORS).split()
    if prefix_only:
        if words[:2] in (["service", "account"], ["service", "accounts"]):
            return True
        words = words[:1]
    for index, word in enumerate(words):
        if word.startswith("user") or word in _PRINCIPAL_WORDS:
            return True
        if word in {"account", "accounts"} and (index == 0 or words[index - 1] == "service"):
            return True
    return False


_INITIATOR = "Initiator"
_CORRELATION = "SystemCorrelation"
_SYSTEM_FIELDS = frozenset({"type", "kind", "name", "record_type", "record_id"})
_PRINCIPAL_FIELDS = {
    "user": frozenset({"type", "user_id"}),
    "service_account": frozenset({"type", "service_account_id"}),
}
_JOB_INITIATOR_FIELDS = (
    "type",
    "user_id",
    "service_account_id",
    "kind",
    "name",
    "record_type",
    "record_id",
)


def _check_opaque_id(field: str, value: object, owner: str) -> str:
    checked = check_identifier(field, value, OPAQUE_IDENTIFIER_CHARACTERS, owner=owner)
    if checked.startswith(_CREDENTIAL_PREFIXES):
        raise InvalidSystemActorError(
            field, "must identify a record, never carry a credential", owner=owner
        )
    return checked


def _uuid(field: str, value: object) -> uuid.UUID:
    """A recorded principal id: exactly the canonical lowercase hyphenated
    form `as_metadata()` writes (`str(uuid.UUID(...))`). Upper case,
    braces, `urn:uuid:` or a missing hyphen is refused, so one id has one
    stored spelling (user erasure still matches any spelling it finds)."""
    if isinstance(value, str):
        try:
            parsed = uuid.UUID(value)
        except ValueError:
            parsed = None
        if parsed is not None and str(parsed) == value:
            return parsed
    raise InvalidSystemActorError(field, "must be a canonical UUID string", owner=_INITIATOR)


class InitiatorType(enum.StrEnum):
    """The closed, Core-owned list of initiating-actor types."""

    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    SYSTEM = "system"


@dataclass(frozen=True)
class Initiator:
    """Who or what originally requested an action. Build it with
    `Initiator.user()`, `Initiator.service_account()`, `Initiator.system()`
    or `Initiator.from_caller()`; every combination is validated here.

    - `user`: `principal_id` is the user's id; nothing else.
    - `service_account`: `principal_id` is the service account's id.
    - `system`: `system_actor` names the initiating component (a schedule,
      a provider-event processor, a public link) and optionally
      `record_type`/`record_id` name the record that triggered it (a
      provider event, a link record -- never a bearer value). No
      `principal_id`: a system initiator never carries a user id.

    Attribution only: never a caller, never authority."""

    type: InitiatorType
    principal_id: uuid.UUID | None = None
    system_actor: SystemActor | None = None
    record_type: str | None = None
    record_id: uuid.UUID | str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.type, InitiatorType):
            raise InvalidSystemActorError(
                "type",
                f"must be an InitiatorType, got {type(self.type).__name__}",
                owner=_INITIATOR,
            )
        if self.type is InitiatorType.SYSTEM:
            self._check_system()
            return
        if not isinstance(self.principal_id, uuid.UUID):
            raise InvalidSystemActorError(
                "principal_id", f"of a {self.type.value} must be a uuid.UUID", owner=_INITIATOR
            )
        if (
            self.system_actor is not None
            or self.record_type is not None
            or self.record_id is not None
        ):
            raise InvalidSystemActorError(
                "system_actor",
                f"and the record fields must be absent for a {self.type.value}",
                owner=_INITIATOR,
            )

    def _check_system(self) -> None:
        if self.principal_id is not None:
            raise InvalidSystemActorError(
                "principal_id", "must be absent for a system initiator", owner=_INITIATOR
            )
        if type(self.system_actor) is not SystemActor:
            raise InvalidSystemActorError(
                "system_actor", "of a system initiator must be a SystemActor", owner=_INITIATOR
            )
        if (self.record_type is None) != (self.record_id is None):
            raise InvalidSystemActorError(
                "record_type",
                "and record_id must be given together or not at all",
                owner=_INITIATOR,
            )
        if self.record_type is None:
            return
        record_type = check_identifier(
            "record_type", self.record_type, LOWER_IDENTIFIER_CHARACTERS, owner=_INITIATOR
        )
        if any(word in record_type for word in _CREDENTIAL_WORDS):
            raise InvalidSystemActorError(
                "record_type", "must name a record, never a credential", owner=_INITIATOR
            )
        if _names_a_principal(record_type) or embeds_an_id(record_type):
            raise InvalidSystemActorError(
                "record_type",
                "must name a record, never a user or other principal (owner decision D2)",
                owner=_INITIATOR,
            )
        if not isinstance(self.record_id, uuid.UUID):
            record_id = _check_opaque_id("record_id", self.record_id, _INITIATOR)
            if _names_a_principal(record_id, prefix_only=True):
                raise InvalidSystemActorError(
                    "record_id",
                    "must identify a record, never a user or other principal (owner decision D2)",
                    owner=_INITIATOR,
                )

    @classmethod
    def user(cls, user_id: uuid.UUID) -> Initiator:
        """A user who requested the action themselves."""
        return cls(InitiatorType.USER, principal_id=user_id)

    @classmethod
    def service_account(cls, service_account_id: uuid.UUID) -> Initiator:
        """A service account that requested the action."""
        return cls(InitiatorType.SERVICE_ACCOUNT, principal_id=service_account_id)

    @classmethod
    def system(
        cls,
        actor: SystemActor,
        *,
        record_type: str | None = None,
        record_id: uuid.UUID | str | None = None,
    ) -> Initiator:
        """A system actor that originated the action (a schedule, an inbound
        provider event, a public link), optionally with the record that
        triggered it."""
        return cls(
            InitiatorType.SYSTEM, system_actor=actor, record_type=record_type, record_id=record_id
        )

    @classmethod
    def from_caller(cls, caller: object) -> Initiator | None:
        """The initiator a typed caller stands for: a `UserCaller` is that
        user, a `ServiceAccountCaller` that service account, and a
        `SystemCaller` its attached `SystemActor` -- or `None`
        (unavailable) when it carries none: a purpose names an authority,
        not an initiator. Anything that is not a caller (including a bare
        `SystemActor`) fails closed with `CallerTypeError`."""
        require_caller("Initiator.from_caller", caller)
        if isinstance(caller, UserCaller):
            return cls.user(caller.user_id)
        if isinstance(caller, ServiceAccountCaller):
            return cls.service_account(caller.service_account_id)
        # The remaining caller type is a `SystemCaller` (not imported here:
        # only reviewed modules may name a system purpose).
        actor = getattr(caller, "actor", None)
        return None if actor is None else cls.system(actor)

    def as_metadata(self) -> dict[str, object]:
        """The fixed shape recorded under `initiated_by` (and stored with an
        outbox event): `{"type": "user", "user_id": ...}`,
        `{"type": "service_account", "service_account_id": ...}` or
        `{"type": "system", "kind": ..., "name": ...[, "record_type": ...,
        "record_id": ...]}`."""
        if self.type is InitiatorType.USER:
            return {"type": self.type.value, "user_id": str(self.principal_id)}
        if self.type is InitiatorType.SERVICE_ACCOUNT:
            return {"type": self.type.value, "service_account_id": str(self.principal_id)}
        assert self.system_actor is not None
        value: dict[str, object] = {"type": self.type.value, **self.system_actor.as_metadata()}
        if self.record_type is not None:
            value["record_type"] = self.record_type
            value["record_id"] = str(self.record_id)
        return value

    @classmethod
    def from_metadata(cls, value: object) -> Initiator | None:
        """Parse the shape `as_metadata()` writes. `None` or
        `INITIATOR_UNAVAILABLE` is `None` (unavailable); anything else that
        is not exactly a valid shape -- including a value of the wrong JSON
        type anywhere in it -- fails closed with `InvalidSystemActorError`,
        never another exception."""
        if value is None or value == INITIATOR_UNAVAILABLE:
            return None
        if not isinstance(value, dict):
            raise InvalidSystemActorError("type", "must be a recorded initiator", owner=_INITIATOR)
        kind = value.get("type")
        if not isinstance(kind, str):
            raise InvalidSystemActorError("type", "must be a str", owner=_INITIATOR)
        if kind in _PRINCIPAL_FIELDS:
            if frozenset(value) != _PRINCIPAL_FIELDS[kind]:
                raise InvalidSystemActorError("type", "has unexpected fields", owner=_INITIATOR)
            if kind == InitiatorType.USER.value:
                return cls.user(_uuid("user_id", value["user_id"]))
            return cls.service_account(_uuid("service_account_id", value["service_account_id"]))
        if kind != InitiatorType.SYSTEM.value:
            raise InvalidSystemActorError("type", "is not a known initiator type", owner=_INITIATOR)
        if not {"type", "kind", "name"} <= set(value) <= _SYSTEM_FIELDS:
            raise InvalidSystemActorError("type", "has unexpected fields", owner=_INITIATOR)
        actor_kind = value["kind"]
        if not isinstance(actor_kind, str) or actor_kind not in {k.value for k in SystemActorKind}:
            raise InvalidSystemActorError("kind", "is not a SystemActorKind", owner=_INITIATOR)
        return cls.system(
            SystemActor(SystemActorKind(actor_kind), value["name"]),
            record_type=value.get("record_type"),
            record_id=value.get("record_id"),
        )

    @classmethod
    def from_job_initiator(cls, job_initiator: object) -> Initiator | None:
        """Convert the plain-data initiator a job context carries
        (`TenantJobContext.initiated_by`, set by the outbox dispatcher from
        the stored event) into a validated `Initiator`. `None` stays `None`
        (unavailable); an invalid value fails closed."""
        if job_initiator is None:
            return None
        return cls.from_metadata(
            {
                name: getattr(job_initiator, name)
                for name in _JOB_INITIATOR_FIELDS
                if getattr(job_initiator, name, None) is not None
            }
        )


@dataclass(frozen=True)
class SystemCorrelation:
    """The correlation identity of a system action, each part under its own
    key: `arq_job_id` (the executing job's arq id), `outbox_event_id` (the
    stable outbox event id) and `request_id` (the originating request's
    correlation id). Every part is optional; none is an actor. Ids are
    `[A-Za-z0-9_.:-]{1,100}` (an outbox event id is a UUID), never in a
    known credential shape, and -- owner decision D2, final closure of
    2026-11-03 -- never naming a principal: the record-id rule of a system
    initiator applies, so an id whose first word names a user or other
    principal (`user:...`, `user_<uuid>`, `member-...`,
    `service_account:...`) is refused. A bare UUID or 32 hex digits (an arq
    job id, a generated request id) names no principal and is accepted."""

    arq_job_id: str | None = None
    outbox_event_id: uuid.UUID | None = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        if self.arq_job_id is not None:
            _check_correlation_id("arq_job_id", self.arq_job_id)
        if self.request_id is not None:
            _check_correlation_id("request_id", self.request_id)
        if self.outbox_event_id is not None and not isinstance(self.outbox_event_id, uuid.UUID):
            raise InvalidSystemActorError(
                "outbox_event_id", "must be a uuid.UUID", owner=_CORRELATION
            )

    def as_metadata(self) -> dict[str, object]:
        """The shape recorded under `correlation`: only the parts present."""
        value: dict[str, object] = {}
        if self.arq_job_id is not None:
            value["arq_job_id"] = self.arq_job_id
        if self.outbox_event_id is not None:
            value["outbox_event_id"] = str(self.outbox_event_id)
        if self.request_id is not None:
            value["request_id"] = self.request_id
        return value

    @classmethod
    def from_job_context(cls, context: object) -> SystemCorrelation:
        """The correlation of a job execution: its arq job id
        (`context.job_id`), its outbox event id (`context.event_id`, set
        only for an outbox consumer) and its request correlation id
        (`context.correlation_id`). A job or request id that is not a valid
        correlation value (a caller-chosen correlation id over 100
        characters, outside the character set, in a credential shape, or
        naming a principal) is left out rather than failing the action; the
        audit row's own `correlation_id` column is unaffected."""
        event_id = getattr(context, "event_id", None)
        return cls(
            arq_job_id=_valid_correlation(getattr(context, "job_id", None)),
            outbox_event_id=event_id if isinstance(event_id, uuid.UUID) else None,
            request_id=_valid_correlation(getattr(context, "correlation_id", None)),
        )


def _check_correlation_id(field: str, value: object) -> str:
    checked = _check_opaque_id(field, value, _CORRELATION)
    if _names_a_principal(checked, prefix_only=True):
        raise InvalidSystemActorError(
            field,
            "must correlate an execution, never name a user or other principal (owner decision D2)",
            owner=_CORRELATION,
        )
    return checked


def _valid_correlation(value: object) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_IDENTIFIER_LENGTH:
        return None
    try:
        return _check_correlation_id("id", value)
    except InvalidSystemActorError:
        return None
