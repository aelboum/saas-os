"""The bounded, safe audit-metadata contract (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.4 section 8: "Define and test a safe metadata contract").

Deliberately NOT a generic secret-detection engine (explicitly ruled out
by section 8: "Do not attempt to build a generic secret-detection engine
inside the audit log") -- this is a small, explicit, deterministic set of
checks:

1. JSON-serializable (str/int/float/bool/None/list/dict only -- no
   arbitrary Python objects, no binary blobs).
2. Bounded size once serialized (`_MAX_METADATA_BYTES`) -- this is an
   audit trail, not a request/response payload-capture mechanism.
3. No key, at any nesting depth, matching the explicit denylist below --
   a fixed list of names that are never a legitimate thing to retain
   verbatim in an audit record, not a heuristic or entropy scan.

Validation is a pure function: same input always produces the same
result, no I/O, no randomness (section 8: "deterministic validation").

Separately, `refuse_user_initiators()` is the metadata half of owner
decision D2 (2026-11-02): no new audit record -- tenant or platform --
stores a user initiator under an `initiated_by` key, at any nesting depth.
`trusted_metadata()` (owner decision of 2026-11-03, final closure) is what
both audit writers store: a plain-JSON copy of the caller's metadata in
which every attribution value -- `initiated_by`, `correlation`,
`system_actor`, under any spelling of the key -- has been rebuilt from
exact-type-checked fields through its constructor, or refused.
"""

from __future__ import annotations

import enum
import json
import uuid
from typing import cast

from saas_os.core.audit_log.errors import (
    ForbiddenMetadataKeyError,
    InvalidActorError,
    MetadataNotJSONSerializableError,
    MetadataTooLargeError,
)
from saas_os.core.authority import (
    INITIATOR_UNAVAILABLE,
    Initiator,
    InitiatorType,
    SystemActor,
    SystemActorKind,
    SystemCorrelation,
)

# An audit record retains contextual metadata, not a payload capture --
# 8 KiB is generous for "which fields changed" / "what was requested"
# style context while still bounding pathological input.
MAX_METADATA_BYTES = 8192

# Explicit, fixed denylist (never a generic scanner -- see module
# docstring). Matched case-insensitively against every key at every
# nesting depth. Deliberately broad enough to catch the concrete examples
# docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 8 names by name:
# secrets, bearer tokens, passwords, client secrets, authorization
# headers, cookies.
_FORBIDDEN_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "session_token",
        "id_token",
        "bearer",
        "authorization",
        "auth",
        "cookie",
        "set-cookie",
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "private_key",
        "signing_key",
    }
)


def _check_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str) and key.strip().lower() in _FORBIDDEN_KEYS:
                raise ForbiddenMetadataKeyError(key)
            _check_keys(nested)
    elif isinstance(value, list):
        for item in value:
            _check_keys(item)


# Owner decision D2 (2026-11-02): the initiator types a new audit record
# may store under `initiated_by` -- an allowlist, so a user initiator (and
# any future type) is refused before the insert. Shared by the typed
# `initiated_by=` argument of the tenant writers and the metadata check
# below.
AUDIT_INITIATOR_TYPES = frozenset({InitiatorType.SERVICE_ACCOUNT, InitiatorType.SYSTEM})
INITIATED_BY_KEY = "initiated_by"
CORRELATION_KEY = "correlation"
SYSTEM_ACTOR_KEY = "system_actor"
_USER_INITIATOR_IN_METADATA = (
    'An initiated_by value in audit metadata must be "unavailable" or the recorded '
    "shape of a service-account or system initiator (Initiator.as_metadata()): new "
    "audit records do not store a user id as the initiator (owner decision D2)."
)
_INVALID_CORRELATION_IN_METADATA = (
    "A correlation value in audit metadata must be the recorded shape of a "
    "SystemCorrelation (SystemCorrelation.as_metadata()): only arq_job_id, "
    "outbox_event_id and request_id, none naming a user or other principal "
    "(owner decision D2)."
)
_INVALID_SYSTEM_ACTOR_IN_METADATA = (
    "A system_actor value in audit metadata must be the recorded shape of a "
    "SystemActor (SystemActor.as_metadata()): exactly kind and name (owner decision D2)."
)
# Characters ignored when a key is compared with an attribution key, so
# `initiated_by`, ` Initiated-By `, `initiatedBy` and `INITIATED.BY` are one key.
_KEY_SEPARATORS = str.maketrans("", "", "_-. \t\r\n")
_ATTRIBUTION_KEYS = {
    name.translate(_KEY_SEPARATORS): name
    for name in (INITIATED_BY_KEY, CORRELATION_KEY, SYSTEM_ACTOR_KEY)
}
_CORRELATION_FIELDS = frozenset({"arq_job_id", "outbox_event_id", "request_id"})


def normalized_key(key: object) -> str | None:
    """`key` as compared with a reserved or attribution key: lower case,
    without padding or separators; `None` for a key that is not a `str`.
    The key is first copied to an exact `str`, so a `str` subclass cannot
    change what it compares as."""
    if not isinstance(key, str):
        return None
    return str.__str__(key).lower().translate(_KEY_SEPARATORS)


def attribution_key(key: object) -> str | None:
    """The attribution key (`initiated_by`, `correlation`, `system_actor`)
    that the metadata key `key` spells -- in any case, with any padding or
    separators -- or `None`."""
    normalized = normalized_key(key)
    return None if normalized is None else _ATTRIBUTION_KEYS.get(normalized)


def _plain_strings(value: dict[object, object]) -> bool:
    return all(type(field) is str and type(part) is str for field, part in value.items())


def _rebuilt_initiator_value(value: object) -> object:
    """The value to record under an `initiated_by` key: `None` or exactly
    `"unavailable"` as they are, or a service-account or system initiator's
    shape rebuilt through `Initiator`'s constructor. Anything else -- a user
    shape, an `Initiator` object, a bare id, a list, a shape with an extra
    field or a value of the wrong type in it -- is refused
    (`InvalidActorError`, naming no value)."""
    if value is None:
        return None
    if type(value) is str and value == INITIATOR_UNAVAILABLE:
        return INITIATOR_UNAVAILABLE
    if type(value) is not dict or not _plain_strings(value):
        raise InvalidActorError(_USER_INITIATOR_IN_METADATA)
    try:
        parsed = Initiator.from_metadata(dict(value))
    except (TypeError, ValueError, KeyError) as error:  # InvalidSystemActorError: ValueError
        raise InvalidActorError(_USER_INITIATOR_IN_METADATA) from error
    if parsed is None or parsed.type not in AUDIT_INITIATOR_TYPES:
        raise InvalidActorError(_USER_INITIATOR_IN_METADATA)
    rebuilt = parsed.as_metadata()
    if rebuilt != value:
        raise InvalidActorError(_USER_INITIATOR_IN_METADATA)
    return rebuilt


def _canonical_uuid(value: str) -> uuid.UUID | None:
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value else None


def _rebuilt_correlation_value(value: object) -> object:
    """The value to record under a `correlation` key: `None` as it is, or a
    `SystemCorrelation` shape rebuilt through its constructor (which refuses
    an id naming a user or other principal, or in a credential shape).
    Anything else is refused (`InvalidActorError`, naming no value)."""
    if value is None:
        return None
    if type(value) is not dict or not set(value) <= _CORRELATION_FIELDS:
        raise InvalidActorError(_INVALID_CORRELATION_IN_METADATA)
    if not _plain_strings(value):
        raise InvalidActorError(_INVALID_CORRELATION_IN_METADATA)
    event_id = value.get("outbox_event_id")
    outbox_event_id = None if event_id is None else _canonical_uuid(event_id)
    if event_id is not None and outbox_event_id is None:
        raise InvalidActorError(_INVALID_CORRELATION_IN_METADATA)
    try:
        rebuilt = SystemCorrelation(
            arq_job_id=value.get("arq_job_id"),
            outbox_event_id=outbox_event_id,
            request_id=value.get("request_id"),
        ).as_metadata()
    except ValueError as error:  # InvalidSystemActorError
        raise InvalidActorError(_INVALID_CORRELATION_IN_METADATA) from error
    if rebuilt != value:
        raise InvalidActorError(_INVALID_CORRELATION_IN_METADATA)
    return rebuilt


_ACTOR_KINDS = frozenset(kind.value for kind in SystemActorKind)


def _rebuilt_system_actor_value(value: object) -> object:
    """The value to record under a `system_actor` key: `None` as it is, or
    a `SystemActor` shape rebuilt through its constructor. Anything else is
    refused (`InvalidActorError`, naming no value)."""
    if value is None:
        return None
    if (
        type(value) is not dict
        or set(value) != {"kind", "name"}
        or not _plain_strings(value)
        or value["kind"] not in _ACTOR_KINDS
    ):
        raise InvalidActorError(_INVALID_SYSTEM_ACTOR_IN_METADATA)
    try:
        rebuilt = SystemActor(SystemActorKind(value["kind"]), value["name"]).as_metadata()
    except ValueError as error:  # InvalidSystemActorError
        raise InvalidActorError(_INVALID_SYSTEM_ACTOR_IN_METADATA) from error
    if rebuilt != value:
        raise InvalidActorError(_INVALID_SYSTEM_ACTOR_IN_METADATA)
    return rebuilt


_REBUILDERS = {
    INITIATED_BY_KEY: _rebuilt_initiator_value,
    CORRELATION_KEY: _rebuilt_correlation_value,
    SYSTEM_ACTOR_KEY: _rebuilt_system_actor_value,
}


def refuse_user_initiators(metadata: object) -> None:
    """Owner decision D2 (2026-11-02): raise `InvalidActorError`, before any
    write, when any key spelling `initiated_by` (any case, padding or
    separators -- `attribution_key()` -- at any nesting depth, inside dicts,
    lists and tuples) holds anything but `None`, `"unavailable"` or the
    recorded shape of a service-account or system initiator. A user
    initiator is never converted to `None`: it is refused. The message
    names no id and no key path. Containers already visited are skipped, so
    a self-referencing value terminates here (and is then refused by
    `validate_metadata()` as not JSON-serializable).

    This checks the caller's own objects, so a user initiator is refused as
    such even in metadata that is not JSON-serializable;
    `trusted_metadata()` repeats every check on the plain copy it stores."""
    _check_attribution_values(metadata, frozenset({INITIATED_BY_KEY}))


def _check_attribution_values(metadata: object, names: frozenset[str]) -> None:
    """Run the rebuild check of every attribution key in `names` on the
    caller's own objects (dicts, lists and tuples, at any depth), raising
    `InvalidActorError` on the first value that is not a recorded shape."""
    if metadata is None:
        return
    pending: list[object] = [metadata]
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if not isinstance(value, (dict, list, tuple)) or id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, dict):
            for key, nested in value.items():
                name = attribution_key(key)
                if name is not None and name in names:
                    _REBUILDERS[name](nested)
                    continue
                pending.append(nested)
        else:
            pending.extend(value)


# `uuid.UUID`'s own slot, read past any attribute a subclass or an instance
# defines, so a rebuilt id is the 128-bit value the object really holds.
_UUID_INT = uuid.UUID.__dict__["int"]


def rebuilt_uuid(value: object) -> uuid.UUID:
    """A new `uuid.UUID` holding the 128-bit value of `value` (a
    `uuid.UUID`), so an audit row never stores the caller's own id object;
    `InvalidActorError` otherwise. Used for the actor and correlation ids
    both audit writers record."""
    if not isinstance(value, uuid.UUID):
        raise InvalidActorError("an identity must be a uuid.UUID.")
    try:
        return uuid.UUID(int=_UUID_INT.__get__(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise InvalidActorError("an identity must be a uuid.UUID.") from error


def rebuilt_authority(authority: object, enum_type: type[enum.Enum]) -> str:
    """The value of the `enum_type` member `authority` stands for (a system
    caller's purpose), looked up in the enum itself, never read from the
    object; `InvalidActorError` otherwise. The enum is passed in: only
    reviewed modules may name it (tests/architecture/test_authority_contract.py)."""
    try:
        value = enum_type(authority).value
    except (TypeError, ValueError) as error:
        raise InvalidActorError("a system caller's purpose must be a SystemAuthority.") from error
    if type(value) is not str:
        raise InvalidActorError("a system caller's purpose must be a SystemAuthority.")
    return value


def _rebuild_attribution(value: object) -> object:
    """`value` (plain JSON data) with every attribution value rebuilt."""
    if isinstance(value, dict):
        rebuilt: dict[str, object] = {}
        for key, nested in value.items():
            name = attribution_key(key)
            rebuilt[key] = (
                _rebuild_attribution(nested) if name is None else _REBUILDERS[name](nested)
            )
        return rebuilt
    if isinstance(value, list):
        return [_rebuild_attribution(item) for item in value]
    return value


def trusted_metadata(metadata: dict[str, object] | None) -> dict[str, object] | None:
    """What an audit writer stores for `metadata` (owner decision of
    2026-11-03, final closure): never the caller's own objects.

    1. the attribution checks of step 3 on the caller's own objects (so a
       user initiator, or an identity-carrying correlation, is refused as
       such even in metadata that is not serializable), then
       `validate_metadata()` (serializable, size, denylist);
    2. a plain-JSON copy (`json.loads(json.dumps(...))`): only `dict`,
       `list`, `str`, `int`, `float`, `bool` and `None`, so no subclass,
       tuple or custom object of the caller's survives;
    3. in that copy, the value under every key spelling `initiated_by`,
       `correlation` or `system_actor` (any case, padding or separators, at
       any depth) is rebuilt from its exact-type-checked fields through the
       constructor of `Initiator` (service-account or system only),
       `SystemCorrelation` or `SystemActor`, and must equal its rebuilt
       shape; anything else is refused with `InvalidActorError`, naming no
       value. `None` stays `None`, and `initiated_by` may be exactly
       `"unavailable"`;
    4. `validate_metadata()` again, on the copy that is stored.

    Metadata made only of plain JSON values, whose attribution values are
    already in their recorded shapes, is stored equal to the input and
    serializes to the same bytes."""
    if metadata is None:
        return None
    _check_attribution_values(metadata, frozenset(_REBUILDERS))
    validate_metadata(metadata)
    rebuilt = cast("dict[str, object]", _rebuild_attribution(json.loads(json.dumps(metadata))))
    validate_metadata(rebuilt)
    return rebuilt


def validate_metadata(metadata: dict[str, object] | None) -> None:
    """Raise a typed `InvalidAuditRecordError` subclass if `metadata`
    violates the contract; return `None` (no exception) if it is
    acceptable. `metadata=None` is always acceptable -- not every audit
    event has contextual metadata.
    """
    if metadata is None:
        return

    try:
        serialized = json.dumps(metadata)
    except (TypeError, ValueError) as exc:
        raise MetadataNotJSONSerializableError() from exc

    size = len(serialized.encode("utf-8"))
    if size > MAX_METADATA_BYTES:
        raise MetadataTooLargeError(size, MAX_METADATA_BYTES)

    _check_keys(metadata)
