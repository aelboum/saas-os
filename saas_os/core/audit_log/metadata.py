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
Both audit writers call it before `validate_metadata()`.
"""

from __future__ import annotations

import json

from saas_os.core.audit_log.errors import (
    ForbiddenMetadataKeyError,
    InvalidActorError,
    MetadataNotJSONSerializableError,
    MetadataTooLargeError,
)
from saas_os.core.authority import INITIATOR_UNAVAILABLE, Initiator, InitiatorType

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
_USER_INITIATOR_IN_METADATA = (
    'An initiated_by value in audit metadata must be "unavailable" or the recorded '
    "shape of a service-account or system initiator (Initiator.as_metadata()): new "
    "audit records do not store a user id as the initiator (owner decision D2)."
)


def _is_recordable_initiator(value: object) -> bool:
    """Whether `value` may stand under an `initiated_by` key of a new audit
    record: `None` or exactly `"unavailable"`, or exactly the recorded shape
    of a service-account or system initiator. Anything else -- a user
    shape, an `Initiator` object, a bare id, a list, a shape with an extra
    field or a value of the wrong type in it -- is not."""
    if value is None or (isinstance(value, str) and value == INITIATOR_UNAVAILABLE):
        return True
    if not isinstance(value, dict):
        return False
    try:
        parsed = Initiator.from_metadata(value)
    except (TypeError, ValueError, KeyError):  # InvalidSystemActorError is a ValueError
        return False
    return (
        parsed is not None
        and parsed.type in AUDIT_INITIATOR_TYPES
        and parsed.as_metadata() == value
    )


def refuse_user_initiators(metadata: object) -> None:
    """Owner decision D2 (2026-11-02): raise `InvalidActorError`, before any
    write, when any key named `initiated_by` (any case or padding, at any
    nesting depth, inside dicts, lists and tuples) holds anything but `None`,
    `"unavailable"` or the recorded shape of a service-account or system
    initiator. A user initiator is never converted to `None`: it is refused.
    The message names no id and no key path. Containers already visited are
    skipped, so a self-referencing value terminates here (and is then
    refused by `validate_metadata()` as not JSON-serializable)."""
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
                if isinstance(key, str) and key.strip().lower() == INITIATED_BY_KEY:
                    if not _is_recordable_initiator(nested):
                        raise InvalidActorError(_USER_INITIATOR_IN_METADATA)
                    continue
                pending.append(nested)
        else:
            pending.extend(value)


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
