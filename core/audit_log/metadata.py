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
"""

from __future__ import annotations

import json

from core.audit_log.errors import (
    ForbiddenMetadataKeyError,
    MetadataNotJSONSerializableError,
    MetadataTooLargeError,
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
