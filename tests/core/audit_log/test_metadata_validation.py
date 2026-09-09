"""Audit-metadata contract tests (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4
section 8). Pure unit tests -- no database.
"""

from __future__ import annotations

import pytest
from core.audit_log.errors import (
    ForbiddenMetadataKeyError,
    MetadataNotJSONSerializableError,
    MetadataTooLargeError,
)
from core.audit_log.metadata import MAX_METADATA_BYTES, validate_metadata


def test_none_metadata_is_valid() -> None:
    validate_metadata(None)  # must not raise


def test_simple_json_serializable_metadata_is_valid() -> None:
    validate_metadata({"changed_fields": ["name", "status"], "count": 2, "ok": True})


def test_nested_metadata_is_valid_if_no_forbidden_key_appears() -> None:
    validate_metadata({"before": {"name": "old"}, "after": {"name": "new"}})


def test_metadata_with_non_json_serializable_value_is_rejected() -> None:
    class Unserializable:
        pass

    with pytest.raises(MetadataNotJSONSerializableError):
        validate_metadata({"thing": Unserializable()})


def test_metadata_exceeding_size_limit_is_rejected() -> None:
    oversized: dict[str, object] = {"blob": "x" * (MAX_METADATA_BYTES + 1)}
    with pytest.raises(MetadataTooLargeError) as excinfo:
        validate_metadata(oversized)
    assert excinfo.value.limit_bytes == MAX_METADATA_BYTES
    assert excinfo.value.size_bytes > MAX_METADATA_BYTES


def test_metadata_at_exactly_the_limit_is_valid() -> None:
    # Construct a payload whose serialized form is exactly at the limit.
    import json

    overhead = len(json.dumps({"blob": ""}))
    payload: dict[str, object] = {"blob": "x" * (MAX_METADATA_BYTES - overhead)}
    assert len(json.dumps(payload).encode("utf-8")) == MAX_METADATA_BYTES
    validate_metadata(payload)  # must not raise


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "PASSWORD",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "bearer",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "private_key",
    ],
)
def test_forbidden_top_level_key_is_rejected(key: str) -> None:
    with pytest.raises(ForbiddenMetadataKeyError) as excinfo:
        validate_metadata({key: "whatever-value"})
    assert excinfo.value.key == key


def test_forbidden_key_never_appears_in_the_exception_message() -> None:
    """The rejected *value* must never leak into the error -- only the key
    name (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 8)."""
    with pytest.raises(ForbiddenMetadataKeyError) as excinfo:
        validate_metadata({"password": "hunter2-super-secret-value"})
    assert "hunter2-super-secret-value" not in str(excinfo.value)


def test_forbidden_key_nested_inside_a_dict_is_rejected() -> None:
    with pytest.raises(ForbiddenMetadataKeyError) as excinfo:
        validate_metadata({"request": {"headers": {"Authorization": "Bearer xyz"}}})
    assert excinfo.value.key.lower() == "authorization"


def test_forbidden_key_nested_inside_a_list_of_dicts_is_rejected() -> None:
    with pytest.raises(ForbiddenMetadataKeyError):
        validate_metadata({"items": [{"name": "ok"}, {"secret": "nope"}]})


def test_safe_keys_that_merely_contain_a_forbidden_substring_are_allowed() -> None:
    """The denylist matches whole keys, not substrings -- "password_policy"
    is a legitimate, non-sensitive key name (e.g. describing which policy
    was applied), not a credential."""
    validate_metadata({"password_policy": "min-length-12"})


def test_validate_metadata_is_deterministic() -> None:
    payload = {"a": 1, "b": [1, 2, 3], "c": {"d": "e"}}
    validate_metadata(payload)
    validate_metadata(payload)  # calling twice must behave identically
