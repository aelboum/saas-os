"""S-03 (BANK-SEC-01/04) -- `saas_os.infra.observability.redaction`: the generic
sensitive-value redaction primitive, tested standalone (no logging
configuration involved -- see `test_logging_redaction_unit.py` for the
wired-in `JsonFormatter` behavior)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from saas_os.infra.observability.redaction import (
    REDACTED,
    is_sensitive_key,
    redact,
    safe_exception_type,
)


def _dict(value: object) -> dict[str, Any]:
    """`redact()`'s return type is `object` (it recurses through
    heterogeneous structures) -- this narrows a known-dict test result
    for indexing, without loosening the production function's honest
    signature."""
    assert isinstance(value, dict)
    return cast("dict[str, Any]", value)


# --- basic key redaction -----------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "authorization",
        "client_secret",
        "credential",
        "credentials",
        "private_key",
    ],
)
def test_sensitive_keys_are_redacted(key: str) -> None:
    result = redact({key: "should-not-survive"})

    assert result == {key: REDACTED}


@pytest.mark.parametrize(
    "key",
    [
        "user_id",
        "tenant_id",
        "provider",
        "operation",
        "status",
        "http_method",
        "http_path",
        "amount",
        "currency",
        "email",  # deliberately NOT in the denylist -- see module docstring
    ],
)
def test_ordinary_keys_are_not_redacted(key: str) -> None:
    result = redact({key: "ordinary-value"})

    assert result == {key: "ordinary-value"}


def test_password_hint_is_not_redacted_no_substring_matching() -> None:
    """`password_hint` must not be caught by the `password` denylist entry
    -- exact match on the normalized key only, never a substring rule."""
    result = redact({"password_hint": "my first pet"})

    assert result == {"password_hint": "my first pet"}


@pytest.mark.parametrize(
    "key",
    ["token_count", "secretary_name", "credential_type"],
)
def test_compound_words_containing_a_denylist_substring_are_not_redacted(key: str) -> None:
    """`token_count`/`secretary_name`/`credential_type` must not match
    `token`/`secret`/`credential` -- normalization is exact-match, never
    substring, even where the denylist word appears as a whole component
    of a longer compound key."""
    result = redact({key: "ordinary-value"})

    assert result == {key: "ordinary-value"}


# --- case / separator variation ----------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["access_token", "AccessToken", "ACCESS_TOKEN", "Access-Token", "accessToken"],
)
def test_case_and_separator_variants_are_all_recognized(key: str) -> None:
    assert is_sensitive_key(key)
    assert redact({key: "secret-value"}) == {key: REDACTED}


def test_client_secret_camel_case_variant_is_recognized() -> None:
    assert is_sensitive_key("clientSecret")
    assert redact({"clientSecret": "x"}) == {"clientSecret": REDACTED}


# --- nested dictionaries ------------------------------------------------------


def test_nested_dict_sensitive_value_is_redacted() -> None:
    payload = {
        "provider": "example",
        "request": {
            "headers": {"Authorization": "Bearer secret-token"},
            "body": {"refresh_token": "secret-refresh-token"},
        },
    }

    result = _dict(redact(payload))

    assert result["provider"] == "example"
    assert result["request"]["headers"]["Authorization"] == "Bearer [REDACTED]"
    assert result["request"]["body"]["refresh_token"] == REDACTED


def test_deeply_nested_sensitive_value_is_redacted() -> None:
    payload = {"a": {"b": {"c": {"d": {"api_key": "deep-secret"}}}}}

    result = _dict(redact(payload))

    assert result["a"]["b"]["c"]["d"]["api_key"] == REDACTED


def test_depth_limit_fails_safe_not_open() -> None:
    """Security-critical: past `_MAX_REDACTION_DEPTH`, an unexamined
    dict/list must NOT be returned verbatim (which would silently defeat
    the whole boundary for pathologically deep input containing a secret
    below the limit) -- it must be replaced with a truncation marker."""
    canary = "BANKSEC_CANARY_DEEP_SECRET_99999"
    payload: dict[str, object] = {"api_key": canary}
    for _ in range(15):  # deeper than _MAX_REDACTION_DEPTH (10)
        payload = {"nested": payload}

    result = redact(payload)

    assert canary not in str(result)


# --- lists ---------------------------------------------------------------------


def test_list_of_dicts_with_sensitive_values_is_redacted() -> None:
    payload = {"accounts": [{"id": "1", "token": "t1"}, {"id": "2", "token": "t2"}]}

    result = _dict(redact(payload))

    assert result["accounts"][0] == {"id": "1", "token": REDACTED}
    assert result["accounts"][1] == {"id": "2", "token": REDACTED}


def test_tuple_is_handled_like_a_list() -> None:
    payload = {"pair": ({"secret": "x"}, {"id": "y"})}

    result = _dict(redact(payload))

    assert result["pair"][0] == {"secret": REDACTED}
    assert result["pair"][1] == {"id": "y"}


# --- headers -------------------------------------------------------------------


@pytest.mark.parametrize(
    "header_name",
    ["Authorization", "authorization", "Cookie", "cookie", "Set-Cookie", "X-API-Key", "x-api-key"],
)
def test_sensitive_headers_are_redacted_case_insensitively(header_name: str) -> None:
    assert is_sensitive_key(header_name)


def test_authorization_header_preserves_scheme_not_credential() -> None:
    result = _dict(redact({"Authorization": "Bearer super-secret-canary-token"}))

    assert result["Authorization"] == "Bearer [REDACTED]"
    assert "super-secret-canary-token" not in str(result)


def test_authorization_header_without_recognizable_scheme_is_fully_redacted() -> None:
    result = _dict(redact({"Authorization": "opaque-blob-no-scheme"}))

    assert result["Authorization"] == REDACTED


# --- safe values / false positives --------------------------------------------


def test_representative_safe_payload_is_unchanged() -> None:
    payload = {
        "user_id": "123",
        "provider": "stripe",
        "operation": "token_refresh",  # "token" only inside the value -- key itself is "operation"
        "status": "success",
    }

    assert redact(payload) == payload


# --- no mutation -----------------------------------------------------------


def test_redact_does_not_mutate_the_original_dict() -> None:
    original = {"token": "secret", "nested": {"password": "hunter2"}}
    original_copy = {"token": "secret", "nested": {"password": "hunter2"}}

    redact(original)

    assert original == original_copy


def test_redact_does_not_mutate_the_original_list() -> None:
    original = [{"secret": "x"}]

    redact(original)

    assert original == [{"secret": "x"}]


# --- safe_exception_type -------------------------------------------------------


def test_safe_exception_type_returns_type_name_only() -> None:
    exc = ValueError("contains a secret: sk_live_deadbeef")

    result = safe_exception_type(exc)

    assert result == "ValueError"
    assert "deadbeef" not in result
    assert "secret" not in result
