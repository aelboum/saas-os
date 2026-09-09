"""P1.11 -- pure unit tests for `core/idempotency`'s key-validation,
fingerprinting, and configuration primitives. No database needed --
`run_idempotent()`/`begin_idempotent_operation()`'s own atomic/concurrency
behavior needs real PostgreSQL and is covered by
`tests/core/idempotency/test_idempotency_integration.py`.
"""

from __future__ import annotations

import uuid

import pytest
from core.idempotency.config import IdempotencyConfig, get_idempotency_config
from core.idempotency.errors import (
    IdempotencyConfigurationError,
    IdempotencyInProgressError,
    IdempotencyKeyInvalidError,
    IdempotencyKeyReusedError,
)
from core.idempotency.service import compute_fingerprint, validate_idempotency_key

# --- validate_idempotency_key() -----------------------------------------


def test_validate_accepts_a_normal_key() -> None:
    validate_idempotency_key("order-2026-09-09-abc123")  # must not raise


def test_validate_rejects_empty_key() -> None:
    with pytest.raises(IdempotencyKeyInvalidError):
        validate_idempotency_key("")


def test_validate_rejects_oversized_key() -> None:
    with pytest.raises(IdempotencyKeyInvalidError):
        validate_idempotency_key("a" * 201)


def test_validate_accepts_key_at_max_length() -> None:
    validate_idempotency_key("a" * 200)  # must not raise


def test_validate_rejects_malformed_key_with_unsafe_characters() -> None:
    for bad_key in ["has spaces", "has/slash", "has\nnewline", "has\ttab", "semi;colon", "quote'"]:
        with pytest.raises(IdempotencyKeyInvalidError):
            validate_idempotency_key(bad_key)


def test_validate_accepts_safe_special_characters() -> None:
    validate_idempotency_key("key.with_safe~chars-123")  # must not raise


# --- compute_fingerprint() ----------------------------------------------


def test_fingerprint_is_deterministic() -> None:
    payload = {"plan_key": "pro", "quantity": "5"}
    assert compute_fingerprint(payload) == compute_fingerprint(payload)


def test_fingerprint_is_independent_of_key_order() -> None:
    a = {"plan_key": "pro", "quantity": "5"}
    b = {"quantity": "5", "plan_key": "pro"}
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_fingerprint_differs_for_different_payloads() -> None:
    assert compute_fingerprint({"plan_key": "pro"}) != compute_fingerprint({"plan_key": "basic"})


def test_fingerprint_is_a_sha256_hex_digest() -> None:
    digest = compute_fingerprint({"x": 1})
    assert len(digest) == 64
    int(digest, 16)  # must be valid hex


# --- Errors carry only identifying metadata -----------------------------


def test_key_reused_error_never_echoes_the_fingerprint_or_payload() -> None:
    tenant_id = uuid.uuid4()
    error = IdempotencyKeyReusedError(tenant_id, "billing.subscribe", "my-key")
    message = str(error)
    assert "my-key" in message  # the key itself is not secret
    assert str(tenant_id) in message
    # No stored fingerprint/result value ever appears -- there is none to leak.


def test_in_progress_error_identifies_the_operation() -> None:
    tenant_id = uuid.uuid4()
    error = IdempotencyInProgressError(tenant_id, "usage.consume_quota", "my-key")
    assert error.operation == "usage.consume_quota"
    assert error.idempotency_key == "my-key"
    assert error.tenant_id == tenant_id


# --- config ---------------------------------------------------------------


def test_default_retention_is_24_hours() -> None:
    assert IdempotencyConfig().retention_seconds == 24 * 60 * 60


def test_default_pending_ttl_is_30_seconds() -> None:
    assert IdempotencyConfig().pending_ttl_seconds == 30


def test_config_rejects_non_positive_retention() -> None:
    with pytest.raises(IdempotencyConfigurationError):
        IdempotencyConfig(retention_seconds=0)


def test_config_rejects_non_positive_pending_ttl() -> None:
    with pytest.raises(IdempotencyConfigurationError):
        IdempotencyConfig(pending_ttl_seconds=0)


def test_missing_env_vars_fall_back_to_safe_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IDEMPOTENCY_RETENTION_SECONDS", raising=False)
    monkeypatch.delenv("IDEMPOTENCY_PENDING_TTL_SECONDS", raising=False)
    get_idempotency_config.cache_clear()
    try:
        config = get_idempotency_config()
        assert config.retention_seconds == 24 * 60 * 60
        assert config.pending_ttl_seconds == 30
    finally:
        get_idempotency_config.cache_clear()


def test_invalid_env_var_raises_rather_than_silently_disabling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IDEMPOTENCY_RETENTION_SECONDS", "not-a-number")
    get_idempotency_config.cache_clear()
    try:
        with pytest.raises(IdempotencyConfigurationError):
            get_idempotency_config()
    finally:
        get_idempotency_config.cache_clear()
