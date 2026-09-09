"""P1.10 -- pure unit tests for the timestamp/signature verification
primitives: `compute_signed_envelope()`, `verify_webhook_signature()`,
and `core.webhooks.config`. No database or network needed -- the atomic
replay-ledger mechanism itself (`record_webhook_delivery()`) needs a real
PostgreSQL instance and is covered by
`tests/core/webhooks/test_replay_protection_integration.py`.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta

import pytest
from core.webhooks.config import WebhookSecurityConfig, get_webhook_security_config
from core.webhooks.errors import (
    WebhookConfigurationError,
    WebhookSignatureInvalidError,
    WebhookTimestampInvalidError,
)
from core.webhooks.service import (
    compute_signature,
    compute_signed_envelope,
    verify_webhook_signature,
)

_SECRET = "a-test-signing-secret"
_BODY = b'{"event_id":"abc","event_type":"test.event","data":{"x":1}}'


# --- compute_signed_envelope() ------------------------------------------


def test_compute_signed_envelope_matches_independently_computed_hmac() -> None:
    timestamp = 1_700_000_000
    signed_bytes = f"{timestamp}".encode("ascii") + b"." + _BODY
    expected = hmac.new(_SECRET.encode("utf-8"), signed_bytes, hashlib.sha256).hexdigest()
    assert compute_signed_envelope(_SECRET, _BODY, timestamp) == f"sha256={expected}"


def test_compute_signed_envelope_differs_from_plain_compute_signature() -> None:
    """The whole point of the envelope: signing the body alone must never
    equal signing timestamp+body -- otherwise the timestamp would carry
    no cryptographic weight and could be forged freely."""
    timestamp = 1_700_000_000
    assert compute_signed_envelope(_SECRET, _BODY, timestamp) != compute_signature(_SECRET, _BODY)


def test_compute_signed_envelope_differs_for_different_timestamps() -> None:
    assert compute_signed_envelope(_SECRET, _BODY, 1_700_000_000) != compute_signed_envelope(
        _SECRET, _BODY, 1_700_000_001
    )


def test_compute_signed_envelope_is_deterministic() -> None:
    timestamp = 1_700_000_000
    assert compute_signed_envelope(_SECRET, _BODY, timestamp) == compute_signed_envelope(
        _SECRET, _BODY, timestamp
    )


# --- verify_webhook_signature(): happy path -----------------------------


def test_verify_accepts_a_fresh_valid_signature() -> None:
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    signature = compute_signed_envelope(_SECRET, _BODY, timestamp)
    verify_webhook_signature(_SECRET, _BODY, timestamp, signature, now=now)  # must not raise


def test_verify_accepts_a_signature_within_tolerance_boundary() -> None:
    now = datetime.now(UTC)
    delivery_time = now - timedelta(seconds=250)  # within the 300s default
    timestamp = int(delivery_time.timestamp())
    signature = compute_signed_envelope(_SECRET, _BODY, timestamp)
    verify_webhook_signature(_SECRET, _BODY, timestamp, signature, now=now)


# --- verify_webhook_signature(): timestamp rejection --------------------


def test_verify_rejects_a_stale_timestamp() -> None:
    now = datetime.now(UTC)
    delivery_time = now - timedelta(seconds=301)  # just past the 300s default
    timestamp = int(delivery_time.timestamp())
    signature = compute_signed_envelope(_SECRET, _BODY, timestamp)
    with pytest.raises(WebhookTimestampInvalidError):
        verify_webhook_signature(_SECRET, _BODY, timestamp, signature, now=now)


def test_verify_rejects_a_far_future_timestamp() -> None:
    now = datetime.now(UTC)
    delivery_time = now + timedelta(seconds=301)
    timestamp = int(delivery_time.timestamp())
    signature = compute_signed_envelope(_SECRET, _BODY, timestamp)
    with pytest.raises(WebhookTimestampInvalidError):
        verify_webhook_signature(_SECRET, _BODY, timestamp, signature, now=now)


def test_verify_uses_configurable_tolerance() -> None:
    now = datetime.now(UTC)
    delivery_time = now - timedelta(seconds=30)
    timestamp = int(delivery_time.timestamp())
    signature = compute_signed_envelope(_SECRET, _BODY, timestamp)
    with pytest.raises(WebhookTimestampInvalidError):
        verify_webhook_signature(
            _SECRET, _BODY, timestamp, signature, tolerance_seconds=10, now=now
        )
    verify_webhook_signature(_SECRET, _BODY, timestamp, signature, tolerance_seconds=60, now=now)


def test_verify_rejects_an_unparseable_timestamp() -> None:
    now = datetime.now(UTC)
    with pytest.raises(WebhookTimestampInvalidError):
        verify_webhook_signature(_SECRET, _BODY, 99_999_999_999_999_999, "sha256=whatever", now=now)


def test_stale_timestamp_is_rejected_before_the_signature_is_even_checked() -> None:
    """Ordering requirement: timestamp is validated before signature --
    proven here by an intentionally garbage signature that would also
    fail signature verification, confirming the timestamp error (not a
    signature error) is what's actually raised for a stale+bad-signature
    request."""
    now = datetime.now(UTC)
    delivery_time = now - timedelta(seconds=999)
    timestamp = int(delivery_time.timestamp())
    with pytest.raises(WebhookTimestampInvalidError):
        verify_webhook_signature(
            _SECRET, _BODY, timestamp, "sha256=not-even-hex-of-right-length", now=now
        )


# --- verify_webhook_signature(): signature rejection ---------------------


def test_verify_rejects_an_invalid_signature() -> None:
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    with pytest.raises(WebhookSignatureInvalidError):
        verify_webhook_signature(_SECRET, _BODY, timestamp, "sha256=0" * 64, now=now)


def test_verify_rejects_a_signature_computed_with_the_wrong_secret() -> None:
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    wrong_signature = compute_signed_envelope("a-different-secret", _BODY, timestamp)
    with pytest.raises(WebhookSignatureInvalidError):
        verify_webhook_signature(_SECRET, _BODY, timestamp, wrong_signature, now=now)


def test_verify_rejects_an_altered_payload() -> None:
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    signature = compute_signed_envelope(_SECRET, _BODY, timestamp)
    altered_body = _BODY.replace(b'"x":1', b'"x":2')
    with pytest.raises(WebhookSignatureInvalidError):
        verify_webhook_signature(_SECRET, altered_body, timestamp, signature, now=now)


def test_verify_rejects_a_signature_computed_over_the_body_alone() -> None:
    """A signature computed the OLD (pre-P1.10) payload-only way must not
    verify against the new envelope scheme -- proves the protocol
    transition is real, not merely additive."""
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    old_style_signature = compute_signature(_SECRET, _BODY)
    with pytest.raises(WebhookSignatureInvalidError):
        verify_webhook_signature(_SECRET, _BODY, timestamp, old_style_signature, now=now)


def test_timestamp_and_signature_errors_are_distinguishable() -> None:
    now = datetime.now(UTC)
    stale_timestamp = int((now - timedelta(seconds=999)).timestamp())
    fresh_timestamp = int(now.timestamp())

    with pytest.raises(WebhookTimestampInvalidError) as timestamp_exc:
        verify_webhook_signature(_SECRET, _BODY, stale_timestamp, "sha256=" + "0" * 64, now=now)

    with pytest.raises(WebhookSignatureInvalidError) as signature_exc:
        verify_webhook_signature(_SECRET, _BODY, fresh_timestamp, "sha256=" + "0" * 64, now=now)

    assert type(timestamp_exc.value) is not type(signature_exc.value)
    assert str(timestamp_exc.value) != str(signature_exc.value)


def test_verify_uses_constant_time_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    """`hmac.compare_digest` is used, never `==` -- proven indirectly:
    monkeypatching it out with a call-recording wrapper shows it is
    actually invoked on the verification path."""
    calls: list[tuple[object, object]] = []
    original = hmac.compare_digest

    def _recording_compare(a: object, b: object) -> bool:
        calls.append((a, b))
        return original(a, b)  # type: ignore[arg-type]

    monkeypatch.setattr(hmac, "compare_digest", _recording_compare)

    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    signature = compute_signed_envelope(_SECRET, _BODY, timestamp)
    verify_webhook_signature(_SECRET, _BODY, timestamp, signature, now=now)

    assert calls, "verify_webhook_signature must call hmac.compare_digest"


# --- config ---------------------------------------------------------------


def test_default_tolerance_is_five_minutes() -> None:
    assert WebhookSecurityConfig().tolerance_seconds == 300


def test_config_rejects_non_positive_tolerance() -> None:
    with pytest.raises(WebhookConfigurationError):
        WebhookSecurityConfig(tolerance_seconds=0)


def test_missing_env_var_falls_back_to_the_safe_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay protection must never be silently disabled by absent
    configuration -- a missing env var must resolve to the conservative
    default, never to 'no check'."""
    monkeypatch.delenv("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", raising=False)
    get_webhook_security_config.cache_clear()
    try:
        config = get_webhook_security_config()
        assert config.tolerance_seconds == 300
    finally:
        get_webhook_security_config.cache_clear()


def test_env_var_overrides_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", "60")
    get_webhook_security_config.cache_clear()
    try:
        assert get_webhook_security_config().tolerance_seconds == 60
    finally:
        get_webhook_security_config.cache_clear()


def test_invalid_env_var_raises_rather_than_silently_disabling_protection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", "not-a-number")
    get_webhook_security_config.cache_clear()
    try:
        with pytest.raises(WebhookConfigurationError):
            get_webhook_security_config()
    finally:
        get_webhook_security_config.cache_clear()
