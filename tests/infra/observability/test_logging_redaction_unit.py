"""S-03 (BANK-SEC-01/04) -- proves `saas_os.infra.observability.logging`'s
`JsonFormatter` actually applies the redaction boundary before JSON
serialization, using the exact `captured_logs`/`configure_logging`
pattern `test_logging.py` already establishes. Canary values follow
BANK-SEC-04's own naming convention -- synthetic, unmistakable, never
real credentials.
"""

from __future__ import annotations

import json
import logging

import pytest

from saas_os.infra.observability.config import ObservabilityConfig
from saas_os.infra.observability.logging import configure_logging

_CANARY_ACCESS_TOKEN = "BANKSEC_CANARY_ACCESS_TOKEN_12345"
_CANARY_REFRESH_SECRET = "BANKSEC_CANARY_REFRESH_SECRET_67890"


@pytest.fixture
def captured_logs(capsys: pytest.CaptureFixture[str]):
    def _get() -> list[dict[str, object]]:
        out = capsys.readouterr().out
        return [json.loads(line) for line in out.strip().splitlines() if line.strip()]

    return _get


def _raw_stdout(capsys: pytest.CaptureFixture[str]) -> str:
    return capsys.readouterr().out


def test_top_level_sensitive_extra_field_is_redacted(captured_logs) -> None:  # noqa: ANN001
    configure_logging(ObservabilityConfig(log_level="INFO"))

    # `account_id`, not `user_id`/`tenant_id`: those are reserved fields
    # `CorrelationFilter` always populates from the correlation context,
    # not from `extra=` -- unrelated to redaction, just a naming clash to
    # avoid here.
    logging.getLogger("probe").info(
        "token issued", extra={"access_token": _CANARY_ACCESS_TOKEN, "account_id": "acct-1"}
    )

    record = captured_logs()[0]
    assert record["access_token"] == "[REDACTED]"
    assert record["account_id"] == "acct-1"


def test_nested_sensitive_value_in_extra_is_redacted(captured_logs) -> None:  # noqa: ANN001
    configure_logging(ObservabilityConfig(log_level="INFO"))

    logging.getLogger("probe").info(
        "provider call",
        extra={
            "provider": "example",
            "request": {
                "headers": {"Authorization": f"Bearer {_CANARY_ACCESS_TOKEN}"},
                "body": {"refresh_token": _CANARY_REFRESH_SECRET},
            },
        },
    )

    record = captured_logs()[0]
    assert record["request"]["headers"]["Authorization"] == "Bearer [REDACTED]"
    assert record["request"]["body"]["refresh_token"] == "[REDACTED]"
    assert record["provider"] == "example"


def test_canary_secrets_never_appear_anywhere_in_captured_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The security-regression canary test: search the *raw* captured
    stdout text (not just the parsed field this module knows to check),
    proving the canary values do not leak through any other field of the
    same JSON line either."""
    configure_logging(ObservabilityConfig(log_level="INFO"))

    logging.getLogger("probe").info(
        "token pair issued",
        extra={
            "access_token": _CANARY_ACCESS_TOKEN,
            "refresh_token": _CANARY_REFRESH_SECRET,
            "nested": {"client_secret": _CANARY_ACCESS_TOKEN + "-nested"},
            "list_field": [{"api_key": _CANARY_REFRESH_SECRET + "-in-list"}],
        },
    )

    raw = _raw_stdout(capsys)
    assert _CANARY_ACCESS_TOKEN not in raw
    assert _CANARY_REFRESH_SECRET not in raw
    assert (_CANARY_ACCESS_TOKEN + "-nested") not in raw
    assert (_CANARY_REFRESH_SECRET + "-in-list") not in raw


def test_ordinary_extra_fields_remain_useful_after_redaction(captured_logs) -> None:  # noqa: ANN001
    """Redaction must not gut the log record's usefulness -- non-sensitive
    context remains fully present and correct."""
    configure_logging(ObservabilityConfig(log_level="INFO"))

    logging.getLogger("probe").info(
        "webhook delivered",
        extra={
            "subscription_id": "sub-1",
            "provider": "stripe",
            "status": "success",
            "attempt": 1,
            "access_token": _CANARY_ACCESS_TOKEN,
        },
    )

    record = captured_logs()[0]
    assert record["subscription_id"] == "sub-1"
    assert record["provider"] == "stripe"
    assert record["status"] == "success"
    assert record["attempt"] == 1
    assert record["access_token"] == "[REDACTED]"


def test_message_string_interpolation_is_an_explicitly_uncovered_path(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Documents the boundary's known limitation rather than silently
    leaving it untested: a secret interpolated directly into the message
    string (not passed via `extra=`) is NOT scrubbed -- this is why
    developer guidance (the ADR, and this module's own docstring) says to
    pass sensitive-shaped context through `extra=` keys, never string
    interpolation. This test exists so the limitation is enforced by a
    failing assertion if anyone ever changes this without updating the
    documentation, not left as an undocumented assumption."""
    configure_logging(ObservabilityConfig(log_level="INFO"))

    logging.getLogger("probe").info("token=%s", _CANARY_ACCESS_TOKEN)

    raw = _raw_stdout(capsys)
    assert _CANARY_ACCESS_TOKEN in raw  # known, documented, uncovered path
