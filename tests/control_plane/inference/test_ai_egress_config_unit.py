"""Provisional AI egress settings (AI-B decision R3; ADR-0054 section 8a).

The defaults are the documented *candidate* values, configurable and not
final; invalid configuration fails closed.
"""

from __future__ import annotations

import pytest

from saas_os.control_plane.inference.egress_config import (
    CANDIDATE_CONNECT_TIMEOUT_SECONDS,
    CANDIDATE_READ_TIMEOUT_SECONDS,
    CANDIDATE_TOTAL_DEADLINE_SECONDS,
    PROVISIONAL_MAX_RESPONSE_BYTES,
    ai_egress_settings,
)
from saas_os.infra.egress import EgressConfigurationError


def test_defaults_are_the_documented_candidates() -> None:
    assert (
        CANDIDATE_CONNECT_TIMEOUT_SECONDS,
        CANDIDATE_READ_TIMEOUT_SECONDS,
        CANDIDATE_TOTAL_DEADLINE_SECONDS,
    ) == (5.0, 30.0, 120.0)
    settings = ai_egress_settings({})
    assert settings.policy.connect_timeout_seconds == 5.0
    assert settings.policy.read_timeout_seconds == 30.0
    assert settings.total_deadline_seconds == 120.0
    assert settings.policy.max_response_bytes == PROVISIONAL_MAX_RESPONSE_BYTES
    assert settings.policy.allowed_ports == frozenset({443})


def test_values_are_configurable() -> None:
    settings = ai_egress_settings(
        {
            "AI_EGRESS_CONNECT_TIMEOUT_SECONDS": "2",
            "AI_EGRESS_READ_TIMEOUT_SECONDS": "10.5",
            "AI_EGRESS_TOTAL_DEADLINE_SECONDS": "45",
            "AI_EGRESS_MAX_RESPONSE_BYTES": "65536",
        }
    )
    assert settings.policy.connect_timeout_seconds == 2.0
    assert settings.policy.read_timeout_seconds == 10.5
    assert settings.total_deadline_seconds == 45.0
    assert settings.policy.max_response_bytes == 65536


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AI_EGRESS_CONNECT_TIMEOUT_SECONDS", "0"),
        ("AI_EGRESS_CONNECT_TIMEOUT_SECONDS", "-1"),
        ("AI_EGRESS_READ_TIMEOUT_SECONDS", "abc"),
        ("AI_EGRESS_READ_TIMEOUT_SECONDS", "nan"),
        ("AI_EGRESS_TOTAL_DEADLINE_SECONDS", "inf"),
        ("AI_EGRESS_TOTAL_DEADLINE_SECONDS", "999999"),
        ("AI_EGRESS_MAX_RESPONSE_BYTES", "0"),
        ("AI_EGRESS_MAX_RESPONSE_BYTES", "1.5"),
        ("AI_EGRESS_MAX_RESPONSE_BYTES", "999999999999"),
    ],
)
def test_invalid_values_fail_closed(name: str, value: str) -> None:
    with pytest.raises(EgressConfigurationError):
        ai_egress_settings({name: value})


def test_environment_is_read_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_EGRESS_READ_TIMEOUT_SECONDS", "12")
    assert ai_egress_settings().policy.read_timeout_seconds == 12.0
