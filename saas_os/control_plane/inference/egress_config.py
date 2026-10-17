"""Provisional egress settings for AI provider calls (AI-B decision R3).

The timeout values are the **candidates** recorded in ADR-0054 section 8a, used
as configurable provisional defaults. They are not approved production values:
final values are decided and validated before Phase AI-D (ADR-0054 Q3).
Streaming is not implemented in AI-B, so the streaming candidates (idle 60 s,
maximum lifetime 10 min) have no setting here yet.

`AI_EGRESS_MAX_RESPONSE_BYTES` defaults to 8 MiB: a provisional implementation
bound, needed so that every response is bounded, and likewise to be validated
before AI-D.

Plain environment configuration, read the way other non-secret tunables are
(`saas_os/infra/ratelimit/config.py`). This is not AI-C's provider-management
configuration: no provider, model, credential or endpoint is configured here.
"""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass

from saas_os.infra.egress import EgressConfigurationError, StrictEgressPolicy

CANDIDATE_CONNECT_TIMEOUT_SECONDS = 5.0
CANDIDATE_READ_TIMEOUT_SECONDS = 30.0
CANDIDATE_TOTAL_DEADLINE_SECONDS = 120.0
PROVISIONAL_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

_UPPER_BOUND_SECONDS = 3600.0
_UPPER_BOUND_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class AIEgressSettings:
    policy: StrictEgressPolicy
    total_deadline_seconds: float


def _seconds(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise EgressConfigurationError(f"invalid_{name.lower()}") from exc
    if not math.isfinite(value) or not 0 < value <= _UPPER_BOUND_SECONDS:
        raise EgressConfigurationError(f"invalid_{name.lower()}")
    return value


def _bytes(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    if not raw.strip().isdigit():
        raise EgressConfigurationError(f"invalid_{name.lower()}")
    value = int(raw)
    if not 0 < value <= _UPPER_BOUND_BYTES:
        raise EgressConfigurationError(f"invalid_{name.lower()}")
    return value


def ai_egress_settings(env: Mapping[str, str] | None = None) -> AIEgressSettings:
    """Settings from `AI_EGRESS_CONNECT_TIMEOUT_SECONDS`,
    `AI_EGRESS_READ_TIMEOUT_SECONDS`, `AI_EGRESS_TOTAL_DEADLINE_SECONDS` and
    `AI_EGRESS_MAX_RESPONSE_BYTES`, each falling back to its provisional
    default. Invalid values fail closed (`EgressConfigurationError`). Only
    port 443 is allowed; other ports need explicit configuration, which is
    AI-C's provider configuration and does not exist yet."""
    source = os.environ if env is None else env
    connect = _seconds(
        source, "AI_EGRESS_CONNECT_TIMEOUT_SECONDS", CANDIDATE_CONNECT_TIMEOUT_SECONDS
    )
    read = _seconds(source, "AI_EGRESS_READ_TIMEOUT_SECONDS", CANDIDATE_READ_TIMEOUT_SECONDS)
    total = _seconds(source, "AI_EGRESS_TOTAL_DEADLINE_SECONDS", CANDIDATE_TOTAL_DEADLINE_SECONDS)
    max_bytes = _bytes(source, "AI_EGRESS_MAX_RESPONSE_BYTES", PROVISIONAL_MAX_RESPONSE_BYTES)
    policy = StrictEgressPolicy(
        connect_timeout_seconds=connect,
        read_timeout_seconds=read,
        max_response_bytes=max_bytes,
    )
    return AIEgressSettings(policy=policy, total_deadline_seconds=total)
