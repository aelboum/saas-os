"""Provisional egress settings for AI provider calls (ADR-0054 section 8a,
R3 revised 2026-10-18).

The timeout values are the **candidates** recorded in ADR-0054 section 8a,
shipped as provisional, deployment-configurable defaults. They are not
validated production values: each production deployment validates its own
settings against its providers and workloads before enabling real-provider
traffic, and Q3 stays open for any change of the defaults. Streaming is not
enabled, so the streaming candidates (idle 60 s, maximum lifetime 10 min) have
no setting here.

`AI_EGRESS_MAX_RESPONSE_BYTES` defaults to 8 MiB: a provisional bound, needed
so that every response is bounded, and likewise validated per deployment.

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
    default. Invalid values fail closed (`EgressConfigurationError`). Port
    443 is the default; another port comes only from the provider row's
    validated `base_url` (AI-C provider configuration)."""
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
