"""Health/readiness result types (docs/IMPLEMENTATION-ROADMAP.md Phase 2.5,
docs/DEPLOYMENT-ARCHITECTURE.md section 7).

A `CheckResult`'s `detail` is deliberately restricted to a failing
exception's *type name* only -- never its message/args, which could
otherwise echo interpolated connection details from a driver-specific
error. This is what makes the Security Requirement ("no sensitive
internal detail exposed") hold structurally rather than by convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: HealthStatus
    detail: str | None = None


@dataclass(frozen=True)
class ReadinessReport:
    status: HealthStatus
    checks: tuple[CheckResult, ...]
