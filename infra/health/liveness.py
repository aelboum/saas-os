"""Liveness check (docs/IMPLEMENTATION-ROADMAP.md Phase 2.5,
docs/DEPLOYMENT-ARCHITECTURE.md section 7).

Liveness answers "is this process alive" -- deterministic, local, no
PostgreSQL, no Redis, no external service, no network access. If this
function can execute at all, the process is live. This is deliberately
not the same question readiness asks (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.5: liveness must not require dependency availability).
"""

from __future__ import annotations

from infra.health.results import CheckResult, HealthStatus


def check_liveness() -> CheckResult:
    return CheckResult(name="process", status=HealthStatus.HEALTHY)
