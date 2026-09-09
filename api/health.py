"""Infrastructure liveness/readiness HTTP endpoints (P1.8:
docs/DEPLOYMENT-ARCHITECTURE.md section 7 -- "infra/health owns the
generic liveness/readiness endpoint mechanism"; this module is the HTTP
transport for that already-existing, already-tested mechanism
(`infra.health.check_liveness`/`check_readiness`, Phase 2.5). No new
dependency-check logic is introduced here.

Mounted directly on the app root in `api/main.py` (`/healthz`, `/readyz`)
-- not under `/v1`, and never through `api.dependencies`' enforced chain
(authentication -> tenant resolution -> rate limiting -> RBAC). These are
infrastructure endpoints, not part of the versioned external API surface:
a load balancer/orchestrator must be able to reach them with no bearer
token, no tenant, and no risk of being rate-limited or audited as if they
were a tenant-scoped request.

**Liveness** (`GET /healthz`): "is this process alive" -- `check_liveness()`
does no I/O (module docstring, `infra/health/liveness.py`), so this route
can never be made unhealthy by a PostgreSQL/Redis outage.

**Readiness** (`GET /readyz`): "is this process ready to serve requests
that need PostgreSQL/Redis" -- aggregates both via `check_readiness()`.
Returns `200` only if every check is healthy; `503` otherwise (never
`500` -- a dependency being down is an expected, not exceptional,
readiness state).

**Security (docs/SECURITY.md; this checkpoint's own Health endpoint
security requirement)**: the response body carries only a fixed check
`name` and `status` ("healthy"/"unhealthy") per dependency -- never
`infra.health.results.CheckResult.detail` (an exception *type name*,
already scrubbed of message/DSN content by `infra/health` itself, but
still internal diagnostic detail this endpoint does not need to repeat
to an unauthenticated caller), and never a credential, connection
string, tenant ID, or user ID (there is none to leak -- this route
never establishes tenant/actor context in the first place).
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from infra.health import HealthStatus, check_liveness, check_readiness

router = APIRouter(include_in_schema=False)


@router.get("/healthz")
def liveness() -> dict[str, str]:
    result = check_liveness()
    return {"status": result.status.value}


@router.get("/readyz")
async def readiness(response: Response) -> dict[str, object]:
    report = await check_readiness()
    if report.status != HealthStatus.HEALTHY:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": report.status.value,
        "checks": [{"name": check.name, "status": check.status.value} for check in report.checks],
    }
