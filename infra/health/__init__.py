"""`infra/health` -- generic liveness/readiness aggregation
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.5; docs/DEPLOYMENT-ARCHITECTURE.md
section 7).

Liveness answers "is this process alive" -- local, deterministic, no
dependency on PostgreSQL, Redis, or any external service. Readiness
answers "is this infrastructure ready to serve work" by aggregating DB
and Redis reachability, reusing `infra/db`'s and `infra/jobs`'s own
sanctioned connection primitives -- `infra/health` owns no connection
configuration or secret access of its own (docs/ARCHITECTURE.md section 2:
Infrastructure depends on nothing above it; `infra/health` depends on
`infra/db` and `infra/jobs`, both siblings within Infrastructure).

This module does not expose an HTTP endpoint -- wiring a route is Phase
8.2's ingress-layer concern (docs/IMPLEMENTATION-ROADMAP.md), consistent
with the roadmap's own "/health (or equivalent)" phrasing for this phase.
What this phase provides is the aggregation mechanism a future route
calls.

    infra.health.check_liveness()   -> CheckResult      (sync, no I/O)
    infra.health.check_readiness()  -> ReadinessReport   (async, DB + Redis)

Neither result ever includes a secret value, a connection string, or a raw
exception message -- a failed check's `detail` is limited to the failing
exception's *type name* (docs/SECURITY.md: no sensitive internal detail is
exposed to an unauthenticated caller).
"""

from infra.health.liveness import check_liveness
from infra.health.readiness import check_readiness
from infra.health.results import CheckResult, HealthStatus, ReadinessReport

__all__ = [
    "HealthStatus",
    "CheckResult",
    "ReadinessReport",
    "check_liveness",
    "check_readiness",
]
