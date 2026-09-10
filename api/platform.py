"""`build_platform_app()` -- the minimal, reusable FastAPI application
builder ADR-0017 recorded as a principle (docs/ADR/0017-saas-os-api-application-boundary.md:
"SaaS OS may expose reusable API infrastructure/components... but a
consumer must never be forced to import a complete SaaS OS application or
server as if it were the consumer's own application").

A consuming project owns its own application composition (its own routes,
its own OpenAPI metadata, its own exception handlers, its own business
middleware -- ADR-0017's own classification table). This module owns only
the reusable platform wiring every consumer needs regardless of business
domain, extracted unchanged from `api/main.py`'s own pre-existing
`create_app()`/`lifespan()` (this repository's own dev/test server,
`api/main.py`, is itself the first consumer of this builder -- see that
module):

- `FastAPI` construction (`debug=False`, fixed -- docs/SECURITY.md: HTTP
  errors must never leak a stack trace; there is no parameter to turn
  this on, matching `api/main.py`'s own prior "no configuration flag"
  invariant).
- `lifespan`: `infra.observability.configure_logging()`/`configure_tracing()`,
  then `infra.db.validate_application_role(infra.db.get_engine())` --
  the fail-closed guard that an unsafe (superuser/BYPASSRLS) database
  role must never reach a "ready" application. Unconditional, exactly as
  before: no parameter here skips it, in any environment.
- `api.middleware.CorrelationIdMiddleware` -- request-correlation, ahead
  of every route.
- The reusable default routers ADR-0017's own classification table marks
  "Reusable library surface" and generic across any business domain:
  `api.health.router` (liveness/readiness) and `api.auth.router` (OIDC
  login/callback/logout/me -- identity is a Core concern, ADR-0005).
  `api/v1/tenant_status.py` is deliberately NOT mounted here -- ADR-0017
  itself leaves that one route unclassified ("no product route exists to
  generalize from"); a consumer that wants it mounts it explicitly, the
  same way `api/main.py` does.

Deliberately minimal (ADR-0017's own scope: "recorded as a principle...
the precise package-level restructuring is left as open follow-up work"):
no plugin/hook system, no speculative configuration beyond `title`/
`version` (the two pieces of application metadata every consumer
necessarily has and FastAPI itself already requires), no attempt to
anticipate configuration no real consumer has asked for yet.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.auth import router as auth_router
from api.health import router as health_router
from api.middleware import CorrelationIdMiddleware
from infra.db import get_engine, validate_application_role
from infra.observability import configure_logging, configure_tracing


@asynccontextmanager
async def _platform_lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    configure_tracing()
    validate_application_role(get_engine())
    yield


def build_platform_app(*, title: str, version: str) -> FastAPI:
    """Construct a `FastAPI` app wired with SaaS OS's reusable platform
    concerns (see module docstring). A consuming project mounts its own
    business routers onto the returned app:

        app = build_platform_app(title="Recharge", version="1.0.0")
        app.include_router(recharge_router)
    """
    app = FastAPI(
        title=title,
        version=version,
        debug=False,
        lifespan=_platform_lifespan,
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(health_router)
    app.include_router(auth_router)
    return app
