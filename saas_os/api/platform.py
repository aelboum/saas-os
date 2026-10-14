"""`build_platform_app()` -- the minimal, reusable FastAPI application
builder ADR-0017 recorded as a principle (docs/ADR/0017-saas-os-api-application-boundary.md:
"SaaS OS may expose reusable API infrastructure/components... but a
consumer must never be forced to import a complete SaaS OS application or
server as if it were the consumer's own application").

A consuming project owns its own application composition (its own routes,
its own OpenAPI metadata, its own exception handlers, its own business
middleware -- ADR-0017's own classification table). This module owns only
the reusable platform wiring every consumer needs regardless of business
domain, extracted unchanged from `saas_os/api/main.py`'s own pre-existing
`create_app()`/`lifespan()` (this repository's own dev/test server,
`saas_os/api/main.py`, is itself the first consumer of this builder -- see that
module):

- `FastAPI` construction (`debug=False`, fixed -- docs/SECURITY.md: HTTP
  errors must never leak a stack trace; there is no parameter to turn
  this on, matching `saas_os/api/main.py`'s own prior "no configuration flag"
  invariant).
- `lifespan`: `saas_os.infra.observability.configure_logging()`/`configure_tracing()`,
  then `saas_os.infra.db.validate_application_role(saas_os.infra.db.get_engine())` --
  the fail-closed guard that an unsafe (superuser/BYPASSRLS) database
  role must never reach a "ready" application. Unconditional, exactly as
  before: no parameter here skips it, in any environment.
- `saas_os.api.middleware.CorrelationIdMiddleware` -- request-correlation, ahead
  of every route.
- The reusable default routers ADR-0017's own classification table marks
  "Reusable library surface" and generic across any business domain:
  `saas_os.api.health.router` (liveness/readiness) and `saas_os.api.auth.router` (OIDC
  login/callback/logout/me -- identity is a Core concern, ADR-0005).
  `saas_os/api/v1/tenant_status.py` is deliberately NOT mounted here -- ADR-0017
  itself leaves that one route unclassified ("no product route exists to
  generalize from"); a consumer that wants it mounts it explicitly, the
  same way `saas_os/api/main.py` does.

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

from saas_os.api.auth import router as auth_router
from saas_os.api.health import router as health_router
from saas_os.api.middleware import CorrelationIdMiddleware
from saas_os.api.platform_admin.config import get_platform_admin_http_config
from saas_os.api.route_policy import assert_platform_route_rules, assert_route_policies
from saas_os.core.config import get_settings
from saas_os.core.identity import get_deactivation_scan_config
from saas_os.core.platform_authority import (
    get_oversight_read_config,
    get_platform_mutation_config,
)
from saas_os.infra.db import get_engine, validate_application_role
from saas_os.infra.observability import configure_logging, configure_tracing


def _is_production() -> bool:
    return get_settings().environment == "production"


@asynccontextmanager
async def _platform_lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Foundation Enforcement (FE-4): checked first, before anything else
    # starts, against the fully assembled app -- every router a consumer
    # mounted after build_platform_app() returned is included. An
    # undeclared route fails startup closed (saas_os/api/route_policy.py).
    policies = assert_route_policies(app, production=_is_production())
    # ADR-0045 section 7, in the same step: the platform-admin surface
    # needs the deployment's opt-in as well as the product's, and an
    # authority-changing route needs the fresh-session rule. Reading the
    # configuration here also stops startup on an invalid session-age limit.
    assert_platform_route_rules(policies, enabled=get_platform_admin_http_config().enabled)
    configure_logging()
    configure_tracing()
    validate_application_role(get_engine())
    # ADR-0045 ruling R1: an invalid PLATFORM_DEACTIVATION_MAX_TENANTS is a
    # configuration error that stops startup.
    get_deactivation_scan_config()
    # ADR-0045 section 9d: likewise PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS.
    get_oversight_read_config()
    # And PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS (amendment of 2026-10-14).
    get_platform_mutation_config()
    yield


def build_platform_app(*, title: str, version: str) -> FastAPI:
    """Construct a `FastAPI` app wired with SaaS OS's reusable platform
    concerns (see module docstring). A consuming project mounts its own
    business routers onto the returned app:

        app = build_platform_app(title="Recharge", version="1.0.0")
        app.include_router(recharge_router)
    """
    # D1 (docs/ADR/0030-foundation-enforcement.md): the generated API
    # documentation is an explicit policy -- served outside production,
    # disabled in production.
    documentation: dict[str, str | None] = (
        {"openapi_url": None, "docs_url": None, "redoc_url": None} if _is_production() else {}
    )
    app = FastAPI(
        title=title,
        version=version,
        debug=False,
        lifespan=_platform_lifespan,
        **documentation,  # type: ignore[arg-type]
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(health_router)
    app.include_router(auth_router)
    return app
