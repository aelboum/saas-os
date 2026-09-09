"""The FastAPI application composition root
(docs/IMPLEMENTATION-ROADMAP.md Phase 8.1/8.2).

`debug=False` explicit (not just the framework default) -- this
checkpoint's own Step 10: HTTP errors must not leak stack traces; FastAPI
only includes traceback detail in a response when `debug=True`.

No route is mounted here except `/v1` (external API,
docs/API-ARCHITECTURE.md section 1) -- no internal-API or AI Control
Plane HTTP surface exists yet (`api/__init__.py`'s own Non-Goals); adding
one is a future phase's own explicit scope, not inferred here.

`lifespan` (P1.2) is this process's application-runtime startup hook --
this is the only real ASGI application this repository runs today (no
worker/other process currently has its own startup path; see
`infra/db/role_guard.py`'s own docstring). It calls
`infra.db.validate_application_role()` once, against the same
process-wide `infra.db.get_engine()` every request already uses, before
the application is considered ready. `validate_application_role()`
raises `UnsafeDatabaseRoleError` -- a plain exception, uncaught here on
purpose -- if the connected role can bypass Row-Level Security or that
property could not be established; FastAPI/Starlette propagates a
startup-phase `lifespan` exception to the ASGI server, which fails
startup rather than serving traffic. There is no configuration flag to
skip this -- an unsafe role must never reach a "ready" application in any
environment, not only in whichever ones remember to opt in.

P1.4 activates the existing `infra/observability` foundation (previously
built but never called from this process, docs/OBSERVABILITY.md section
2) and wires `api.middleware.CorrelationIdMiddleware` ahead of every
route -- see that module's own docstring for the full request-correlation
contract. `configure_logging()`/`configure_tracing()` are called from
`lifespan`, not eagerly at module/`create_app()` scope -- both are
side-effecting, process-wide setup (a stdlib logging handler; OpenTelemetry's
own once-only global `TracerProvider`) and belong in the same startup hook
`validate_application_role()` already uses, not as a side effect of merely
*importing* this module. Neither call introduces a new observability
mechanism; both call the same `configure_logging()`/`configure_tracing()`
entry points `infra/observability`'s own tests already exercise.

P1.8 mounts `api.health.router` (`/healthz`, `/readyz`) directly on the
app -- the one production ASGI entrypoint is `api/server.py`
(`uvicorn.run(app, ...)`), never a second application. Health routes are
added ahead of the `/v1` router but, unlike it, receive no
`api.dependencies` chain (see `api/health.py`'s own docstring for why:
they are infrastructure-only, never tenant-scoped).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.auth import router as auth_router
from api.health import router as health_router
from api.middleware import CorrelationIdMiddleware
from api.v1 import tenant_status_router
from infra.db import get_engine, validate_application_role
from infra.observability import configure_logging, configure_tracing


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    configure_tracing()
    validate_application_role(get_engine())
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="saas-os external API",
        version="v1",
        debug=False,
        lifespan=lifespan,
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(health_router)
    # P2.2: browser/client authentication (OIDC login, callback, logout,
    # current user) -- mounted at the app root, outside `/v1`, like the
    # health routes; see `api/auth/__init__.py` for its boundary.
    app.include_router(auth_router)
    app.include_router(tenant_status_router)
    return app


app = create_app()
