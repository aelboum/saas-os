"""This repository's own application composition root
(docs/IMPLEMENTATION-ROADMAP.md Phase 8.1/8.2; rebuilt on top of
`api.platform.build_platform_app()` in the SaaS OS packaging/consumer
implementation phase, docs/ADR/0017-saas-os-api-application-boundary.md).

All reusable platform wiring (FastAPI construction with `debug=False`,
`lifespan` -- logging/tracing configuration, the P1.2
`validate_application_role()` fail-closed startup guard --
`CorrelationIdMiddleware`, and the reusable default routers) now lives in
`api.platform` (see that module's own docstring for the full contract);
this module is what ADR-0017 calls "application-specific composition":
this repository's own dev/test server, built the same way a real
consuming project builds its own -- by calling `build_platform_app()` and
mounting its own route(s) on top. A consuming project must never import
*this* module as its own application (ADR-0017's Option A, rejected); it
imports `api.platform.build_platform_app` instead.

`api/v1/tenant_status.py` is mounted only here, not inside
`build_platform_app()` -- ADR-0017 leaves that one route deliberately
unclassified ("no product route exists to generalize from"); this
repository's own server keeps mounting it explicitly, as an example of
exactly what a consumer's own composition root does.
"""

from __future__ import annotations

from fastapi import FastAPI

from api.platform import build_platform_app
from api.v1 import tenant_status_router


def create_app() -> FastAPI:
    app = build_platform_app(title="saas-os external API", version="v1")
    app.include_router(tenant_status_router)
    return app


app = create_app()
