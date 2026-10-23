"""This product's application entrypoint (ADR-0017).

    uvicorn my_product.app:app

The product owns its composition. `build_platform_app()` contributes only
what every product needs regardless of domain: fail-closed startup checks
(every route declares a policy; the database role cannot bypass RLS),
request correlation, health routes and the OIDC auth routes. Routers are
mounted here, on top.
"""

from __future__ import annotations

from fastapi import FastAPI

from my_product.purge import register_purge_participants
from my_product.routes import router as items_router
from saas_os.api.platform import build_platform_app


def create_app() -> FastAPI:
    app = build_platform_app(title="My Product", version="0.1.0")
    app.include_router(items_router)
    register_purge_participants()
    return app


app = create_app()
