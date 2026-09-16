"""The reference consumer's own application entrypoint (ADR-0018/ADR-0017).

Proves the "own application entrypoint" requirement directly: this
project builds its own `FastAPI` app by calling
`api.platform.build_platform_app()` (an installed SaaS OS's reusable
builder) and mounting its own route on top -- it never imports
`api.main:app` as its own application (ADR-0017's rejected Option A).
"""

from __future__ import annotations

from api.platform import build_platform_app
from fastapi import FastAPI

from reference_consumer.purge import register as register_purge_participant
from reference_consumer.routes import router as widgets_router


def create_app() -> FastAPI:
    app = build_platform_app(title="Reference Consumer", version="0.1.0")
    app.include_router(widgets_router)
    # RA-12-2: registers this Product's own tenant purge participant
    # (reference_consumer/purge.py) with Core's purge orchestration --
    # this Product's own answer to "what happens to my tenant data on
    # tenant purge," never something core.tenancy decides for it.
    register_purge_participant()
    return app


app = create_app()
