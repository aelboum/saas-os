"""The opt-in platform-admin HTTP surface
(docs/ADR/0045-installation-scoped-platform-authority.md section 7).

    app = build_platform_app(title="My Product", version="1.0.0")
    app.include_router(build_platform_admin_router())

**Two opt-ins.** Nothing in SaaS OS mounts this router: not
`build_platform_app()`, not `saas_os/api/main.py`, not the consumer
scaffold. A product mounts it in code, and the deployment sets
`PLATFORM_ADMIN_HTTP_ENABLED=true`. Mounted without the setting, the
application fails startup; the setting alone exposes nothing.

Every route is under `/v1/platform`, declares exactly one platform
permission (`require_platform_permission`), and calls one Core function
that authorizes the same caller again in its own transaction. The route
adds no decision.

`build_platform_admin_router` is imported on first use: this package's
`config` module is read by `saas_os.api.dependencies`, which the router
module itself depends on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from saas_os.api.platform_admin.config import (
    MAX_AUTHORITY_SESSION_AGE_SECONDS,
    MIN_AUTHORITY_SESSION_AGE_SECONDS,
    PlatformAdminHttpConfig,
    PlatformAdminHttpConfigurationError,
    get_platform_admin_http_config,
)

if TYPE_CHECKING:
    from fastapi import APIRouter


def build_platform_admin_router() -> APIRouter:
    """A new platform-admin router, prefix `/v1/platform`. See the module
    docstring for the two opt-ins."""
    from saas_os.api.platform_admin.router import build_router

    return build_router()


__all__ = [
    "build_platform_admin_router",
    "PlatformAdminHttpConfig",
    "PlatformAdminHttpConfigurationError",
    "get_platform_admin_http_config",
    "MAX_AUTHORITY_SESSION_AGE_SECONDS",
    "MIN_AUTHORITY_SESSION_AGE_SECONDS",
]
