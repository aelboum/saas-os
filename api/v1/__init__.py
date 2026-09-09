"""`/v1` external API routes (docs/ADR/0006-api-style-and-versioning.md:
"versioned from the first released route using a URL path segment").
"""

from api.v1.tenant_status import router as tenant_status_router

__all__ = ["tenant_status_router"]
