"""The single-origin routing contract (ADR-0024): which public paths
behind `PUBLIC_APP_ORIGIN` belong to the **backend**, and therefore --
by exclusion, never by enumeration -- which belong to the product
frontend.

The backend's public surface is exactly what
`api.platform.build_platform_app()` mounts for every consumer
(`api/health.py`, `api/auth/routes.py`) plus the versioned external API
namespace ADR-0006 fixes (`/v1/*`, where a consuming project mounts its
own routers). `tests/api/test_single_origin_routing_unit.py` asserts this
tuple against the real mounted route table of a built platform app, so
the contract cannot silently drift from the routes that actually exist.

Everything not matched here reaches the frontend. That default is what
keeps SaaS-OS out of the product's business: SaaS-OS never needs to know
that a product serves `/t/{tenant}/dashboard`, `/app`, or anything else --
those are simply "not backend paths" and are proxied to the frontend
unchanged.

This is a closed, declared list, not a programmable routing DSL. A
consuming product that needs an additional browser-facing backend prefix
edits the emitted Caddyfile it owns (`saas-os-edge-config`,
ADR-0015 rules 9/10) -- SaaS-OS does not ship a mechanism for arbitrary
proxy rules, and deliberately exposes no way to route an internal service
(PostgreSQL, Redis, the worker, ZITADEL's database) through this edge.
"""

from __future__ import annotations

from importlib import resources
from typing import Final

BACKEND_ROUTE_PREFIXES: Final[tuple[str, ...]] = ("/auth", "/v1")
"""Path *prefixes* the backend owns. `/auth/*` is the OIDC flow
(`api/auth/routes.py`); `/v1/*` is the versioned external API (ADR-0006),
including whatever routers a consuming project mounts there itself."""

BACKEND_EXACT_PATHS: Final[tuple[str, ...]] = ("/healthz", "/readyz")
"""Exact paths the backend owns: `api/health.py`'s liveness/readiness.

Local development only. The production Caddyfile deliberately does *not*
proxy these to the backend (an external prober has no legitimate need for
a deployment's readiness detail) -- see ADR-0024's "Local vs production"
section. Exposing them locally is what makes `curl $PUBLIC_APP_ORIGIN/readyz`
a usable "is my whole stack up?" check for a developer."""

LOCAL_EDGE_CADDYFILE_RESOURCE: Final = "assets/Caddyfile.local-edge"
"""Packaged local-development edge configuration, emitted by the
`saas-os-edge-config` console script (`infra/edge/cli.py`)."""


def _caddy_backend_path_matcher() -> str:
    return " ".join(
        [f"{prefix}/*" for prefix in BACKEND_ROUTE_PREFIXES] + list(BACKEND_EXACT_PATHS)
    )


CADDY_BACKEND_PATH_MATCHER: Final[str] = _caddy_backend_path_matcher()
"""The exact `path` matcher argument list the packaged Caddyfile must use.
`tests/architecture/test_single_origin_edge.py` asserts the shipped asset
contains this string verbatim, so the declared contract above and the
configuration that actually enforces it cannot drift apart."""


def is_backend_path(path: str) -> bool:
    """True when `path` is routed to the backend, false when it reaches the
    frontend.

    This is the *declared application routing contract* -- the statement of
    which public paths belong to the backend, in the form the rest of this
    repository (and its tests) can assert against. It is not a reimplementation
    of Caddy's `path` matcher, and is not byte-for-byte equivalent to it: the
    edge normalizes and percent-decodes a request target before matching, and
    matches case-insensitively, none of which is done here. Feed it the
    already-normalized application path, not a raw request target.

    On that path the contract is: `/auth/*` matches `/auth/` and anything
    below it, never the bare `/auth` (no such route exists) and never
    `/authorize`."""
    if path in BACKEND_EXACT_PATHS:
        return True
    return any(path.startswith(f"{prefix}/") for prefix in BACKEND_ROUTE_PREFIXES)


def read_local_edge_caddyfile() -> str:
    """The packaged local-development edge configuration, as text."""
    return (
        resources.files("infra.edge")
        .joinpath(LOCAL_EDGE_CADDYFILE_RESOURCE)
        .read_text(encoding="utf-8")
    )
