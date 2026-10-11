"""`saas_os.infra.edge` -- the reusable single-origin application-runtime boundary
(docs/ADR/0024-single-origin-application-runtime.md).

A browser-facing SaaS application is composed of two servers (a product
backend and a product frontend) that must appear to the browser as **one
origin**: cookies, the OIDC callback, and relative `fetch()` URLs are all
origin-scoped, so a two-origin local topology forces every consuming
product to re-invent the same edge/proxy, callback-origin and API-origin
decisions independently. This package is SaaS-OS's answer to that, and
nothing more:

- `origin` -- the `PUBLIC_APP_ORIGIN` configuration contract: what a
  browser-visible origin is allowed to be, and the one derivation
  `OIDC redirect URI = PUBLIC_APP_ORIGIN + /auth/callback`. Consumed by
  `saas_os/api/auth/config.py` (the relying party) and
  `saas_os/infra/local_identity/zitadel_bootstrap.py` (the tool that registers
  that exact URI with the local provider) -- one source of truth, so the
  two can never drift apart.
- `routing` -- the declared set of public paths the *backend* owns behind
  that origin (`/auth/*`, `/v1/*`, `/healthz`, `/readyz`). Everything else
  belongs to the product frontend.
- `assets/Caddyfile.local-edge` -- the reusable **local-development** edge
  configuration implementing exactly that split, emitted for a consuming
  project by the `saas-os-edge-config` console script (`cli`) so no
  product copies this repository's files (ADR-0015).

**Boundary.** SaaS-OS owns origin composition, the callback-origin
derivation, and which path prefixes reach the backend. It does not own,
and must never encode, a product's authenticated entry route, dashboard
URL, navigation, or tenant UX -- after login the browser is sent to a
fixed, same-origin path (`AUTH_POST_LOGIN_PATH`, default `/`) and what
that path renders is entirely the product frontend's decision.

**This is not a production edge.** `docker-compose.prod.yml` + the
repository-root `Caddyfile` remain this repository's production
TLS/reverse-proxy boundary (ADR-0023 Phase 3); the asset here is
development composition only. See the ADR for the distinction.

No layer violation: this package reads no configuration at import time,
imports nothing from `core`/`api`/`products`/`control_plane`, and has no
dependency beyond the standard library.
"""

from __future__ import annotations

from saas_os.infra.edge.origin import (
    AUTH_CALLBACK_PATH,
    PublicAppOriginError,
    callback_url_for,
    normalize_public_app_origin,
    resolve_callback_url,
)
from saas_os.infra.edge.routing import (
    BACKEND_EXACT_PATHS,
    BACKEND_ROUTE_PREFIXES,
    CADDY_BACKEND_PATH_MATCHER,
    LOCAL_EDGE_CADDYFILE_RESOURCE,
    is_backend_path,
    read_local_edge_caddyfile,
)

__all__ = [
    "AUTH_CALLBACK_PATH",
    "BACKEND_EXACT_PATHS",
    "BACKEND_ROUTE_PREFIXES",
    "CADDY_BACKEND_PATH_MATCHER",
    "LOCAL_EDGE_CADDYFILE_RESOURCE",
    "PublicAppOriginError",
    "callback_url_for",
    "is_backend_path",
    "normalize_public_app_origin",
    "read_local_edge_caddyfile",
    "resolve_callback_url",
]
