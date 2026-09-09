"""`infra/ratelimit` -- Redis-backed rate limiting
(docs/IMPLEMENTATION-ROADMAP.md Phase 8.2; docs/API-ARCHITECTURE.md
section 6: "Owned by Infra as a cross-cutting ingress concern, applied
uniformly ahead of both Core and Product routes, scoped by tenant and by
API key").

Owns: `RateLimitConfig`/`get_ratelimit_config()`, `check_rate_limit()`/
`enforce_rate_limit()` (fixed-window counter). Has zero knowledge of
what a "tenant" or a "route" is (docs/ARCHITECTURE.md section 2:
"Infrastructure has zero knowledge of business concepts") -- callers
supply an opaque scoping key; `api/dependencies.py` is where the
"scoped by tenant" policy is actually applied.

P1.5: also owns the fail-closed backend-failure contract --
`RateLimitBackendError` (a Redis outage/timeout/command error, always
distinct from `RateLimitExceededError`) -- this module never silently
treats a Redis failure as "allowed" or "not allowed"; `api/dependencies.py`
maps it to HTTP 503, never 429.

Does NOT own: API-key-scoped limiting (deferred -- Phase 8's own scope
does not introduce API-key HTTP authentication, see `api/__init__.py`'s
own Non-Goals), per-route limit overrides via a Product's contract
(`docs/API-ARCHITECTURE.md` section 6's own "a product may declare
tighter limits ... via its contract" -- no product exists yet to declare
one).
"""

from infra.ratelimit.config import RateLimitConfig, get_ratelimit_config
from infra.ratelimit.errors import (
    RateLimitBackendError,
    RateLimitConfigurationError,
    RateLimitExceededError,
)
from infra.ratelimit.limiter import RateLimitResult, check_rate_limit, enforce_rate_limit

__all__ = [
    "RateLimitConfig",
    "get_ratelimit_config",
    "RateLimitResult",
    "check_rate_limit",
    "enforce_rate_limit",
    "RateLimitConfigurationError",
    "RateLimitExceededError",
    "RateLimitBackendError",
]
