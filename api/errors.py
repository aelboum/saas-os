"""Stable HTTP error responses (docs/IMPLEMENTATION-ROADMAP.md Phase 8.1;
this checkpoint's own Step 10: "HTTP errors must not leak secrets, stack
traces, SQL, internal credentials ... Avoid distinguishing authentication
failures in a way that enables credential enumeration").

Every function here returns a plain `fastapi.HTTPException` with a fixed,
generic `detail` string -- never the underlying exception's own message,
which could carry an internal detail (a table name, a constraint name, a
stack frame) the caller has no legitimate need to see. FastAPI's default
`debug=False` behavior already suppresses tracebacks from responses
(`api/main.py` sets this explicitly, belt-and-suspenders); this module is
the second layer, ensuring even a *handled* error path never echoes
exception internals into the response body.

`unauthorized()` and `not_found()` in particular use one fixed message
each, regardless of the specific underlying reason (invalid token vs.
expired vs. revoked; tenant doesn't exist vs. caller isn't a member) --
this is deliberate, not an oversight: mirrors `core/webhooks`'/
`core/notifications`'s own "same error whether not-found or wrong-tenant"
non-enumeration convention, applied here to the HTTP layer.
"""

from __future__ import annotations

from fastapi import HTTPException, status


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def not_found(resource: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource} not found.")


def forbidden() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized.")


def rate_limited(retry_after_seconds: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Rate limit exceeded.",
        headers={"Retry-After": str(retry_after_seconds)},
    )


def quota_exceeded() -> HTTPException:
    """P1.9: a quota-metered action was denied because the tenant's
    plan-configured limit for the metric would be exceeded. Deliberately
    a `429`, like `rate_limited()`, but with its own distinct, fixed
    `detail` string -- the two must never be conflated (a quota outcome
    is a real, currently-effective business limit the request WAS fully
    evaluated against; a rate limit is a short request-rate window).
    Unlike `rate_limited()`, no `Retry-After` header is set: a quota
    resets at its configured window boundary (e.g. the next calendar
    month), not after a short, fixed backoff -- a caller-facing
    `Retry-After` value here would either be misleadingly short or leak
    the exact window boundary, and this checkpoint's own convention
    (module docstring) is to disclose no more internal detail than the
    fixed `detail` string itself."""
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Quota exceeded.",
    )


def idempotency_key_invalid() -> HTTPException:
    """P1.11: the caller-supplied `Idempotency-Key` header failed basic
    validation (missing when required, empty, oversized, or outside the
    safe character set) -- `400`, never echoing the offending value back
    (module docstring: no internal detail beyond the fixed message)."""
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Idempotency-Key.")


def idempotency_key_reused() -> HTTPException:
    """P1.11: the same `Idempotency-Key` was already used, for the same
    tenant and operation, with a genuinely different request --
    deterministic `409`, distinct fixed `detail` from every other error
    in this module so a client can reliably branch on it."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Idempotency-Key already used with a different request.",
    )


def idempotency_in_progress() -> HTTPException:
    """P1.11: a concurrent request for the same `Idempotency-Key` has not
    yet resolved. Also `409` (never `429`/`503` -- this is not a rate or
    backend-availability condition, module docstring), with its own
    distinct `detail` so it is never confused with
    `idempotency_key_reused()`'s different-request case."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="A request with this Idempotency-Key is still being processed.",
    )


def service_unavailable(retry_after_seconds: int) -> HTTPException:
    """P1.5: a dependency this request needed (currently: the rate-limit
    backend) failed -- deliberately a different status *and* a different
    generic `detail` from `rate_limited()`'s own 429, so a caller can
    never mistake "we could not determine your rate limit" for "you
    exceeded it". Never includes the underlying failure's own message
    (module docstring) -- `retry_after_seconds` is always a small, fixed,
    caller-supplied constant here, never a value derived from the failed
    backend itself (there is nothing trustworthy to derive it from)."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Service temporarily unavailable.",
        headers={"Retry-After": str(retry_after_seconds)},
    )
