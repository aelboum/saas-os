"""P1.5 -- unit tests for `api.dependencies._enforce_rate_limit_for_route`'s
Redis-backend-failure mapping. `infra.ratelimit.enforce_rate_limit` is
monkeypatched (same technique `tests/api/test_dependencies_unit.py` uses
for `validate_session`) so these exercise only the HTTP-status mapping,
not real Redis -- `tests/api/v1/test_ratelimit_failure_integration.py`
covers the same behavior end-to-end against a real (deliberately broken)
Redis.
"""

from __future__ import annotations

import uuid
from typing import cast

import pytest
from api.context import RequestContext
from fastapi import HTTPException, Request

from infra.ratelimit import RateLimitBackendError, RateLimitExceededError

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _FakeURL:
    path = "/v1/tenants/some-tenant/status"


class _FakeRequest:
    """Only `.url.path` is read by `_enforce_rate_limit_for_route`; a
    duck-typed double avoids constructing a real ASGI `Request` scope
    (same `cast(...)` convention `tests/infra/jobs/test_dead_letter.py`
    uses for its own duck-typed Redis pool double)."""

    url = _FakeURL()


def _fake_request() -> Request:
    return cast("Request", _FakeRequest())


def _context() -> RequestContext:
    return RequestContext(actor_id=uuid.uuid4(), tenant_id=uuid.uuid4(), membership_id=uuid.uuid4())


async def test_backend_failure_maps_to_503_not_429(monkeypatch: pytest.MonkeyPatch) -> None:
    import api.dependencies as deps

    async def _raise_backend_error(key: str, *, config: object) -> None:
        raise RateLimitBackendError(key)

    monkeypatch.setattr(deps, "enforce_rate_limit", _raise_backend_error)
    monkeypatch.setattr(deps, "get_ratelimit_config", lambda: object())

    with pytest.raises(HTTPException) as excinfo:
        await deps._enforce_rate_limit_for_route(_fake_request(), context=_context())

    assert excinfo.value.status_code == 503
    assert excinfo.value.detail == "Service temporarily unavailable."
    assert excinfo.value.headers is not None
    assert excinfo.value.headers["Retry-After"] == "5"


async def test_exceeded_limit_still_maps_to_429_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: P1.5 must not touch the pre-existing 429 behavior."""
    import api.dependencies as deps

    async def _raise_exceeded(key: str, *, config: object) -> None:
        raise RateLimitExceededError(key, 42)

    monkeypatch.setattr(deps, "enforce_rate_limit", _raise_exceeded)
    monkeypatch.setattr(deps, "get_ratelimit_config", lambda: object())

    with pytest.raises(HTTPException) as excinfo:
        await deps._enforce_rate_limit_for_route(_fake_request(), context=_context())

    assert excinfo.value.status_code == 429
    assert excinfo.value.detail == "Rate limit exceeded."
    assert excinfo.value.headers is not None
    assert excinfo.value.headers["Retry-After"] == "42"


async def test_503_and_429_are_distinguishable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both are 4xx/5xx-adjacent failures, but they must never be
    conflated: different status code, different detail, different
    Retry-After semantics (bounded constant vs. the real window)."""
    import api.dependencies as deps

    async def _raise_backend_error(key: str, *, config: object) -> None:
        raise RateLimitBackendError(key)

    monkeypatch.setattr(deps, "enforce_rate_limit", _raise_backend_error)
    monkeypatch.setattr(deps, "get_ratelimit_config", lambda: object())
    with pytest.raises(HTTPException) as backend_exc:
        await deps._enforce_rate_limit_for_route(_fake_request(), context=_context())

    async def _raise_exceeded(key: str, *, config: object) -> None:
        raise RateLimitExceededError(key, 42)

    monkeypatch.setattr(deps, "enforce_rate_limit", _raise_exceeded)
    with pytest.raises(HTTPException) as exceeded_exc:
        await deps._enforce_rate_limit_for_route(_fake_request(), context=_context())

    assert backend_exc.value.status_code != exceeded_exc.value.status_code
    assert backend_exc.value.detail != exceeded_exc.value.detail


async def test_successful_check_returns_the_context_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: the success path is untouched -- no context mutation,
    no new side effect on the happy path."""
    import api.dependencies as deps

    async def _succeed(key: str, *, config: object) -> None:
        return None

    monkeypatch.setattr(deps, "enforce_rate_limit", _succeed)
    monkeypatch.setattr(deps, "get_ratelimit_config", lambda: object())

    context = _context()
    result = await deps._enforce_rate_limit_for_route(_fake_request(), context=context)
    assert result is context
