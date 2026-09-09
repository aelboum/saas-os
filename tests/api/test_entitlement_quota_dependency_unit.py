"""Unit tests for P1.9's `api.dependencies.require_entitlement_and_quota()`
HTTP-status mapping. `require_entitlement`/`consume_quota` are
monkeypatched in `api.dependencies`'s own namespace (same technique
`tests/api/test_ratelimit_dependency_unit.py` uses for
`enforce_rate_limit`) -- these exercise only the 403/429 mapping and the
entitlement-denial audit write, not real PostgreSQL entitlements/usage
(`tests/core/usage/test_quota_enforcement_integration.py` and the new
API-level integration test cover that end-to-end).

The inner `_dependency` closure is called directly with an explicit
`context=` keyword, bypassing FastAPI's own dependency-injection
resolution -- identical technique to
`tests/api/test_ratelimit_dependency_unit.py::test_backend_failure_maps_to_503_not_429`,
which calls `_enforce_rate_limit_for_route` the same way. This is possible
because `Depends(...)` is only a parameter *default* value; it is never
evaluated unless FastAPI itself resolves the dependency graph.
"""

from __future__ import annotations

import uuid

import api.dependencies as deps
import pytest
from api.context import RequestContext
from core.billing.errors import EntitlementDeniedError
from core.usage.errors import QuotaExceededError
from fastapi import HTTPException

pytestmark = pytest.mark.anyio


def _context() -> RequestContext:
    return RequestContext(actor_id=uuid.uuid4(), tenant_id=uuid.uuid4(), membership_id=uuid.uuid4())


async def _call(entitlement_key: str | None, quota_metric: str | None, context: RequestContext):
    dependency = deps.require_entitlement_and_quota(
        "widgets", "read", entitlement_key=entitlement_key, quota_metric=quota_metric
    )
    # The dependency's own signature carries `Depends(require_permission(...))`
    # as its default -- calling it directly with an explicit `context=`
    # keyword skips that inner RBAC dependency entirely (Depends(...) is
    # only ever a parameter default; it is never evaluated unless FastAPI
    # itself resolves the dependency graph), matching the existing
    # precedent cited in this file's own docstring.
    return await dependency(context=context)


# --- Entitlement -----------------------------------------------------------


async def test_entitlement_granted_allows_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deps, "require_entitlement", lambda tenant_id, key: None)
    context = _context()
    result = await _call("reports", None, context)
    assert result is context


async def test_entitlement_denied_maps_to_403(monkeypatch: pytest.MonkeyPatch) -> None:
    def _deny(tenant_id: uuid.UUID, key: str) -> None:
        raise EntitlementDeniedError(tenant_id, key)

    monkeypatch.setattr(deps, "require_entitlement", _deny)
    audited: list[dict[str, object]] = []
    monkeypatch.setattr(deps, "record_audit_event", lambda **kwargs: audited.append(kwargs))

    with pytest.raises(HTTPException) as excinfo:
        await _call("reports", None, _context())

    assert excinfo.value.status_code == 403
    assert audited, "entitlement denial must be audited like an RBAC denial"
    assert audited[0]["resource_type"] == "entitlement"
    assert audited[0]["resource_id"] == "reports"
    assert audited[0]["action"] == "api.access_denied"


async def test_entitlement_denial_does_not_leak_subscription_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _deny(tenant_id: uuid.UUID, key: str) -> None:
        raise EntitlementDeniedError(tenant_id, key)

    monkeypatch.setattr(deps, "require_entitlement", _deny)
    monkeypatch.setattr(deps, "record_audit_event", lambda **kwargs: None)

    with pytest.raises(HTTPException) as excinfo:
        await _call("reports", None, _context())

    assert excinfo.value.detail == "Not authorized."


async def test_no_entitlement_key_skips_the_entitlement_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(tenant_id: uuid.UUID, key: str) -> None:
        raise AssertionError("require_entitlement must not be called when entitlement_key is None")

    monkeypatch.setattr(deps, "require_entitlement", _boom)
    context = _context()
    result = await _call(None, None, context)
    assert result is context


# --- Quota -------------------------------------------------------------


async def test_quota_available_allows_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deps, "consume_quota", lambda tenant_id, metric, quantity: object())
    context = _context()
    result = await _call(None, "api_calls", context)
    assert result is context


async def test_quota_exceeded_maps_to_429(monkeypatch: pytest.MonkeyPatch) -> None:
    def _deny(tenant_id: uuid.UUID, metric: str, quantity: object) -> None:
        from decimal import Decimal

        raise QuotaExceededError(tenant_id, metric, used=Decimal("10"), limit=Decimal("10"))

    monkeypatch.setattr(deps, "consume_quota", _deny)

    with pytest.raises(HTTPException) as excinfo:
        await _call(None, "api_calls", _context())

    assert excinfo.value.status_code == 429
    assert excinfo.value.detail == "Quota exceeded."


async def test_quota_denial_is_not_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mirrors the rate-limit-exceeded precedent (module docstring):
    routine, expected, not a security decision about the actor."""

    def _deny(tenant_id: uuid.UUID, metric: str, quantity: object) -> None:
        from decimal import Decimal

        raise QuotaExceededError(tenant_id, metric, used=Decimal("10"), limit=Decimal("10"))

    monkeypatch.setattr(deps, "consume_quota", _deny)
    audited: list[dict[str, object]] = []
    monkeypatch.setattr(deps, "record_audit_event", lambda **kwargs: audited.append(kwargs))

    with pytest.raises(HTTPException):
        await _call(None, "api_calls", _context())

    assert audited == []


async def test_no_quota_metric_skips_the_quota_check(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(tenant_id: uuid.UUID, metric: str, quantity: object) -> None:
        raise AssertionError("consume_quota must not be called when quota_metric is None")

    monkeypatch.setattr(deps, "consume_quota", _boom)
    context = _context()
    result = await _call(None, None, context)
    assert result is context


# --- Ordering: entitlement runs before quota --------------------------------


async def test_entitlement_denial_prevents_the_quota_check_from_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _deny(tenant_id: uuid.UUID, key: str) -> None:
        raise EntitlementDeniedError(tenant_id, key)

    def _boom(tenant_id: uuid.UUID, metric: str, quantity: object) -> None:
        raise AssertionError("consume_quota must not run when entitlement was already denied")

    monkeypatch.setattr(deps, "require_entitlement", _deny)
    monkeypatch.setattr(deps, "consume_quota", _boom)
    monkeypatch.setattr(deps, "record_audit_event", lambda **kwargs: None)

    with pytest.raises(HTTPException) as excinfo:
        await _call("reports", "api_calls", _context())

    assert excinfo.value.status_code == 403


async def test_403_and_429_are_distinguishable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _deny_entitlement(tenant_id: uuid.UUID, key: str) -> None:
        raise EntitlementDeniedError(tenant_id, key)

    monkeypatch.setattr(deps, "require_entitlement", _deny_entitlement)
    monkeypatch.setattr(deps, "record_audit_event", lambda **kwargs: None)
    with pytest.raises(HTTPException) as entitlement_exc:
        await _call("reports", None, _context())

    def _deny_quota(tenant_id: uuid.UUID, metric: str, quantity: object) -> None:
        from decimal import Decimal

        raise QuotaExceededError(tenant_id, metric, used=Decimal("1"), limit=Decimal("1"))

    monkeypatch.setattr(deps, "consume_quota", _deny_quota)
    with pytest.raises(HTTPException) as quota_exc:
        await _call(None, "api_calls", _context())

    assert entitlement_exc.value.status_code != quota_exc.value.status_code
    assert entitlement_exc.value.detail != quota_exc.value.detail
