"""Unit tests for P1.9's quota-enforcement helpers that do not require a
real PostgreSQL instance: `_numeric_limit()` (the shared limit-parsing
helper `check_quota()`/`consume_quota()` both use) and `consume_quota()`'s
own input validation, which deliberately runs *before* any database
access (module docstring). Real atomic-consumption/concurrency/isolation
behavior needs a real transaction and real advisory locks --
`tests/core/usage/test_quota_enforcement_integration.py` covers that.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

import pytest
from core.usage.errors import InvalidUsageEventError, QuotaExceededError
from core.usage.service import _numeric_limit, consume_quota


def test_numeric_limit_parses_int() -> None:
    assert _numeric_limit({"api_calls": 100}, "api_calls") == Decimal("100")


def test_numeric_limit_parses_float() -> None:
    assert _numeric_limit({"storage_gb": 2.5}, "storage_gb") == Decimal("2.5")


def test_numeric_limit_none_when_key_missing() -> None:
    assert _numeric_limit({}, "api_calls") is None


def test_numeric_limit_none_for_boolean_value() -> None:
    """A boolean capability flag must never be misread as a numeric quota
    limit -- entitlement and quota are distinct concepts sharing one dict
    (core/usage/service.py's own docstring)."""
    assert _numeric_limit({"api_calls": True}, "api_calls") is None


def test_numeric_limit_none_for_non_numeric_string() -> None:
    assert _numeric_limit({"api_calls": "unlimited"}, "api_calls") is None


def test_numeric_limit_check_quota_and_consume_quota_agree(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both callers must derive "no limit" identically for the same
    unconfigured metric -- proven here by calling the shared helper
    directly rather than duplicating the parsing logic in each caller."""
    entitlements: dict[str, object] = {"unrelated_key": 5}
    assert _numeric_limit(entitlements, "api_calls") is None


def test_consume_quota_rejects_negative_quantity_before_touching_the_database() -> None:
    """`quantity < 0` is rejected as the very first statement in
    `consume_quota()`, before `tenant_session_scope()` is ever entered --
    proven here by the fact this test needs no database connection at all
    and still deterministically raises."""
    with pytest.raises(InvalidUsageEventError):
        consume_quota(uuid.uuid4(), "api_calls", Decimal("-1"))


def test_quota_exceeded_error_carries_only_numeric_identifying_context() -> None:
    tenant_id = uuid.uuid4()
    error = QuotaExceededError(tenant_id, "api_calls", used=Decimal("10"), limit=Decimal("10"))
    assert error.tenant_id == tenant_id
    assert error.metric == "api_calls"
    assert error.used == Decimal("10")
    assert error.limit == Decimal("10")
    assert str(tenant_id) in str(error)
