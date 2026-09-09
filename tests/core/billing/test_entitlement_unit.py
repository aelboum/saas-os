"""Unit tests for P1.9's `has_entitlement()`/`require_entitlement()` --
`core.billing.service.get_entitlements()` is monkeypatched, so these
exercise only the boolean-capability-gate logic itself, never a real
PostgreSQL plan/subscription lookup (`tests/core/billing/test_billing_integration.py`
and the new isolation/enforcement integration tests cover that).
"""

from __future__ import annotations

import uuid

import core.billing.service as billing_service
import pytest
from core.billing.errors import EntitlementDeniedError
from core.billing.service import has_entitlement, require_entitlement


def _tenant() -> uuid.UUID:
    return uuid.uuid4()


def test_has_entitlement_true_when_plan_grants_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(billing_service, "get_entitlements", lambda tenant_id: {"reports": True})
    assert has_entitlement(_tenant(), "reports") is True


def test_has_entitlement_false_when_key_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(billing_service, "get_entitlements", lambda tenant_id: {})
    assert has_entitlement(_tenant(), "reports") is False


def test_has_entitlement_false_when_value_is_explicitly_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(billing_service, "get_entitlements", lambda tenant_id: {"reports": False})
    assert has_entitlement(_tenant(), "reports") is False


def test_has_entitlement_false_for_a_numeric_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """A numeric quota metric sharing the same entitlements dict must
    never be mistaken for a granted boolean capability (module docstring:
    entitlement vs. quota are distinct concepts in the same dict)."""
    monkeypatch.setattr(billing_service, "get_entitlements", lambda tenant_id: {"api_calls": 1})
    assert has_entitlement(_tenant(), "api_calls") is False


def test_has_entitlement_false_with_no_active_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(billing_service, "get_entitlements", lambda tenant_id: {})
    assert has_entitlement(_tenant(), "anything") is False


def test_require_entitlement_passes_silently_when_granted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(billing_service, "get_entitlements", lambda tenant_id: {"reports": True})
    require_entitlement(_tenant(), "reports")  # must not raise


def test_require_entitlement_raises_when_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(billing_service, "get_entitlements", lambda tenant_id: {})
    tenant_id = _tenant()
    with pytest.raises(EntitlementDeniedError) as excinfo:
        require_entitlement(tenant_id, "reports")
    assert excinfo.value.tenant_id == tenant_id
    assert excinfo.value.key == "reports"


def test_entitlement_denied_error_never_echoes_the_full_entitlements_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security: the exception message must carry only the key, never any
    other entitlement/plan detail that happened to be in the dict."""
    monkeypatch.setattr(
        billing_service,
        "get_entitlements",
        lambda tenant_id: {"secret_internal_flag": "should-not-leak"},
    )
    with pytest.raises(EntitlementDeniedError) as excinfo:
        require_entitlement(_tenant(), "reports")
    assert "should-not-leak" not in str(excinfo.value)
    assert "secret_internal_flag" not in str(excinfo.value)
