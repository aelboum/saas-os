"""Unit tests for `control_plane.orchestration.service._data_authorization_satisfied`
(P1.1: wiring Data Authorization into AI Control Plane tool execution).
Pure-function logic -- no database required, part of the default `pytest`
run.
"""

from __future__ import annotations

import uuid

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.orchestration.service import _data_authorization_satisfied

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()


def _decision(**overrides: object) -> DataAuthorizationDecision:
    defaults: dict[str, object] = dict(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=TENANT_A,
        data_classification="tenant_data",
        purpose="support_response_drafting",
        provider="anthropic",
        reason=None,
    )
    defaults.update(overrides)
    return DataAuthorizationDecision(**defaults)  # type: ignore[arg-type]


def test_allow_for_matching_tenant_satisfies() -> None:
    assert _data_authorization_satisfied(_decision(), tenant_id=TENANT_A) is True


def test_none_decision_never_satisfies() -> None:
    assert _data_authorization_satisfied(None, tenant_id=TENANT_A) is False


def test_deny_decision_never_satisfies() -> None:
    from control_plane.data_authorization import DataDenialReason

    denied = _decision(
        outcome=DataAuthorizationOutcome.DENY, reason=DataDenialReason.NO_TENANT_POLICY
    )
    assert _data_authorization_satisfied(denied, tenant_id=TENANT_A) is False


def test_allow_for_a_different_tenant_never_satisfies() -> None:
    """A genuinely-computed ALLOW for Tenant B must not satisfy Tenant A's
    invocation -- proves the tenant check, independent of forgery."""
    foreign_allow = _decision(tenant_id=TENANT_B)
    assert _data_authorization_satisfied(foreign_allow, tenant_id=TENANT_A) is False


def test_hand_constructed_allow_for_a_different_tenant_never_satisfies() -> None:
    """A hand-constructed (never audited, never evaluated by
    `evaluate_data_authorization()`) ALLOW claiming a different tenant
    still fails the tenant check -- the same guarantee holds regardless of
    where the decision object came from."""
    forged = DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=uuid.uuid4(),
        data_classification="tenant_data",
        purpose="support_response_drafting",
        provider="anthropic",
        reason=None,
    )
    assert _data_authorization_satisfied(forged, tenant_id=TENANT_A) is False
