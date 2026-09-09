"""Unit tests for `control_plane.data_authorization.service.evaluate_data_authorization`
(ADR-0013; docs/IMPLEMENTATION-ROADMAP.md Phase 9.2). Pure-function logic
-- no database required, part of the default `pytest` run.
"""

from __future__ import annotations

import uuid

import pytest

from control_plane.data_authorization import (
    DataAuthorizationOutcome,
    DataAuthorizationRequest,
    DataDenialReason,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    evaluate_data_authorization,
)

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()

PROVIDER_POLICY = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic", "openai"}))

TENANT_A_POLICY = TenantAIDataPolicy(
    tenant_id=TENANT_A,
    allowed_data_classifications=frozenset({"tenant_data"}),
    allowed_purposes=frozenset({"support_response_drafting"}),
    allowed_providers=frozenset({"anthropic"}),
)


def _request(**overrides: object) -> DataAuthorizationRequest:
    defaults: dict[str, object] = {
        "tenant_id": TENANT_A,
        "data_classification": "tenant_data",
        "purpose": "support_response_drafting",
        "provider": "anthropic",
        "resource_type": "support_ticket",
        "resource_id": "ticket-1",
    }
    defaults.update(overrides)
    return DataAuthorizationRequest(**defaults)  # type: ignore[arg-type]


class TestExplicitAllow:
    def test_fully_permitted_request_is_allowed(self) -> None:
        decision = evaluate_data_authorization(
            _request(), tenant_policy=TENANT_A_POLICY, provider_policy=PROVIDER_POLICY
        )
        assert decision.outcome is DataAuthorizationOutcome.ALLOW
        assert decision.is_allowed
        assert decision.reason is None


class TestDefaultDeny:
    def test_no_tenant_policy_denies(self) -> None:
        decision = evaluate_data_authorization(
            _request(), tenant_policy=None, provider_policy=PROVIDER_POLICY
        )
        assert decision.outcome is DataAuthorizationOutcome.DENY
        assert decision.reason is DataDenialReason.NO_TENANT_POLICY

    def test_unclassified_data_denies(self) -> None:
        decision = evaluate_data_authorization(
            _request(data_classification=""),
            tenant_policy=TENANT_A_POLICY,
            provider_policy=PROVIDER_POLICY,
        )
        assert decision.outcome is DataAuthorizationOutcome.DENY
        assert decision.reason is DataDenialReason.UNCLASSIFIED_DATA

    def test_unknown_classification_value_denies(self) -> None:
        decision = evaluate_data_authorization(
            _request(data_classification="top_secret"),
            tenant_policy=TENANT_A_POLICY,
            provider_policy=PROVIDER_POLICY,
        )
        assert decision.outcome is DataAuthorizationOutcome.DENY
        assert decision.reason is DataDenialReason.UNCLASSIFIED_DATA


class TestWrongScopeAndPurpose:
    def test_data_class_not_permitted_by_tenant_policy_denies(self) -> None:
        decision = evaluate_data_authorization(
            _request(data_classification="sensitive"),
            tenant_policy=TENANT_A_POLICY,
            provider_policy=PROVIDER_POLICY,
        )
        assert decision.reason is DataDenialReason.DATA_CLASS_NOT_PERMITTED

    def test_wrong_purpose_denies(self) -> None:
        decision = evaluate_data_authorization(
            _request(purpose="unrelated_purpose"),
            tenant_policy=TENANT_A_POLICY,
            provider_policy=PROVIDER_POLICY,
        )
        assert decision.reason is DataDenialReason.PURPOSE_NOT_PERMITTED

    def test_provider_not_globally_eligible_denies(self) -> None:
        decision = evaluate_data_authorization(
            _request(provider="some_untrusted_provider"),
            tenant_policy=TENANT_A_POLICY,
            provider_policy=PROVIDER_POLICY,
        )
        assert decision.reason is DataDenialReason.PROVIDER_NOT_GLOBALLY_ELIGIBLE

    def test_provider_globally_eligible_but_not_tenant_permitted_denies(self) -> None:
        # "openai" is globally eligible (PROVIDER_POLICY) but Tenant A's own
        # policy only permits "anthropic" -- narrowing, never widening.
        decision = evaluate_data_authorization(
            _request(provider="openai"),
            tenant_policy=TENANT_A_POLICY,
            provider_policy=PROVIDER_POLICY,
        )
        assert decision.reason is DataDenialReason.PROVIDER_NOT_PERMITTED


class TestCrossTenantPolicyIsolation:
    def test_tenant_bs_policy_does_not_authorize_tenant_as_request(self) -> None:
        """A `TenantAIDataPolicy` object for the *wrong* tenant must never
        authorize a request for a different tenant, even if its allow-lists
        would otherwise match -- proves the policy's own `tenant_id` is
        checked, not merely its contents."""
        tenant_b_policy = TenantAIDataPolicy(
            tenant_id=TENANT_B,
            allowed_data_classifications=frozenset({"tenant_data"}),
            allowed_purposes=frozenset({"support_response_drafting"}),
            allowed_providers=frozenset({"anthropic"}),
        )
        decision = evaluate_data_authorization(
            _request(tenant_id=TENANT_A),
            tenant_policy=tenant_b_policy,
            provider_policy=PROVIDER_POLICY,
        )
        assert decision.outcome is DataAuthorizationOutcome.DENY
        assert decision.reason is DataDenialReason.NO_TENANT_POLICY


class TestDeterminism:
    def test_same_inputs_produce_same_outcome_and_reason(self) -> None:
        first = evaluate_data_authorization(
            _request(), tenant_policy=TENANT_A_POLICY, provider_policy=PROVIDER_POLICY
        )
        second = evaluate_data_authorization(
            _request(), tenant_policy=TENANT_A_POLICY, provider_policy=PROVIDER_POLICY
        )
        assert first.outcome == second.outcome
        assert first.reason == second.reason


class TestDecisionInvariant:
    def test_decision_construction_rejects_allow_with_reason(self) -> None:
        from control_plane.data_authorization.models import DataAuthorizationDecision

        with pytest.raises(AssertionError):
            DataAuthorizationDecision(
                outcome=DataAuthorizationOutcome.ALLOW,
                tenant_id=TENANT_A,
                data_classification="tenant_data",
                purpose="x",
                provider="anthropic",
                reason=DataDenialReason.NO_TENANT_POLICY,
            )

    def test_decision_construction_rejects_deny_without_reason(self) -> None:
        from control_plane.data_authorization.models import DataAuthorizationDecision

        with pytest.raises(AssertionError):
            DataAuthorizationDecision(
                outcome=DataAuthorizationOutcome.DENY,
                tenant_id=TENANT_A,
                data_classification="tenant_data",
                purpose="x",
                provider="anthropic",
                reason=None,
            )
