"""Gap 20a, hermetic checks (ADR-0054 amendment of 2026-11-09).

- `policy_blockers` is the one definition of "this candidate fails a policy
  check": `evaluate` keeps a candidate exactly when it returns nothing, over
  seeded random candidates, grants, ranks and preferences.
- Ranking: lower rank first, unranked after every ranked one, ties (only among
  unranked) in alias order; all `None` is alias order; ranking never admits a
  candidate policy refused.
- Reason codes of `preference_violations` and the retired/disabled split.
- Every reason code maps to exactly one of the four families.
"""

from __future__ import annotations

import random
import uuid
from typing import Any

import pytest

from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.config.tenant_policy import (
    TenantAIPreferencesView,
    preference_violations,
)
from saas_os.control_plane.inference.eligibility import (
    FAMILY_BLOCKED,
    FAMILY_DISABLED,
    FAMILY_SUSPENDED,
    FAMILY_UNAVAILABLE,
    REASON_FAMILIES,
)
from saas_os.control_plane.inference.errors import (
    InferencePolicyDeniedError,
    InferenceUnsupportedCapabilityError,
)
from saas_os.control_plane.inference.resolution import (
    Candidate,
    Snapshot,
    evaluate,
    meets_preferences,
    policy_blockers,
    validate_request,
)
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.control_plane.inference.use_cases import UseCase, register_use_case

_ALL_CAPS = frozenset(c.value for c in Capability)
_ADAPTERS = {"openai_chat_completions": frozenset(Capability)}
_USE_CASE = register_use_case(UseCase(name="gap20a.unit", max_classification="tenant_data"))


def _candidate(**overrides: Any) -> Candidate:
    values: dict[str, Any] = {
        "model_ref": uuid.uuid4(),
        "provider_key": "p",
        "protocol": "openai_chat_completions",
        "base_url": "https://api.example.com/v1",
        "credential_ref": "KEY",
        "credential_bound": True,
        "provider_active": True,
        "provider_version": 1,
        "model_id": "m",
        "capabilities": _ALL_CAPS,
        "max_output_tokens": 1000,
        "model_usable": True,
        "model_version": 1,
        "installation_allows": True,
        "tenant_grant": frozenset({"none", "tenant_data"}),
    }
    values.update(overrides)
    return Candidate(**values)


def _snapshot(candidates: tuple[Candidate, ...], **overrides: Any) -> Snapshot:
    values: dict[str, Any] = {
        "tenant_policy_exists": True,
        "tenant_policy_enabled": True,
        "tenant_policy_version": 1,
        "use_case_grant": frozenset({"none", "tenant_data"}),
        "alias_active": True,
        "alias_version": 1,
        "tenant_held": False,
        "candidates": candidates,
    }
    values.update(overrides)
    return Snapshot(**values)


def _evaluate(snapshot: Snapshot):
    request = InferenceRequest(
        alias="a",
        use_case=_USE_CASE.name,
        messages=(Message("user", (ContentPart("text", "tenant_data", text="hi"),)),),
        max_output_tokens=100,
    )
    return evaluate(
        snapshot,
        validate_request(request),
        max_output_tokens=100,
        adapter_capabilities=_ADAPTERS,  # type: ignore[arg-type]
    )


def test_evaluate_keeps_exactly_the_candidates_policy_blockers_clears() -> None:
    rng = random.Random(20260110)
    handlings = [
        {},
        {"residency": ["eu"], "retention_days": 5, "training_use": False},
        {"residency": ["us", "eu"], "retention_days": 90, "training_use": True},
        {"residency": ["us"], "retention_days": 0, "training_use": False},
    ]
    for _ in range(300):
        candidates = tuple(
            _candidate(
                provider_key=f"p{i}",
                credential_bound=rng.random() > 0.2,
                provider_active=rng.random() > 0.2,
                model_usable=rng.random() > 0.2,
                installation_allows=rng.random() > 0.2,
                tenant_grant=rng.choice(
                    [None, frozenset({"none"}), frozenset({"none", "tenant_data"})]
                ),
                data_handling=rng.choice(handlings),
                preference_rank=rng.choice([None, None, 0, 1, 2, 3]),
            )
            for i in range(rng.randint(1, 5))
        )
        preferences = TenantAIPreferencesView(
            allowed_residency=tuple(rng.choice([(), ("us",), ("eu", "us")])),
            max_retention_days=rng.choice([None, 0, 30]),
            exclude_training_use=rng.random() > 0.5,
        )
        snapshot = _snapshot(
            candidates,
            preferences=preferences,
            use_case_grant=rng.choice(
                [
                    frozenset({"none", "tenant_data"}),
                    frozenset({"none", "tenant_data", "sensitive"}),
                ]
            ),
        )
        expected = {
            c.provider_key
            for c in candidates
            if not policy_blockers(
                snapshot, c, use_case=_USE_CASE.name, classification="tenant_data"
            )
        }
        try:
            chosen = {e.candidate.provider_key for e in _evaluate(snapshot)}
        except (InferencePolicyDeniedError, InferenceUnsupportedCapabilityError):
            chosen = set()
        assert chosen == expected


def test_all_null_ranks_keep_alias_order() -> None:
    candidates = tuple(_candidate(provider_key=f"p{i}") for i in range(4))
    assert [e.candidate.provider_key for e in _evaluate(_snapshot(candidates))] == [
        "p0",
        "p1",
        "p2",
        "p3",
    ]


def test_lower_rank_first_unranked_last_ties_in_alias_order() -> None:
    candidates = (
        _candidate(provider_key="a"),
        _candidate(provider_key="b", preference_rank=5),
        _candidate(provider_key="c"),
        _candidate(provider_key="d", preference_rank=1),
        _candidate(provider_key="e", preference_rank=0),
    )
    assert [e.candidate.provider_key for e in _evaluate(_snapshot(candidates))] == [
        "e",
        "d",
        "b",
        "a",
        "c",
    ]


def test_a_rank_never_admits_a_candidate_policy_refused() -> None:
    candidates = (
        _candidate(provider_key="refused", preference_rank=0, provider_active=False),
        _candidate(provider_key="allowed"),
    )
    assert [e.candidate.provider_key for e in _evaluate(_snapshot(candidates))] == ["allowed"]


def test_the_decision_does_not_change_with_the_rank() -> None:
    plain = _evaluate(_snapshot((_candidate(provider_key="x"),)))[0].decision
    ranked = _evaluate(_snapshot((_candidate(provider_key="x", preference_rank=2),)))[0].decision
    assert plain == ranked


@pytest.mark.parametrize(
    ("overrides", "codes"),
    [
        ({"provider_active": False}, ("provider_disabled",)),
        ({"credential_bound": False}, ("credential_unbound",)),
        ({"model_usable": False}, ("model_disabled",)),
        ({"model_usable": False, "model_retired": True}, ("model_retired",)),
        ({"installation_allows": False}, ("destination_policy_denied",)),
        ({"tenant_grant": None}, ("not_granted",)),
        ({"tenant_grant": frozenset({"none"})}, ("not_granted",)),
        ({}, ()),
    ],
)
def test_policy_blockers_names_the_failed_check(overrides: dict, codes: tuple[str, ...]) -> None:
    candidate = _candidate(**overrides)
    snapshot = _snapshot((candidate,))
    assert (
        policy_blockers(snapshot, candidate, use_case=_USE_CASE.name, classification="tenant_data")
        == codes
    )


def test_preference_violations_are_closed_codes_and_meets_preferences_is_their_negation() -> None:
    preferences = TenantAIPreferencesView(
        allowed_residency=("us",), max_retention_days=30, exclude_training_use=True
    )
    assert preference_violations({}, preferences) == ("residency", "retention", "training_use")
    assert (
        preference_violations(
            {"residency": ["us"], "retention_days": 30, "training_use": False}, preferences
        )
        == ()
    )
    assert preference_violations(
        {"residency": ["us", "eu"], "retention_days": True, "training_use": None}, preferences
    ) == ("residency", "retention", "training_use")
    for handling in ({}, {"residency": ["us"], "retention_days": 1, "training_use": False}):
        assert meets_preferences(handling, preferences) is (
            not preference_violations(handling, preferences)
        )
    assert preference_violations({}, TenantAIPreferencesView()) == ()


def test_every_reason_code_belongs_to_exactly_one_known_family() -> None:
    families = {FAMILY_UNAVAILABLE, FAMILY_BLOCKED, FAMILY_SUSPENDED, FAMILY_DISABLED}
    assert set(REASON_FAMILIES.values()) == families
    for code in (
        "provider_disabled",
        "credential_unbound",
        "model_disabled",
        "model_retired",
        "destination_policy_denied",
        "residency",
        "retention",
        "training_use",
        "capability",
        "not_granted",
        "not_in_alias",
        "tenant_ai_held",
    ):
        assert code in REASON_FAMILIES, code
    assert REASON_FAMILIES["tenant_ai_held"] == FAMILY_SUSPENDED
    assert REASON_FAMILIES["not_in_alias"] == FAMILY_UNAVAILABLE
