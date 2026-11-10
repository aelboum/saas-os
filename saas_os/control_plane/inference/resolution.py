"""Validation, classification and destination eligibility (ADR-0055 sections
2-4 and 6; AI-INFERENCE-CONTRACTS section 5 steps 2-3).

`validate_request` checks the request against its registered use case and
computes the effective classification (the highest of its parts). It reads
nothing.

`load_snapshot` reads, in the caller's tenant transaction, the global
configuration (no RLS) and the tenant's own policy (tenant RLS) for one alias
and use case. `evaluate` decides, from that snapshot alone, which of the
alias's candidates may receive the request. Each check is independent; every
one must pass (ADR-0055 section 4):

0. the platform has not placed a hold on the tenant's AI
   (`config.hold`; ADR-0054 amendment of 2026-11-09). Checked before the
   tenant's policy and overriding it: a held tenant is refused with
   `tenant_ai_held` whatever its policy and grants say;
1. the use case is registered and the classification is within its ceiling;
2. the tenant's AI policy exists and is enabled;
3. the tenant granted the use case, enabled, for the classification;
4. the alias exists and is active;
and, per candidate:
5. the provider is active and its credential is bound to its endpoint origin;
6. the model is not disabled and not past `retire_after`;
7. installation policy allows the provider for the classification;
8. the tenant granted that model as a destination of the use case, enabled,
   for the classification, and the ADR-0013 evaluator
   (`evaluate_data_authorization`) allows that destination;
9. the model and the adapter support every required capability, and the
   model's output limit covers the request;
10. the provider's declared data handling meets the tenant's preferences
    (AI-E): residency within the allowed regions, retention at most the
    maximum, no training use when excluded. Undeclared handling fails any
    requirement. Preferences only ever narrow eligibility.

A denial is never a reason to try another destination: policy failures of
checks 1-4 deny the request; a candidate failing 5-8 is simply not
eligible; if no candidate is eligible the request is denied, and if some
pass 5-8 but none passes 9 the request is `unsupported_capability`.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from saas_os.control_plane.data_authorization import (
    DataAuthorizationOutcome,
    DataAuthorizationRequest,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    evaluate_data_authorization,
)
from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.config.hold import tenant_ai_held
from saas_os.control_plane.inference.config.models import (
    AIAlias,
    AIDestinationPolicy,
    AIEndpointTrust,
    AIModel,
    AIProvider,
)
from saas_os.control_plane.inference.config.service import endpoint_origin
from saas_os.control_plane.inference.config.tenant_policy import (
    TenantAIPolicyView,
    TenantAIPreferencesView,
    load_tenant_ai_policy,
    preference_violations,
)
from saas_os.control_plane.inference.errors import (
    InferenceInvalidRequestError,
    InferencePolicyDeniedError,
    InferenceUnsupportedCapabilityError,
)
from saas_os.control_plane.inference.types import (
    CLASSIFICATION_RANK,
    CLASSIFICATIONS,
    InferenceRequest,
)
from saas_os.control_plane.inference.use_cases import UseCase, registered_use_case
from saas_os.infra.db import Session, select
from saas_os.infra.egress import TrustedEndpoint

MAX_STOP_SEQUENCES = 4
MAX_STOP_LENGTH = 64
MAX_CLIENT_REQUEST_ID = 128
_MAX_OUTPUT_TOKENS = 1_000_000


@dataclass(frozen=True)
class ValidatedRequest:
    use_case: UseCase
    effective_classification: str
    required_capabilities: frozenset[Capability]
    system: str | None = field(repr=False)
    turns: tuple[tuple[str, str], ...] = field(repr=False)  # (role, text)
    input_bytes: int


def validate_request(request: InferenceRequest) -> ValidatedRequest:
    """Shape, size and classification. Raises before anything is read."""
    if not isinstance(request, InferenceRequest):
        raise InferenceInvalidRequestError("request_type")
    use_case = registered_use_case(request.use_case) if isinstance(request.use_case, str) else None
    if use_case is None:
        raise InferencePolicyDeniedError("use_case_not_registered")
    if not isinstance(request.alias, str) or not 0 < len(request.alias) <= 100:
        raise InferenceInvalidRequestError("alias")
    if (
        isinstance(request.max_output_tokens, bool)
        or not isinstance(request.max_output_tokens, int)
        or not 0 < request.max_output_tokens <= _MAX_OUTPUT_TOKENS
    ):
        raise InferenceInvalidRequestError("max_output_tokens")
    if request.client_request_id is not None and (
        not isinstance(request.client_request_id, str)
        or not 0 < len(request.client_request_id) <= MAX_CLIENT_REQUEST_ID
        or not request.client_request_id.isprintable()
    ):
        raise InferenceInvalidRequestError("client_request_id")
    if request.tools:
        raise InferenceUnsupportedCapabilityError("tools")
    if request.response_format != "text":
        raise InferenceUnsupportedCapabilityError("response_format")
    if request.temperature is not None and (
        isinstance(request.temperature, bool)
        or not isinstance(request.temperature, int | float)
        or not 0.0 <= float(request.temperature) <= 2.0
    ):
        raise InferenceInvalidRequestError("temperature")
    if len(request.stop) > MAX_STOP_SEQUENCES or any(
        not isinstance(s, str) or not 0 < len(s) <= MAX_STOP_LENGTH for s in request.stop
    ):
        raise InferenceInvalidRequestError("stop")
    if not all(isinstance(c, Capability) for c in request.required_capabilities):
        raise InferenceInvalidRequestError("required_capabilities")
    if not request.messages:
        raise InferenceInvalidRequestError("messages")

    rank = -1
    parts = 0
    total = 0
    system_texts: list[str] = []
    turns: list[tuple[str, str]] = []
    for index, message in enumerate(request.messages):
        if message.role == "tool" or message.tool_call_id is not None:
            raise InferenceUnsupportedCapabilityError("tool_messages")
        if message.role not in ("system", "user", "assistant") or not message.parts:
            raise InferenceInvalidRequestError("message")
        texts: list[str] = []
        for part in message.parts:
            parts += 1
            # The classification is checked before anything else of the part.
            if part.classification not in CLASSIFICATIONS:
                raise InferencePolicyDeniedError("invalid_classification")
            if part.kind not in use_case.part_kinds:
                raise InferencePolicyDeniedError("part_kind_not_allowed")
            if part.kind != "text":
                raise InferenceUnsupportedCapabilityError("part_kind")
            if not isinstance(part.text, str):
                raise InferenceInvalidRequestError("part_text")
            rank = max(rank, CLASSIFICATION_RANK[part.classification])
            total += len(part.text.encode("utf-8"))
            texts.append(part.text)
        text = "\n".join(texts)
        if message.role == "system":
            if index != 0:
                raise InferenceInvalidRequestError("system_not_first")
            system_texts.append(text)
        else:
            turns.append((message.role, text))
    if parts > use_case.max_parts:
        raise InferencePolicyDeniedError("too_many_parts")
    if total > use_case.max_input_bytes:
        raise InferencePolicyDeniedError("input_too_large")
    if not turns or turns[-1][0] != "user":
        raise InferenceInvalidRequestError("last_message_must_be_user")
    classification = CLASSIFICATIONS[rank]
    if rank > CLASSIFICATION_RANK[use_case.max_classification]:
        raise InferencePolicyDeniedError("classification_above_use_case_ceiling")

    required = {Capability.TEXT_INPUT, Capability.TEXT_OUTPUT}
    required |= set(request.required_capabilities) | set(use_case.required_capabilities)
    if system_texts:
        required.add(Capability.SYSTEM_INSTRUCTIONS)
    if request.temperature is not None:
        required.add(Capability.TEMPERATURE)
    if request.stop:
        required.add(Capability.STOP_SEQUENCES)
    return ValidatedRequest(
        use_case=use_case,
        effective_classification=classification,
        required_capabilities=frozenset(required),
        system=system_texts[0] if system_texts else None,
        turns=tuple(turns),
        input_bytes=total,
    )


@dataclass(frozen=True)
class Candidate:
    """One alias candidate as configured, with what the tenant and the
    installation decided about it."""

    model_ref: uuid.UUID
    provider_key: str
    protocol: str
    base_url: str = field(repr=False)
    credential_ref: str = field(repr=False)
    credential_bound: bool
    provider_active: bool
    provider_version: int
    model_id: str
    capabilities: frozenset[str]
    max_output_tokens: int
    model_usable: bool
    model_version: int
    installation_allows: bool
    tenant_grant: frozenset[str] | None  # None: no enabled grant
    trusted_endpoints: tuple[TrustedEndpoint, ...] = ()
    data_handling: dict = field(default_factory=dict)
    # The tenant's own order among its granted models (Gap 20a): lower first,
    # `None` after every ranked grant. Orders the eligible candidates only.
    preference_rank: int | None = None
    model_retired: bool = False


@dataclass(frozen=True)
class Snapshot:
    tenant_policy_exists: bool
    tenant_policy_enabled: bool
    tenant_policy_version: int
    use_case_grant: frozenset[str] | None  # None: no enabled grant
    alias_active: bool
    alias_version: int
    # Required, never defaulted: a snapshot built without an answer about the
    # platform hold must not silently mean "not held".
    tenant_held: bool
    candidates: tuple[Candidate, ...]
    preferences: TenantAIPreferencesView = TenantAIPreferencesView()
    tenant_id: uuid.UUID = field(default_factory=uuid.uuid4)


def _trusted(session: Session, base_url: str, now: datetime) -> tuple[TrustedEndpoint, ...]:
    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    port = parts.port if parts.port is not None else 443
    rows = (
        session.execute(
            select(AIEndpointTrust).where(
                AIEndpointTrust.host == host,
                AIEndpointTrust.port == port,
                AIEndpointTrust.revoked_at.is_(None),
                AIEndpointTrust.expires_at > now,
            )
        )
        .scalars()
        .all()
    )
    return tuple(
        TrustedEndpoint(
            host=row.host,
            port=row.port,
            networks=tuple(ipaddress.ip_network(n) for n in row.networks),
        )
        for row in rows
    )


def build_candidate(
    session: Session,
    policy: TenantAIPolicyView,
    model: AIModel,
    provider: AIProvider,
    *,
    use_case: str,
    classification: str,
    now: datetime,
) -> Candidate:
    """One model as configured, with what the installation and the tenant
    decided about it. The only place a `Candidate` is built, so the call-time
    snapshot and the eligibility view read the same facts."""
    allowed = session.execute(
        select(AIDestinationPolicy.allowed).where(
            AIDestinationPolicy.provider_id == provider.id,
            AIDestinationPolicy.classification == classification,
        )
    ).scalar_one_or_none()
    destination = next(
        (
            d
            for d in policy.destinations
            if d.use_case == use_case and d.model_ref == model.id and d.enabled
        ),
        None,
    )
    retired = model.retire_after is not None and model.retire_after <= now
    return Candidate(
        model_ref=model.id,
        provider_key=provider.key,
        protocol=provider.protocol,
        base_url=provider.base_url,
        credential_ref=provider.credential_ref,
        credential_bound=provider.credential_origin is not None
        and provider.credential_origin == endpoint_origin(provider.base_url),
        provider_active=provider.status == "active",
        provider_version=provider.version,
        model_id=model.model_id,
        capabilities=frozenset(model.capabilities),
        max_output_tokens=model.max_output_tokens,
        model_usable=model.lifecycle != "disabled" and not retired,
        model_version=model.version,
        installation_allows=allowed is True,
        tenant_grant=frozenset(destination.classifications) if destination else None,
        trusted_endpoints=_trusted(session, provider.base_url, now),
        data_handling=dict(provider.data_handling or {}),
        preference_rank=destination.preference_rank if destination else None,
        model_retired=retired,
    )


def load_snapshot(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    alias: str,
    use_case: str,
    classification: str,
) -> Snapshot:
    now = datetime.now(UTC)
    held = tenant_ai_held(session, tenant_id)
    policy = load_tenant_ai_policy(session, tenant_id)
    grant = next((u for u in policy.use_cases if u.use_case == use_case and u.enabled), None)
    alias_row = session.execute(select(AIAlias).where(AIAlias.alias == alias)).scalar_one_or_none()
    candidates: list[Candidate] = []
    if alias_row is not None:
        for raw in alias_row.candidates:
            pair = session.execute(
                select(AIModel, AIProvider)
                .join(AIProvider, AIProvider.id == AIModel.provider_id)
                .where(AIModel.id == uuid.UUID(raw))
            ).first()
            if pair is None:
                continue
            candidates.append(
                build_candidate(
                    session,
                    policy,
                    pair[0],
                    pair[1],
                    use_case=use_case,
                    classification=classification,
                    now=now,
                )
            )
    return Snapshot(
        tenant_policy_exists=policy.exists,
        tenant_policy_enabled=policy.enabled,
        tenant_policy_version=policy.version,
        use_case_grant=frozenset(grant.classifications) if grant else None,
        alias_active=alias_row is not None and alias_row.status == "active",
        alias_version=alias_row.version if alias_row is not None else 0,
        tenant_held=held,
        candidates=tuple(candidates),
        preferences=policy.preferences,
        tenant_id=tenant_id,
    )


def meets_preferences(handling: dict, preferences: TenantAIPreferencesView) -> bool:
    """The tenant's data-handling requirements against a provider's declared
    handling. Nothing declared fails every requirement that is set."""
    return not preference_violations(handling, preferences)


def data_authorization_allows(
    snapshot: Snapshot, candidate: Candidate, *, use_case: str, classification: str
) -> bool:
    """The ADR-0013 gate (ADR-0054 D1; ADR-0055 section 3, checks 2 and 3),
    evaluated for one destination with the tenant's and the installation's
    stored decisions: the tenant allows the classification for the use case
    and the provider; the installation makes the provider eligible for the
    classification. Pure and default-deny; it repeats what routing checked,
    so a routing defect cannot let a destination through on its own."""
    tenant_classes = (snapshot.use_case_grant or frozenset()) & (
        candidate.tenant_grant or frozenset()
    )
    decision = evaluate_data_authorization(
        DataAuthorizationRequest(
            tenant_id=snapshot.tenant_id,
            data_classification=classification,
            purpose=use_case,
            provider=candidate.provider_key,
            resource_type="ai_inference",
        ),
        tenant_policy=TenantAIDataPolicy(
            tenant_id=snapshot.tenant_id,
            allowed_data_classifications=frozenset(tenant_classes),
            allowed_purposes=frozenset({use_case}) if snapshot.use_case_grant else frozenset(),
            allowed_providers=(
                frozenset({candidate.provider_key}) if candidate.tenant_grant else frozenset()
            ),
        ),
        provider_policy=ProviderEligibilityPolicy(
            eligible_providers=(
                frozenset({candidate.provider_key})
                if candidate.installation_allows
                else frozenset()
            )
        ),
    )
    return decision.outcome is DataAuthorizationOutcome.ALLOW


def policy_blockers(
    snapshot: Snapshot, candidate: Candidate, *, use_case: str, classification: str
) -> tuple[str, ...]:
    """Every policy check (ADR-0055 section 4, checks 5-8 and 10) the
    candidate fails, as closed reason codes; empty when it passes them all.
    `evaluate` keeps a candidate exactly when this is empty, and the tenant
    eligibility view reports these codes, so the two cannot disagree."""
    blocked: list[str] = []
    if not candidate.provider_active:
        blocked.append("provider_disabled")
    if not candidate.credential_bound:
        blocked.append("credential_unbound")
    if not candidate.model_usable:
        blocked.append("model_retired" if candidate.model_retired else "model_disabled")
    if not candidate.installation_allows:
        blocked.append("destination_policy_denied")
    if candidate.tenant_grant is None or classification not in candidate.tenant_grant:
        blocked.append("not_granted")
    blocked.extend(preference_violations(candidate.data_handling, snapshot.preferences))
    if (
        not blocked
        and snapshot.use_case_grant is not None
        and classification in snapshot.use_case_grant
        and not data_authorization_allows(
            snapshot, candidate, use_case=use_case, classification=classification
        )
    ):
        # The ADR-0013 gate refused what the checks above allowed (for
        # instance a use case grant that is missing): never let it through.
        blocked.append("destination_policy_denied")
    return tuple(blocked)


@dataclass(frozen=True)
class EligibleCandidate:
    candidate: Candidate
    decision: dict[str, object]


def evaluate(
    snapshot: Snapshot,
    validated: ValidatedRequest,
    *,
    max_output_tokens: int,
    adapter_capabilities: dict[str, frozenset[Capability]],
) -> tuple[EligibleCandidate, ...]:
    """The eligible candidates, in alias order, each with the decision that
    allowed it. Raises `InferencePolicyDeniedError` or
    `InferenceUnsupportedCapabilityError` when none is eligible."""
    classification = validated.effective_classification
    if snapshot.tenant_held:
        raise InferencePolicyDeniedError("tenant_ai_held")
    if not snapshot.tenant_policy_exists or not snapshot.tenant_policy_enabled:
        raise InferencePolicyDeniedError("tenant_policy_absent_or_disabled")
    if snapshot.use_case_grant is None:
        raise InferencePolicyDeniedError("use_case_not_granted")
    if classification not in snapshot.use_case_grant:
        raise InferencePolicyDeniedError("classification_not_granted_for_use_case")
    if not snapshot.alias_active:
        raise InferencePolicyDeniedError("alias_unavailable")

    allowed_by_policy: list[Candidate] = [
        c
        for c in snapshot.candidates
        if not policy_blockers(
            snapshot, c, use_case=validated.use_case.name, classification=classification
        )
    ]
    # The tenant's own order first (lower rank), unranked grants after every
    # ranked one, ties in alias order (the sort is stable). All `None` is
    # exactly alias order. Ranking only orders candidates policy allowed.
    allowed_by_policy.sort(key=lambda c: (c.preference_rank is None, c.preference_rank or 0))
    if not allowed_by_policy:
        raise InferencePolicyDeniedError("no_eligible_destination")
    required = {c.value for c in validated.required_capabilities}
    eligible: list[EligibleCandidate] = []
    for candidate in allowed_by_policy:
        adapter_caps = {c.value for c in adapter_capabilities.get(candidate.protocol, frozenset())}
        if not required <= candidate.capabilities or not required <= adapter_caps:
            continue
        if max_output_tokens > candidate.max_output_tokens:
            continue
        eligible.append(
            EligibleCandidate(
                candidate=candidate,
                decision={
                    "classification": classification,
                    "use_case": validated.use_case.name,
                    "use_case_ceiling": validated.use_case.max_classification,
                    "tenant_policy_version": snapshot.tenant_policy_version,
                    "use_case_grant": sorted(snapshot.use_case_grant),
                    "destination_grant": sorted(candidate.tenant_grant or ()),
                    "installation_policy": True,
                    "data_authorization": "allow",
                    "alias_version": snapshot.alias_version,
                    "preferences_version": snapshot.preferences.version,
                    "provider_version": candidate.provider_version,
                    "model_version": candidate.model_version,
                    "capabilities": sorted(required),
                },
            )
        )
    if not eligible:
        raise InferenceUnsupportedCapabilityError("no_candidate_supports_the_request")
    return tuple(eligible)
