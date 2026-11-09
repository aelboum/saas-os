"""The tenant's view of which catalogue models it may use (ADR-0054 amendment
of 2026-11-09, Gap 20a).

`list_eligible_models` returns one `EligibleModelView` per catalogue model for
a use case (and, optionally, an alias): whether the tenant granted it, whether
`run_inference` would be allowed to use it, and every reason it would not, as a
closed set of codes in four families:

- **unavailable**: not in the alias (`not_in_alias`, `alias_unavailable`);
- **blocked**: a policy or preference violation (`destination_policy_denied`,
  `residency`, `retention`, `training_use`, `capability`, `not_granted`,
  `use_case_not_granted`, `classification_not_granted_for_use_case`);
- **suspended**: the platform holds the tenant's AI (`tenant_ai_held`);
- **disabled**: a switch is off (`tenant_ai_disabled`, `provider_disabled`,
  `credential_unbound`, `model_disabled`, `model_retired`).

It adds no policy logic: the per-model reasons are `resolution.policy_blockers`
and `tenant_policy.preference_violations`, the same functions `evaluate` keeps
a candidate by, over the same `Candidate` facts. It never returns an endpoint,
a credential reference or a secret (`credential_bound` only). Authority:
`ai.policy:read` at the tenant, users and service accounts only. It writes
nothing and, like `read_tenant_ai_policy`, writes no audit row.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.config.errors import AITenantPolicyError
from saas_os.control_plane.inference.config.hold import tenant_ai_held
from saas_os.control_plane.inference.config.models import AIAlias, AIModel, AIProvider
from saas_os.control_plane.inference.config.tenant_policy import load_tenant_ai_policy
from saas_os.control_plane.inference.permissions import AI_POLICY
from saas_os.control_plane.inference.resolution import (
    Candidate,
    Snapshot,
    build_candidate,
    policy_blockers,
)
from saas_os.control_plane.inference.types import CLASSIFICATIONS
from saas_os.control_plane.inference.use_cases import registered_use_case
from saas_os.core.authority import ServiceAccountCaller, UserCaller, require_caller
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import authorize_caller
from saas_os.core.tenancy import require_open_tenant
from saas_os.infra.db import select, tenant_session_scope

FAMILY_UNAVAILABLE = "unavailable"
FAMILY_BLOCKED = "blocked"
FAMILY_SUSPENDED = "suspended"
FAMILY_DISABLED = "disabled"

REASON_FAMILIES: Mapping[str, str] = {
    "not_in_alias": FAMILY_UNAVAILABLE,
    "alias_unavailable": FAMILY_UNAVAILABLE,
    "destination_policy_denied": FAMILY_BLOCKED,
    "residency": FAMILY_BLOCKED,
    "retention": FAMILY_BLOCKED,
    "training_use": FAMILY_BLOCKED,
    "capability": FAMILY_BLOCKED,
    "not_granted": FAMILY_BLOCKED,
    "use_case_not_granted": FAMILY_BLOCKED,
    "classification_not_granted_for_use_case": FAMILY_BLOCKED,
    "tenant_ai_held": FAMILY_SUSPENDED,
    "tenant_ai_disabled": FAMILY_DISABLED,
    "provider_disabled": FAMILY_DISABLED,
    "credential_unbound": FAMILY_DISABLED,
    "model_disabled": FAMILY_DISABLED,
    "model_retired": FAMILY_DISABLED,
}


@dataclass(frozen=True)
class EligibleModelView:
    provider_key: str
    model_id: str
    lifecycle: str
    capabilities: tuple[str, ...]
    data_handling: Mapping[str, object]
    credential_bound: bool
    granted: bool
    preference_rank: int | None
    eligible: bool
    blocked_by: tuple[str, ...]
    families: tuple[str, ...]


def list_eligible_models(
    tenant_id: uuid.UUID,
    *,
    use_case: str,
    caller: object,
    alias: str | None = None,
    classification: str | None = None,
    adapter_capabilities: Mapping[str, frozenset[Capability]] | None = None,
) -> tuple[EligibleModelView, ...]:
    """Every catalogue model, for one use case, with whether the tenant may use
    it and why not. `classification` defaults to the use case's ceiling (the
    most the use case may carry). With `alias`, a model that alias does not
    list is `not_in_alias`. `adapter_capabilities` defaults to the default
    runtime's adapters. Authority: `ai.policy:read` at the tenant."""
    require_caller("ai_policy.read", caller)
    if not isinstance(caller, (UserCaller, ServiceAccountCaller)):
        raise AuthorityNotAuthorizedError("ai_policy.read", tenant_id)
    registered = registered_use_case(use_case) if isinstance(use_case, str) else None
    if registered is None:
        raise AITenantPolicyError("use_case_not_registered")
    chosen = classification if classification is not None else registered.max_classification
    if chosen not in CLASSIFICATIONS:
        raise AITenantPolicyError("invalid_classifications")
    if adapter_capabilities is None:
        from saas_os.control_plane.inference.service import default_runtime

        adapter_capabilities = default_runtime().adapter_capabilities()
    required = {Capability.TEXT_INPUT, Capability.TEXT_OUTPUT} | set(
        registered.required_capabilities
    )
    required_values = {c.value for c in required}
    require_open_tenant(tenant_id)
    now = datetime.now(UTC)
    with tenant_session_scope(tenant_id) as session:
        authorize_caller(
            caller,
            session=session,
            operation="ai_policy.read",
            tenant_id=tenant_id,
            resource=AI_POLICY,
            action="read",
        )
        policy = load_tenant_ai_policy(session, tenant_id)
        held = tenant_ai_held(session, tenant_id)
        alias_row = (
            session.execute(select(AIAlias).where(AIAlias.alias == alias)).scalar_one_or_none()
            if alias is not None
            else None
        )
        pairs = session.execute(
            select(AIModel, AIProvider)
            .join(AIProvider, AIProvider.id == AIModel.provider_id)
            .order_by(AIProvider.key, AIModel.model_id)
        ).all()
        grant = next((u for u in policy.use_cases if u.use_case == use_case and u.enabled), None)
        tenant_level: list[str] = []
        if held:
            tenant_level.append("tenant_ai_held")
        if not policy.exists or not policy.enabled:
            tenant_level.append("tenant_ai_disabled")
        if grant is None:
            tenant_level.append("use_case_not_granted")
        elif chosen not in grant.classifications:
            tenant_level.append("classification_not_granted_for_use_case")
        if alias is not None and (alias_row is None or alias_row.status != "active"):
            tenant_level.append("alias_unavailable")
        in_alias = {uuid.UUID(raw) for raw in (alias_row.candidates if alias_row else [])}
        snapshot = Snapshot(
            tenant_policy_exists=policy.exists,
            tenant_policy_enabled=policy.enabled,
            tenant_policy_version=policy.version,
            use_case_grant=frozenset(grant.classifications) if grant else None,
            alias_active=alias_row is not None and alias_row.status == "active",
            alias_version=alias_row.version if alias_row is not None else 0,
            tenant_held=held,
            candidates=(),
            preferences=policy.preferences,
            tenant_id=tenant_id,
        )
        views: list[EligibleModelView] = []
        for model, provider in pairs:
            candidate: Candidate = build_candidate(
                session,
                policy,
                model,
                provider,
                use_case=use_case,
                classification=chosen,
                now=now,
            )
            blocked = list(tenant_level)
            if alias is not None and model.id not in in_alias:
                blocked.append("not_in_alias")
            blocked.extend(
                policy_blockers(snapshot, candidate, use_case=use_case, classification=chosen)
            )
            adapter_caps = {
                c.value for c in adapter_capabilities.get(candidate.protocol, frozenset())
            }
            if not required_values <= candidate.capabilities or not required_values <= adapter_caps:
                blocked.append("capability")
            codes = tuple(dict.fromkeys(blocked))
            views.append(
                EligibleModelView(
                    provider_key=candidate.provider_key,
                    model_id=candidate.model_id,
                    lifecycle=model.lifecycle,
                    capabilities=tuple(sorted(candidate.capabilities)),
                    data_handling=dict(candidate.data_handling),
                    credential_bound=candidate.credential_bound,
                    granted=candidate.tenant_grant is not None,
                    preference_rank=candidate.preference_rank,
                    eligible=not codes,
                    blocked_by=codes,
                    families=tuple(sorted({REASON_FAMILIES[c] for c in codes})),
                )
            )
        return tuple(views)
