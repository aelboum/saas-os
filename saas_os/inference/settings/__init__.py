"""`saas_os.inference.settings` -- the supported public interface for a
tenant's own AI settings (Gap 20, decision 1 (H3): "Python API first";
ADR-0054 section 3a, amendment of 2026-11-17; issue #285).

A thin facade, like `saas_os.inference`: each function is one delegating call
to the internal `saas_os.control_plane.inference` with the caller's own
arguments, and adds nothing. Every guarantee of the internal functions holds
unchanged: the tenant permission checks (`ai.policy:manage`,
`ai.policy:read`, `ai.budget:manage`, `ai.usage:read`), support access
never satisfying them, grant-time validation, the platform hold overriding
every tenant setting at call time, the tenant audit row in the same
transaction as each change (a refusal writes a `denied` row), and RLS.

Tenant-level only. Platform operations (providers, models, aliases, trust,
installation destination policy, plan budgets, overrides, holds, reservation
release) stay operator-only (`saas-os-operator ai-*`). The functions are
synchronous and open their own transaction; an async route calls them in a
thread (for example `anyio.to_thread.run_sync`).

AI is off for every tenant until a caller holding `ai.policy:manage` turns it
on:

    from saas_os.inference.settings import (
        grant_destination, grant_use_case, set_tenant_ai_policy,
    )

    set_tenant_ai_policy(tenant_id, enabled=True, caller=caller)
    grant_use_case(tenant_id, use_case="support.summarize",
                   classifications=["tenant_data"], caller=caller)
    grant_destination(tenant_id, use_case="support.summarize",
                      provider_key="acme", model_id="acme-chat-1",
                      classifications=["tenant_data"], caller=caller)

A refused permission raises `saas_os.core.rbac.AuthorityNotAuthorizedError`.
Products own their routes (`docs/HTTP-CAPABILITY-MATRIX.md`); SaaS OS has
no route for these settings.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from decimal import Decimal

from saas_os.control_plane.inference import budget_admin as _budget_admin
from saas_os.control_plane.inference import eligibility as _eligibility
from saas_os.control_plane.inference.budget import BudgetState, BudgetStatus
from saas_os.control_plane.inference.budget_admin import AIBudgetError, TenantBudgetCapView
from saas_os.control_plane.inference.config import tenant_policy as _tenant_policy
from saas_os.control_plane.inference.config.errors import (
    AIConfigurationNotFoundError,
    AITenantPolicyError,
)
from saas_os.control_plane.inference.config.tenant_policy import (
    DestinationGrantView,
    TenantAIPolicyView,
    TenantAIPreferencesView,
    UseCaseGrantView,
)
from saas_os.control_plane.inference.eligibility import EligibleModelView


def set_tenant_ai_policy(tenant_id: uuid.UUID, *, enabled: bool, caller: object) -> bool:
    """Turn the tenant's AI on or off as a whole. `ai.policy:manage`."""
    return _tenant_policy.set_tenant_ai_policy(tenant_id, enabled=enabled, caller=caller)


def grant_use_case(
    tenant_id: uuid.UUID,
    *,
    use_case: str,
    classifications: Sequence[str],
    enabled: bool = True,
    caller: object,
) -> UseCaseGrantView:
    """Allow (or with `enabled=False`, disable) a use case and the
    classifications it may carry. `ai.policy:manage`."""
    return _tenant_policy.grant_use_case(
        tenant_id,
        use_case=use_case,
        classifications=classifications,
        enabled=enabled,
        caller=caller,
    )


def grant_destination(
    tenant_id: uuid.UUID,
    *,
    use_case: str,
    provider_key: str,
    model_id: str,
    classifications: Sequence[str],
    enabled: bool = True,
    caller: object,
) -> DestinationGrantView:
    """Allow (or disable) one catalogue model for a use case, with the
    classifications that may be sent to it. Refused
    (`AITenantPolicyError`, `blocked_by`) when the model is disabled or
    retired, installation policy does not allow it, or it fails the
    tenant's own requirements. `ai.policy:manage`."""
    return _tenant_policy.grant_destination(
        tenant_id,
        use_case=use_case,
        provider_key=provider_key,
        model_id=model_id,
        classifications=classifications,
        enabled=enabled,
        caller=caller,
    )


def set_destination_rank(
    tenant_id: uuid.UUID,
    *,
    use_case: str,
    provider_key: str,
    model_id: str,
    rank: int | None,
    caller: object,
) -> DestinationGrantView:
    """Order a model the tenant already granted (lower is tried first; None
    clears). Never makes a model eligible. `ai.policy:manage`."""
    return _tenant_policy.set_destination_rank(
        tenant_id,
        use_case=use_case,
        provider_key=provider_key,
        model_id=model_id,
        rank=rank,
        caller=caller,
    )


def set_tenant_ai_preferences(
    tenant_id: uuid.UUID,
    *,
    allowed_residency: Sequence[str] = (),
    max_retention_days: int | None = None,
    exclude_training_use: bool = False,
    caller: object,
) -> TenantAIPreferencesView:
    """The tenant's data-handling requirements; they only narrow which
    models are eligible. `ai.policy:manage`."""
    return _tenant_policy.set_tenant_ai_preferences(
        tenant_id,
        allowed_residency=allowed_residency,
        max_retention_days=max_retention_days,
        exclude_training_use=exclude_training_use,
        caller=caller,
    )


def read_tenant_ai_policy(tenant_id: uuid.UUID, *, caller: object) -> TenantAIPolicyView:
    """The tenant's AI policy, grants and preferences. `ai.policy:read`."""
    return _tenant_policy.read_tenant_ai_policy(tenant_id, caller=caller)


def list_eligible_models(
    tenant_id: uuid.UUID,
    *,
    use_case: str,
    caller: object,
    alias: str | None = None,
    classification: str | None = None,
) -> tuple[EligibleModelView, ...]:
    """Every catalogue model for one registered use case, with whether the
    tenant may use it and why not (`blocked_by`). Capabilities are those of
    the default runtime. `ai.policy:read`."""
    return _eligibility.list_eligible_models(
        tenant_id,
        use_case=use_case,
        caller=caller,
        alias=alias,
        classification=classification,
    )


def set_tenant_budget_cap(
    tenant_id: uuid.UUID,
    *,
    currency: str,
    amount: Decimal | None,
    caller: object,
    warn_thresholds: Sequence[int] | None = None,
) -> TenantBudgetCapView:
    """The tenant's own monthly cap (None removes it) and warning
    thresholds. The cap only ever lowers the platform budget.
    `ai.budget:manage`, a user only."""
    return _budget_admin.set_tenant_budget_cap(
        tenant_id,
        currency=currency,
        amount=amount,
        caller=caller,
        warn_thresholds=warn_thresholds,
    )


def read_tenant_budget(tenant_id: uuid.UUID, *, caller: object) -> BudgetStatus:
    """The tenant's budget this UTC month, from the tenant's own plans.
    `ai.usage:read`, a user only; audited."""
    return _budget_admin.read_tenant_budget(tenant_id, caller=caller)


__all__ = [
    "AIBudgetError",
    "AIConfigurationNotFoundError",
    "AITenantPolicyError",
    "BudgetState",
    "BudgetStatus",
    "DestinationGrantView",
    "EligibleModelView",
    "TenantAIPolicyView",
    "TenantAIPreferencesView",
    "TenantBudgetCapView",
    "UseCaseGrantView",
    "grant_destination",
    "grant_use_case",
    "list_eligible_models",
    "read_tenant_ai_policy",
    "read_tenant_budget",
    "set_destination_rank",
    "set_tenant_ai_preferences",
    "set_tenant_ai_policy",
    "set_tenant_budget_cap",
]
