"""A tenant's own AI settings, as a product manages them (Gap 20, issue #285).

Ordinary consumer code against the public interface
`saas_os.inference.settings` only -- never `saas_os.control_plane.inference`.
The platform operator has already configured the catalogue (provider, model,
alias, installation destination policy) with `saas-os-operator ai-*`; what
follows is the tenant's decision, made by a user of the tenant who holds
`ai.policy:manage` (and `ai.budget:manage` for the cap):

1. turn AI on for the tenant (it is off until then);
2. allow the product's use case for the classifications it carries;
3. allow one catalogue model for that use case, and rank it first;
4. state the tenant's data-handling requirements;
5. optionally lower the tenant's monthly AI budget.

SaaS OS checks every step: the caller's permission (support access never
satisfies it), that the model is one the platform allows and that meets the
tenant's requirements, and it writes a tenant audit row for each change. A
platform hold on the tenant still refuses every call, whatever is set here.
The functions are synchronous; a product route calls them in a thread.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from reference_consumer.inference import SUMMARIZE_NOTE
from saas_os.inference.settings import (
    EligibleModelView,
    TenantAIPolicyView,
    grant_destination,
    grant_use_case,
    list_eligible_models,
    read_tenant_ai_policy,
    set_destination_rank,
    set_tenant_ai_policy,
    set_tenant_ai_preferences,
    set_tenant_budget_cap,
)

NOTE_CLASSIFICATIONS = ("none", "tenant_data")


def enable_note_summaries(
    caller: object, *, tenant_id: uuid.UUID, provider_key: str, model_id: str
) -> TenantAIPolicyView:
    """Turn on note summaries for the tenant with one chosen model, never
    letting the provider use the tenant's data for training."""
    set_tenant_ai_policy(tenant_id, enabled=True, caller=caller)
    grant_use_case(
        tenant_id,
        use_case=SUMMARIZE_NOTE.name,
        classifications=NOTE_CLASSIFICATIONS,
        caller=caller,
    )
    set_tenant_ai_preferences(tenant_id, exclude_training_use=True, caller=caller)
    grant_destination(
        tenant_id,
        use_case=SUMMARIZE_NOTE.name,
        provider_key=provider_key,
        model_id=model_id,
        classifications=NOTE_CLASSIFICATIONS,
        caller=caller,
    )
    set_destination_rank(
        tenant_id,
        use_case=SUMMARIZE_NOTE.name,
        provider_key=provider_key,
        model_id=model_id,
        rank=0,
        caller=caller,
    )
    return read_tenant_ai_policy(tenant_id, caller=caller)


def note_summary_models(caller: object, *, tenant_id: uuid.UUID) -> tuple[EligibleModelView, ...]:
    """Every catalogue model for note summaries, with why a model may not be
    chosen -- what a settings page shows."""
    return list_eligible_models(tenant_id, use_case=SUMMARIZE_NOTE.name, caller=caller)


def cap_monthly_ai_spend(
    caller: object, *, tenant_id: uuid.UUID, currency: str, amount: Decimal
) -> None:
    """Lower the tenant's own monthly AI budget; it never raises the plan's."""
    set_tenant_budget_cap(tenant_id, currency=currency, amount=amount, caller=caller)
