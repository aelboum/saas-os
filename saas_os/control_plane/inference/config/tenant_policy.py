"""The minimum tenant AI policy (ADR-0055 section 7; ADR-0054 Phase AI-C).

A tenant's own decision about what may be sent where:
- the policy as a whole is enabled or disabled;
- each use case is granted (enabled) with the classifications it may carry;
- each destination (a configured model) is granted per use case with the
  classifications that may be sent to it.

Absent or disabled means deny. Written only through the tenant RBAC permission
`ai.policy:manage` (`can()`; never support access, never a platform
permission), with the change and its tenant audit row in one transaction. A
refusal writes a `denied` tenant audit row after the transaction rolled back.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from saas_os.control_plane.inference.config.errors import (
    AIConfigurationNotFoundError,
    AITenantPolicyError,
)
from saas_os.control_plane.inference.config.models import (
    CLASSIFICATION_ORDER,
    AIAlias,
    AIDestinationPolicy,
    AIModel,
    AIProvider,
    AITenantDestinationGrant,
    AITenantPolicy,
    AITenantPreferences,
    AITenantUseCaseGrant,
)
from saas_os.control_plane.inference.permissions import AI_POLICY
from saas_os.core.audit_log import ActorType, AuditOutcome, record, record_in_transaction
from saas_os.core.authority import (
    ServiceAccountCaller,
    UserCaller,
    require_caller,
)
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import authorize_caller
from saas_os.core.tenancy import lock_open_tenant, require_open_tenant
from saas_os.infra.db import IntegrityError, Session, select, tenant_session_scope

USE_CASE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")
_RESOURCE_TYPE = "ai_tenant_policy"


@dataclass(frozen=True)
class UseCaseGrantView:
    use_case: str
    classifications: tuple[str, ...]
    enabled: bool


@dataclass(frozen=True)
class DestinationGrantView:
    use_case: str
    provider_key: str
    model_id: str
    model_ref: uuid.UUID
    classifications: tuple[str, ...]
    enabled: bool
    preference_rank: int | None = None


@dataclass(frozen=True)
class TenantAIPreferencesView:
    """The tenant's data-handling requirements (AI-E). Each one only narrows
    which destinations are eligible; the defaults require nothing."""

    allowed_residency: tuple[str, ...] = ()
    max_retention_days: int | None = None
    exclude_training_use: bool = False
    version: int = 0


@dataclass(frozen=True)
class TenantAIPolicyView:
    tenant_id: uuid.UUID
    exists: bool
    enabled: bool
    version: int
    use_cases: tuple[UseCaseGrantView, ...]
    destinations: tuple[DestinationGrantView, ...]
    preferences: TenantAIPreferencesView = TenantAIPreferencesView()


def preference_violations(handling: dict, preferences: TenantAIPreferencesView) -> tuple[str, ...]:
    """Which of the tenant's data-handling requirements a provider's declared
    handling fails, as closed reason codes (`residency`, `retention`,
    `training_use`). Nothing declared fails every requirement that is set.
    The one definition: `resolution.meets_preferences` is `not` this."""
    failed: list[str] = []
    if preferences.allowed_residency:
        declared = handling.get("residency")
        if (
            not isinstance(declared, list)
            or not declared
            or not set(declared) <= set(preferences.allowed_residency)
        ):
            failed.append("residency")
    if preferences.max_retention_days is not None:
        retention = handling.get("retention_days")
        if (
            not isinstance(retention, int)
            or isinstance(retention, bool)
            or retention > preferences.max_retention_days
        ):
            failed.append("retention")
    if preferences.exclude_training_use and handling.get("training_use") is not False:
        failed.append("training_use")
    return tuple(failed)


def _classifications(values: Sequence[str]) -> list[str]:
    chosen = sorted(set(values), key=lambda v: CLASSIFICATION_ORDER.get(v, 99))
    if not chosen or any(value not in CLASSIFICATION_ORDER for value in chosen):
        raise AITenantPolicyError("invalid_classifications")
    return chosen


def _use_case(name: str) -> str:
    if not isinstance(name, str) or not USE_CASE_NAME.fullmatch(name):
        raise AITenantPolicyError("invalid_use_case")
    return name


def _record_denied(
    tenant_id: uuid.UUID, caller: UserCaller | ServiceAccountCaller, action: str
) -> None:
    """The refusal row, written after the refused transaction rolled back."""
    is_user = isinstance(caller, UserCaller)
    record(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if is_user else ActorType.SERVICE_ACCOUNT,
        actor_user_id=caller.user_id if isinstance(caller, UserCaller) else None,
        actor_service_account_id=(
            caller.service_account_id if isinstance(caller, ServiceAccountCaller) else None
        ),
        action=action,
        resource_type=_RESOURCE_TYPE,
        outcome=AuditOutcome.DENIED,
        metadata={"reason": "not_authorized"},
    )


def _authorized_change[T](
    tenant_id: uuid.UUID,
    caller: object,
    *,
    operation: str,
    action: str,
    permission_action: str,
    change: Callable[[Session], tuple[T, dict[str, object]]],
) -> T:
    require_caller(operation, caller)
    # Users and service accounts only: no system purpose writes tenant AI policy.
    if not isinstance(caller, (UserCaller, ServiceAccountCaller)):
        raise AuthorityNotAuthorizedError(operation, tenant_id)
    require_open_tenant(tenant_id)
    try:
        with tenant_session_scope(tenant_id) as session:
            lock_open_tenant(session, tenant_id)
            authorize_caller(
                caller,
                session=session,
                operation=operation,
                tenant_id=tenant_id,
                resource=AI_POLICY,
                action=permission_action,
            )
            value, metadata = change(session)
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action=action,
                resource_type=_RESOURCE_TYPE,
                resource_id=str(tenant_id),
                metadata=metadata,
            )
            return value
    except AuthorityNotAuthorizedError:
        _record_denied(tenant_id, caller, action)
        raise


def _policy_row(session: Session, tenant_id: uuid.UUID) -> AITenantPolicy | None:
    return session.execute(
        select(AITenantPolicy).where(AITenantPolicy.tenant_id == tenant_id).with_for_update()
    ).scalar_one_or_none()


def set_tenant_ai_policy(tenant_id: uuid.UUID, *, enabled: bool, caller: object) -> bool:
    """Enable or disable the tenant's AI policy as a whole."""

    def change(session: Session) -> tuple[bool, dict[str, object]]:
        row = _policy_row(session, tenant_id)
        if row is None:
            session.add(AITenantPolicy(tenant_id=tenant_id, enabled=bool(enabled), version=1))
        else:
            row.enabled = bool(enabled)
            row.version += 1
        session.flush()
        return bool(enabled), {"change": "set_policy", "enabled": bool(enabled)}

    return _authorized_change(
        tenant_id,
        caller,
        operation="ai_policy.set",
        action="ai.policy.set",
        permission_action="manage",
        change=change,
    )


def grant_use_case(
    tenant_id: uuid.UUID,
    *,
    use_case: str,
    classifications: Sequence[str],
    enabled: bool = True,
    caller: object,
) -> UseCaseGrantView:
    """Grant (or update) a use case and the classifications it may carry."""
    name = _use_case(use_case)
    values = _classifications(classifications)

    def change(session: Session) -> tuple[UseCaseGrantView, dict[str, object]]:
        row = session.execute(
            select(AITenantUseCaseGrant)
            .where(
                AITenantUseCaseGrant.tenant_id == tenant_id,
                AITenantUseCaseGrant.use_case == name,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            session.add(
                AITenantUseCaseGrant(
                    tenant_id=tenant_id, use_case=name, classifications=values, enabled=enabled
                )
            )
        else:
            row.classifications = values
            row.enabled = bool(enabled)
        session.flush()
        view = UseCaseGrantView(name, tuple(values), bool(enabled))
        return view, {
            "change": "grant_use_case",
            "use_case": name,
            "classifications": values,
            "enabled": bool(enabled),
        }

    return _authorized_change(
        tenant_id,
        caller,
        operation="ai_policy.grant_use_case",
        action="ai.policy.grant_use_case",
        permission_action="manage",
        change=change,
    )


def _model_ref(session: Session, provider_key: str, model_id: str) -> tuple[AIProvider, AIModel]:
    row = session.execute(
        select(AIProvider, AIModel)
        .join(AIModel, AIModel.provider_id == AIProvider.id)
        .where(AIProvider.key == provider_key, AIModel.model_id == model_id)
    ).first()
    if row is None:
        raise AIConfigurationNotFoundError("model")
    return row[0], row[1]


def _grant_blockers(
    session: Session,
    tenant_id: uuid.UUID,
    provider: AIProvider,
    model: AIModel,
    classifications: Sequence[str],
) -> tuple[str, ...]:
    """Why the evaluator would never allow this destination for these
    classifications, whatever else the tenant does: the model is disabled or
    retired, installation policy does not allow the provider for a
    classification, or the tenant's own data-handling requirements fail the
    provider's declared handling. Platform operating states that change
    without a tenant action (provider paused, credential not yet bound) are
    not grounds to refuse a grant. Call time stays the authority."""
    blocked: list[str] = []
    if model.lifecycle == "disabled":
        blocked.append("model_disabled")
    elif model.retire_after is not None and model.retire_after <= datetime.now(UTC):
        blocked.append("model_retired")
    allowed = {
        row.classification: row.allowed
        for row in session.execute(
            select(AIDestinationPolicy).where(AIDestinationPolicy.provider_id == provider.id)
        )
        .scalars()
        .all()
    }
    if any(allowed.get(c) is not True for c in classifications):
        blocked.append("destination_policy_denied")
    prefs = session.execute(
        select(AITenantPreferences).where(AITenantPreferences.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if prefs is not None:
        view = TenantAIPreferencesView(
            tuple(prefs.allowed_residency),
            prefs.max_retention_days,
            prefs.exclude_training_use,
            prefs.version,
        )
        blocked.extend(preference_violations(dict(provider.data_handling or {}), view))
    return tuple(blocked)


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
    """Allow one configured model as a destination for a use case, with the
    classifications that may be sent to it."""
    name = _use_case(use_case)
    values = _classifications(classifications)

    def change(session: Session) -> tuple[DestinationGrantView, dict[str, object]]:
        provider, model = _model_ref(session, provider_key, model_id)
        if enabled:
            blocked = _grant_blockers(session, tenant_id, provider, model, values)
            if blocked:
                raise AITenantPolicyError("destination_not_eligible", blocked_by=blocked)
        row = session.execute(
            select(AITenantDestinationGrant)
            .where(
                AITenantDestinationGrant.tenant_id == tenant_id,
                AITenantDestinationGrant.use_case == name,
                AITenantDestinationGrant.model_ref == model.id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            session.add(
                AITenantDestinationGrant(
                    tenant_id=tenant_id,
                    use_case=name,
                    model_ref=model.id,
                    classifications=values,
                    enabled=enabled,
                )
            )
        else:
            row.classifications = values
            row.enabled = bool(enabled)
        session.flush()
        view = DestinationGrantView(
            name,
            provider.key,
            model.model_id,
            model.id,
            tuple(values),
            bool(enabled),
            row.preference_rank if row is not None else None,
        )
        return view, {
            "change": "grant_destination",
            "use_case": name,
            "provider": provider.key,
            "model": model.model_id,
            "classifications": values,
            "enabled": bool(enabled),
        }

    return _authorized_change(
        tenant_id,
        caller,
        operation="ai_policy.grant_destination",
        action="ai.policy.grant_destination",
        permission_action="manage",
        change=change,
    )


MAX_PREFERENCE_RANK = 32767


def set_destination_rank(
    tenant_id: uuid.UUID,
    *,
    use_case: str,
    provider_key: str,
    model_id: str,
    rank: int | None,
    caller: object,
) -> DestinationGrantView:
    """Order a model the tenant already granted for a use case: the lower
    rank is tried first, `None` clears the rank (the grant then comes after
    every ranked one, in alias order). The rank only chooses among models an
    alias already lists and the tenant already granted; it never adds a
    model to an alias and never makes an ineligible model eligible. Ranks are
    unique per use case (`duplicate_rank`)."""
    name = _use_case(use_case)
    if rank is not None and (
        isinstance(rank, bool) or not isinstance(rank, int) or not 0 <= rank <= MAX_PREFERENCE_RANK
    ):
        raise AITenantPolicyError("invalid_rank")

    def change(session: Session) -> tuple[DestinationGrantView, dict[str, object]]:
        provider, model = _model_ref(session, provider_key, model_id)
        in_alias = any(
            str(model.id) in (alias.candidates or [])
            for alias in session.execute(select(AIAlias)).scalars().all()
        )
        if not in_alias:
            raise AITenantPolicyError("model_not_in_alias")
        row = session.execute(
            select(AITenantDestinationGrant)
            .where(
                AITenantDestinationGrant.tenant_id == tenant_id,
                AITenantDestinationGrant.use_case == name,
                AITenantDestinationGrant.model_ref == model.id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            raise AITenantPolicyError("destination_not_granted")
        if rank is not None:
            taken = session.execute(
                select(AITenantDestinationGrant.id).where(
                    AITenantDestinationGrant.tenant_id == tenant_id,
                    AITenantDestinationGrant.use_case == name,
                    AITenantDestinationGrant.preference_rank == rank,
                    AITenantDestinationGrant.id != row.id,
                )
            ).first()
            if taken is not None:
                raise AITenantPolicyError("duplicate_rank")
        row.preference_rank = rank
        session.flush()
        view = DestinationGrantView(
            name,
            provider.key,
            model.model_id,
            model.id,
            tuple(row.classifications),
            bool(row.enabled),
            rank,
        )
        return view, {
            "change": "set_rank",
            "use_case": name,
            "provider": provider.key,
            "model": model.model_id,
            "rank": rank,
        }

    try:
        return _authorized_change(
            tenant_id,
            caller,
            operation="ai_policy.set_rank",
            action="ai.policy.set_rank",
            permission_action="manage",
            change=change,
        )
    except IntegrityError:
        # A concurrent change took the rank between the check and the write;
        # the partial unique index is the backstop.
        raise AITenantPolicyError("duplicate_rank") from None


_RESIDENCY_TAG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def set_tenant_ai_preferences(
    tenant_id: uuid.UUID,
    *,
    allowed_residency: Sequence[str] = (),
    max_retention_days: int | None = None,
    exclude_training_use: bool = False,
    caller: object,
) -> TenantAIPreferencesView:
    """Set the tenant's data-handling requirements (ADR-0055 section 7,
    AI-E). They are matched against what the platform operator *declared*
    about each provider (`set_provider_data_handling`); a provider that
    declared nothing fails every requirement. They can never make a
    destination eligible that policy did not already allow."""
    tags = sorted(set(allowed_residency))
    if any(not isinstance(tag, str) or not _RESIDENCY_TAG.fullmatch(tag) for tag in tags):
        raise AITenantPolicyError("invalid_residency")
    if max_retention_days is not None and (
        isinstance(max_retention_days, bool) or not 0 <= max_retention_days <= 3650
    ):
        raise AITenantPolicyError("invalid_max_retention_days")
    exclude = bool(exclude_training_use)

    def change(session: Session) -> tuple[TenantAIPreferencesView, dict[str, object]]:
        row = session.execute(
            select(AITenantPreferences)
            .where(AITenantPreferences.tenant_id == tenant_id)
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            row = AITenantPreferences(
                tenant_id=tenant_id,
                allowed_residency=tags,
                max_retention_days=max_retention_days,
                exclude_training_use=exclude,
                version=1,
            )
            session.add(row)
        else:
            row.allowed_residency = tags
            row.max_retention_days = max_retention_days
            row.exclude_training_use = exclude
            row.version += 1
        session.flush()
        view = TenantAIPreferencesView(tuple(tags), max_retention_days, exclude, row.version)
        return view, {
            "change": "set_preferences",
            "allowed_residency": tags,
            "max_retention_days": max_retention_days,
            "exclude_training_use": exclude,
        }

    return _authorized_change(
        tenant_id,
        caller,
        operation="ai_policy.set_preferences",
        action="ai.policy.set_preferences",
        permission_action="manage",
        change=change,
    )


def load_tenant_ai_policy(session: Session, tenant_id: uuid.UUID) -> TenantAIPolicyView:
    """The tenant's policy as read in an existing tenant transaction. Used by
    governed inference; performs no authorization of its own."""
    policy = session.execute(
        select(AITenantPolicy).where(AITenantPolicy.tenant_id == tenant_id)
    ).scalar_one_or_none()
    use_cases = (
        session.execute(
            select(AITenantUseCaseGrant).where(AITenantUseCaseGrant.tenant_id == tenant_id)
        )
        .scalars()
        .all()
    )
    destinations = session.execute(
        select(AITenantDestinationGrant, AIModel, AIProvider)
        .join(AIModel, AIModel.id == AITenantDestinationGrant.model_ref)
        .join(AIProvider, AIProvider.id == AIModel.provider_id)
        .where(AITenantDestinationGrant.tenant_id == tenant_id)
    ).all()
    prefs = session.execute(
        select(AITenantPreferences).where(AITenantPreferences.tenant_id == tenant_id)
    ).scalar_one_or_none()
    return TenantAIPolicyView(
        tenant_id=tenant_id,
        exists=policy is not None,
        enabled=bool(policy.enabled) if policy is not None else False,
        version=policy.version if policy is not None else 0,
        use_cases=tuple(
            UseCaseGrantView(row.use_case, tuple(row.classifications), row.enabled)
            for row in use_cases
        ),
        destinations=tuple(
            DestinationGrantView(
                grant.use_case,
                provider.key,
                model.model_id,
                model.id,
                tuple(grant.classifications),
                grant.enabled,
                grant.preference_rank,
            )
            for grant, model, provider in destinations
        ),
        preferences=(
            TenantAIPreferencesView(
                tuple(prefs.allowed_residency),
                prefs.max_retention_days,
                prefs.exclude_training_use,
                prefs.version,
            )
            if prefs is not None
            else TenantAIPreferencesView()
        ),
    )


def read_tenant_ai_policy(tenant_id: uuid.UUID, *, caller: object) -> TenantAIPolicyView:
    """The tenant's AI policy. Authority: `ai.policy:read` at the tenant."""
    require_caller("ai_policy.read", caller)
    # Users and service accounts only: no system purpose writes tenant AI policy.
    if not isinstance(caller, (UserCaller, ServiceAccountCaller)):
        raise AuthorityNotAuthorizedError("ai_policy.read", tenant_id)
    require_open_tenant(tenant_id)
    with tenant_session_scope(tenant_id) as session:
        authorize_caller(
            caller,
            session=session,
            operation="ai_policy.read",
            tenant_id=tenant_id,
            resource=AI_POLICY,
            action="read",
        )
        return load_tenant_ai_policy(session, tenant_id)
