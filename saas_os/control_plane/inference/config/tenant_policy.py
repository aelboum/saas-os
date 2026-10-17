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

from saas_os.control_plane.inference.config.errors import (
    AIConfigurationNotFoundError,
    AITenantPolicyError,
)
from saas_os.control_plane.inference.config.models import (
    CLASSIFICATION_ORDER,
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
from saas_os.infra.db import Session, select, tenant_session_scope

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
            name, provider.key, model.model_id, model.id, tuple(values), bool(enabled)
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
