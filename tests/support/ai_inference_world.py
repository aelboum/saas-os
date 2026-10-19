"""Shared setup for the governed AI inference integration tests (ADR-0054
Phases AI-D to AI-H). On `sys.path` through `pythonpath` in `pyproject.toml`.

`AIWorld` builds, through the real operations, a configured destination: a
platform operator configures a provider, a model, an alias and installation
policy; a tenant manager sets the tenant's AI policy; a tenant member holds
`ai.inference:run`. `runtime()` returns an `InferenceRuntime` with a scripted
provider adapter, no network, an in-memory concurrency gate and a constant
entitlement, so a test controls each external outcome. `cleanup()` removes
every row it created through the migrations role.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text

from lifecycle_callers import PROVISIONING, enroll_test_operator, platform_operator
from saas_os.control_plane.inference.adapters import (
    AdapterError,
    AdapterResult,
    FakeAdapter,
    OpaqueCredential,
)
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.config import tenant_policy
from saas_os.control_plane.inference.errors import InferenceCapacityExhaustedError
from saas_os.control_plane.inference.service import CircuitBreaker, InferenceRuntime
from saas_os.control_plane.inference.use_cases import UseCase, register_use_case
from saas_os.core.authority import UserCaller
from saas_os.core.identity import get_membership
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.platform_authority import PlatformPermission
from saas_os.core.rbac import RoleScope
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import TenantStatus, create_tenant, transition_tenant_status
from saas_os.infra.db.config import get_migrations_database_config
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.session import build_session_factory, session_scope

P = PlatformPermission
REASON = "TICKET-AI: integration test"
SECRET_NAME = "AI_TEST_PROVIDER_KEY"  # pragma: allowlist secret -- a secret name


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class MemoryAdmission:
    """An in-process stand-in for the Redis lease: counts live slots per
    tenant, refuses above `limit`, records releases."""

    def __init__(self, limit: int = 100) -> None:
        self.limit = limit
        self.live: dict[uuid.UUID, int] = {}
        self.admitted = 0
        self.released = 0

    async def admit(self, tenant_id: uuid.UUID, *, ttl_seconds: float) -> object:
        del ttl_seconds
        if self.live.get(tenant_id, 0) >= self.limit:
            raise InferenceCapacityExhaustedError("tenant_concurrency")
        self.live[tenant_id] = self.live.get(tenant_id, 0) + 1
        self.admitted += 1
        return tenant_id

    async def release(self, slot: object) -> None:
        assert isinstance(slot, uuid.UUID)
        self.live[slot] -= 1
        self.released += 1


@dataclass
class Destination:
    provider_key: str
    model_id: str
    model_ref: uuid.UUID


@dataclass
class Scene:
    tenant_id: uuid.UUID
    alias: str
    use_case: UseCase
    destinations: list[Destination]
    member: UserCaller
    manager: UserCaller
    operator: UserCaller


@dataclass
class AIWorld:
    tenant_ids: list[uuid.UUID] = field(default_factory=list)
    user_ids: list[uuid.UUID] = field(default_factory=list)
    operator_ids: list[uuid.UUID] = field(default_factory=list)
    provider_keys: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)

    # --- people -------------------------------------------------------------------
    def operator(self, *permissions: PlatformPermission) -> UserCaller:
        caller = enroll_test_operator(list(permissions))
        self.operator_ids.append(caller.user_id)
        return caller

    def tenant(self) -> uuid.UUID:
        tenant = create_tenant(unique("ai"), caller=PROVISIONING)
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE, caller=platform_operator())
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(self) -> uuid.UUID:
        user = create_user()
        self.user_ids.append(user.id)
        return user.id

    def member(self, tenant_id: uuid.UUID, *permissions: tuple[str, str]) -> UserCaller:
        user_id = self.user()
        membership = get_membership(tenant_id, user_id) or add_tenant_membership(
            tenant_id, user_id, caller=PROVISIONING
        )
        role = create_role(tenant_id, unique("role"), caller=PROVISIONING)
        for resource, action in permissions:
            grant_permission(
                tenant_id, role.id, register_permission(resource, action).id, caller=PROVISIONING
            )
        assign_first_role_for_new_tenant(
            tenant_id, membership.id, role.id, scope=RoleScope.SELF, caller=PROVISIONING
        )
        return UserCaller(user_id)

    # --- configuration ---------------------------------------------------------------
    def destination(
        self,
        operator: UserCaller,
        *,
        protocol: str = "openai_chat_completions",
        capabilities: Sequence[str] = (
            "text_input",
            "text_output",
            "system_instructions",
            "temperature",
            "stop_sequences",
        ),
        max_output_tokens: int = 4096,
        allow: Sequence[str] = ("none", "tenant_data"),
        base_url: str = "https://api.example.com/v1",
    ) -> Destination:
        key = unique("p")
        self.provider_keys.append(key)
        ai_config.create_provider(
            key=key,
            protocol=protocol,
            base_url=base_url,
            credential_ref=SECRET_NAME,
            caller=operator,
            reason=REASON,
        )
        model = ai_config.create_model(
            provider_key=key,
            model_id="model-1",
            capabilities=list(capabilities),
            max_output_tokens=max_output_tokens,
            caller=operator,
            reason=REASON,
        )
        for classification in allow:
            ai_config.set_destination_policy(
                provider_key=key,
                classification=classification,
                allowed=True,
                caller=operator,
                reason=REASON,
            )
        return Destination(key, "model-1", model.id)

    def scene(
        self,
        *,
        destinations: int = 1,
        max_classification: str = "tenant_data",
        grant: Sequence[str] = ("none", "tenant_data"),
        **destination_options: Any,
    ) -> Scene:
        operator = self.operator(P.AI_PROVIDER_MANAGE, P.AI_POLICY_MANAGE)
        targets = [self.destination(operator, **destination_options) for _ in range(destinations)]
        alias = unique("alias")
        self.aliases.append(alias)
        ai_config.set_alias(
            alias=alias,
            candidates=[(d.provider_key, d.model_id) for d in targets],
            caller=operator,
            reason=REASON,
        )
        use_case = register_use_case(
            UseCase(name=unique("uc").lower(), max_classification=max_classification)
        )
        tenant_id = self.tenant()
        manager = self.member(tenant_id, ("ai.policy", "manage"), ("ai.policy", "read"))
        tenant_policy.set_tenant_ai_policy(tenant_id, enabled=True, caller=manager)
        tenant_policy.grant_use_case(
            tenant_id, use_case=use_case.name, classifications=list(grant), caller=manager
        )
        for target in targets:
            tenant_policy.grant_destination(
                tenant_id,
                use_case=use_case.name,
                provider_key=target.provider_key,
                model_id=target.model_id,
                classifications=list(grant),
                caller=manager,
            )
        member = self.member(tenant_id, ("ai.inference", "run"))
        return Scene(tenant_id, alias, use_case, targets, member, manager, operator)

    # --- teardown ------------------------------------------------------------------------
    def cleanup(self) -> None:
        params = {
            "t": [str(t) for t in self.tenant_ids],
            "u": [str(u) for u in [*self.user_ids, *self.operator_ids]],
            "k": self.provider_keys,
            "a": self.aliases,
            "h": self.hosts,
        }
        engine = build_engine(get_migrations_database_config())
        try:
            factory = build_session_factory(engine)
            with session_scope(session_factory=factory) as session:
                for statement in (
                    "DELETE FROM control_plane.ai_inference_attempts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM control_plane.ai_tenant_destination_grants "
                    "WHERE tenant_id = ANY(:t)",
                    "DELETE FROM control_plane.ai_tenant_use_case_grants WHERE tenant_id = ANY(:t)",
                    "DELETE FROM control_plane.ai_tenant_policies WHERE tenant_id = ANY(:t)",
                    "DELETE FROM control_plane.ai_tenant_preferences WHERE tenant_id = ANY(:t)",
                    "DELETE FROM control_plane.ai_destination_policy WHERE provider_id IN "
                    "(SELECT id FROM control_plane.ai_providers WHERE key = ANY(:k))",
                    "DELETE FROM control_plane.ai_aliases WHERE alias = ANY(:a)",
                    "DELETE FROM control_plane.ai_endpoint_trust WHERE host = ANY(:h)",
                    "DELETE FROM control_plane.ai_model_prices WHERE model_ref IN "
                    "(SELECT m.id FROM control_plane.ai_models m JOIN control_plane.ai_providers p "
                    "ON p.id = m.provider_id WHERE p.key = ANY(:k))",
                    "DELETE FROM control_plane.ai_models WHERE provider_id IN "
                    "(SELECT id FROM control_plane.ai_providers WHERE key = ANY(:k))",
                    "DELETE FROM control_plane.ai_providers WHERE key = ANY(:k)",
                    "DELETE FROM core.outbox_consumptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.outbox_events WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.usage_events WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.audit_log "
                    "WHERE tenant_id = ANY(:t) OR actor_user_id = ANY(:u)",
                    "DELETE FROM core.support_access_requests WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
                    "DELETE FROM core.platform_audit_log "
                    "WHERE target_tenant_id = ANY(:t) OR actor_user_id = ANY(:u)",
                    "DELETE FROM core.platform_grants WHERE operator_id IN "
                    "(SELECT id FROM core.platform_operators WHERE user_id = ANY(:u))",
                    "DELETE FROM core.platform_operators WHERE user_id = ANY(:u)",
                    "DELETE FROM core.tenants WHERE id = ANY(:t)",
                    "DELETE FROM core.external_identities WHERE user_id = ANY(:u)",
                    "DELETE FROM core.users WHERE id = ANY(:u)",
                ):
                    session.execute(text(statement), params)
        finally:
            engine.dispose()


def runtime(
    script: Sequence[AdapterResult | AdapterError] | None = None,
    *,
    admission: MemoryAdmission | None = None,
    entitled: bool = True,
    adapter: object | None = None,
    protocol: str = "openai_chat_completions",
    total_deadline_seconds: float = 30.0,
) -> tuple[InferenceRuntime, Any, MemoryAdmission]:
    gate = admission or MemoryAdmission()
    fake = adapter or FakeAdapter(script)

    async def no_sleep(seconds: float) -> None:
        del seconds

    rt = InferenceRuntime(
        adapters={protocol: fake},  # type: ignore[dict-item]
        egress=lambda eligible: None,  # type: ignore[arg-type,return-value]
        admission=gate,
        entitlement=lambda tenant_id, key: entitled,
        credential=lambda name: (
            OpaqueCredential("test-credential") if name == SECRET_NAME else None
        ),
        circuit=CircuitBreaker(),
        total_deadline_seconds=total_deadline_seconds,
        sleep=no_sleep,
    )
    return rt, fake, gate


def attempts(tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM control_plane.ai_inference_attempts "
                    "WHERE tenant_id = :t ORDER BY attempt_number"
                ),
                {"t": str(tenant_id)},
            ).mappings()
            return [dict(row) for row in rows]
    finally:
        engine.dispose()


def admin_scalar(sql: str, **params: object) -> Any:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return conn.execute(text(sql), params).scalar()
    finally:
        engine.dispose()
