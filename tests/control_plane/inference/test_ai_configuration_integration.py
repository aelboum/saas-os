"""AI-C configuration against a real PostgreSQL (ADR-0054 Phase AI-C;
ADR-0055 section 7).

Platform configuration (global `control_plane.ai_*` catalog):
- each change requires its own platform permission, commits with its
  platform audit row, and a refusal writes a `denied` row and changes
  nothing;
- a credential is a secret *name*; its value is never stored, returned or
  audited; changing the endpoint's origin clears the credential binding
  until a second operation confirms it;
- the read is an audited oversight read;
- the runtime role cannot delete configuration rows.

Tenant AI policy (tenant RLS):
- written only with `ai.policy:manage` at the tenant, with its tenant audit
  row; a refusal writes a `denied` row;
- support access can read the policy and can never change it;
- another tenant cannot see the rows; no system purpose may write them.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import PROVISIONING, enroll_test_operator, platform_operator
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.config import tenant_policy
from saas_os.control_plane.inference.config.errors import AIConfigurationError
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import get_membership
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.platform_authority import PlatformNotAuthorizedError, PlatformPermission
from saas_os.core.rbac import RoleScope
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
    create_role,
    create_support_access_request,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import TenantStatus, create_tenant, transition_tenant_status
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
_SECRET_NAME = "AI_TEST_PROVIDER_KEY"  # pragma: allowlist secret -- a secret name
_SECRET_VALUE = "placeholder-credential-value-for-tests"  # pragma: allowlist secret
_REASON = "TICKET-AI-C: test"


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.ai_providers LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"AI tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Secrets:
        def get(self, name: str) -> str | None:
            return _SECRET_VALUE if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())
    # Only these names are provisioned for AI provider use (credentials.py).
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,AI_TEST_ROTATED")


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.operator_ids: list[uuid.UUID] = []
        self.provider_keys: list[str] = []
        self.aliases: list[str] = []
        self.hosts: list[str] = []

    def operator(self, *permissions: PlatformPermission) -> UserCaller:
        caller = enroll_test_operator(list(permissions))
        self.operator_ids.append(caller.user_id)
        return caller

    def provider(self, operator: UserCaller, *, base_url: str = "https://api.example.com/v1"):
        key = _unique("p")
        self.provider_keys.append(key)
        return ai_config.create_provider(
            key=key,
            protocol="openai_chat_completions",
            base_url=base_url,
            credential_ref=_SECRET_NAME,
            caller=operator,
            reason=_REASON,
        )

    def tenant(self) -> uuid.UUID:
        tenant = create_tenant(_unique("ai-c"), caller=PROVISIONING)
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
        role = create_role(tenant_id, _unique("role"), caller=PROVISIONING)
        for resource, action in permissions:
            grant_permission(
                tenant_id, role.id, register_permission(resource, action).id, caller=PROVISIONING
            )
        assign_first_role_for_new_tenant(
            tenant_id, membership.id, role.id, scope=RoleScope.SELF, caller=PROVISIONING
        )
        return UserCaller(user_id)

    def support_engineer(self, tenant_id: uuid.UUID) -> UserCaller:
        approver = self.member(tenant_id, ("support_access_request", "approve"))
        engineer = self.user()
        request = create_support_access_request(
            caller=UserCaller(engineer),
            tenant_id=tenant_id,
            reason="AI-C support boundary",
            requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        approve_support_access(caller=approver, tenant_id=tenant_id, request_id=request.id)
        return UserCaller(engineer)

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
                    "DELETE FROM control_plane.ai_tenant_destination_grants "
                    "WHERE tenant_id = ANY(:t)",
                    "DELETE FROM control_plane.ai_tenant_use_case_grants WHERE tenant_id = ANY(:t)",
                    "DELETE FROM control_plane.ai_tenant_policies WHERE tenant_id = ANY(:t)",
                    "DELETE FROM control_plane.ai_destination_policy WHERE provider_id IN "
                    "(SELECT id FROM control_plane.ai_providers WHERE key = ANY(:k))",
                    "DELETE FROM control_plane.ai_aliases WHERE alias = ANY(:a)",
                    "DELETE FROM control_plane.ai_models WHERE provider_id IN "
                    "(SELECT id FROM control_plane.ai_providers WHERE key = ANY(:k))",
                    "DELETE FROM control_plane.ai_providers WHERE key = ANY(:k)",
                    "DELETE FROM control_plane.ai_endpoint_trust WHERE host = ANY(:h)",
                    "DELETE FROM core.audit_log "
                    "WHERE tenant_id = ANY(:t) OR actor_user_id = ANY(:u)",
                    "DELETE FROM core.support_access_requests WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
                    "DELETE FROM core.platform_audit_log WHERE target_tenant_id = ANY(:t) "
                    "OR actor_user_id = ANY(:u)",
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


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


def _platform_rows(user_id: uuid.UUID) -> list[tuple[str, str, dict | None, str | None]]:
    with session_scope() as session:
        return [
            (row[0], row[1], row[2], row[3])
            for row in session.execute(
                text(
                    "SELECT action, outcome, metadata, target_type FROM core.platform_audit_log "
                    "WHERE actor_user_id = :u ORDER BY created_at, id"
                ),
                {"u": str(user_id)},
            )
        ]


def _admin_scalar(sql: str, **params: object) -> object:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return conn.execute(text(sql), params).scalar()
    finally:
        engine.dispose()


# --- platform configuration ------------------------------------------------------------


def test_a_provider_change_commits_with_its_platform_audit_row(world: _World) -> None:
    operator = world.operator(P.AI_PROVIDER_MANAGE)
    view = world.provider(operator)
    assert view.credential_bound and view.status == "active" and view.credential_ref == _SECRET_NAME
    rows = _platform_rows(operator.user_id)
    assert [(a, o, t) for a, o, _, t in rows] == [
        ("platform.ai_provider.configure", "success", "ai_provider")
    ]
    assert rows[0][2] is not None and rows[0][2]["change"] == "create_provider"
    # The secret's value is nowhere: not in the row, not in the evidence.
    assert (
        _admin_scalar(
            "SELECT count(*) FROM control_plane.ai_providers "
            "WHERE CAST(ai_providers AS text) LIKE :v",
            v=f"%{_SECRET_VALUE}%",
        )
        == 0
    )
    assert _SECRET_VALUE not in repr(rows) and _SECRET_VALUE not in repr(view)


def test_a_refusal_is_recorded_and_changes_nothing(world: _World) -> None:
    operator = world.operator(P.AI_CONFIG_READ, P.AI_POLICY_MANAGE)  # not provider manage
    key = _unique("p")
    world.provider_keys.append(key)
    with pytest.raises(PlatformNotAuthorizedError):
        ai_config.create_provider(
            key=key,
            protocol="anthropic_messages",
            base_url="https://api.example.com",
            credential_ref=_SECRET_NAME,
            caller=operator,
            reason=_REASON,
        )
    assert (
        _admin_scalar("SELECT count(*) FROM control_plane.ai_providers WHERE key = :k", k=key) == 0
    )
    assert [(a, o) for a, o, _, _ in _platform_rows(operator.user_id)] == [
        ("platform.ai_provider.configure", "denied")
    ]


def test_each_area_needs_its_own_permission(world: _World) -> None:
    provider_admin = world.operator(P.AI_PROVIDER_MANAGE)
    provider = world.provider(provider_admin)
    host = f"{_unique('llm')}.internal.example"
    world.hosts.append(host)
    with pytest.raises(PlatformNotAuthorizedError):
        ai_config.create_trust_entry(
            host=host,
            port=443,
            networks=["10.20.0.0/16"],
            expires_at=datetime.now(UTC) + timedelta(days=30),
            caller=provider_admin,
            reason=_REASON,
        )
    with pytest.raises(PlatformNotAuthorizedError):
        ai_config.set_destination_policy(
            provider_key=provider.key,
            classification="tenant_data",
            allowed=True,
            caller=provider_admin,
            reason=_REASON,
        )
    with pytest.raises(PlatformNotAuthorizedError):
        ai_config.read_ai_configuration(caller=provider_admin)


def test_an_origin_change_clears_the_binding_until_confirmed(world: _World) -> None:
    operator = world.operator(P.AI_PROVIDER_MANAGE)
    provider = world.provider(operator)
    same_origin = ai_config.update_provider_endpoint(
        key=provider.key, base_url="https://api.example.com/v2", caller=operator, reason=_REASON
    )
    assert same_origin.credential_bound
    moved = ai_config.update_provider_endpoint(
        key=provider.key, base_url="https://other.example.net/v1", caller=operator, reason=_REASON
    )
    assert not moved.credential_bound
    # The stored binding itself is cleared, not merely outdated.
    assert (
        _admin_scalar(
            "SELECT credential_origin FROM control_plane.ai_providers WHERE key = :k",
            k=provider.key,
        )
        is None
    )
    # A credential change by name clears the binding again; it never re-binds.
    rotated = ai_config.set_provider_credential_ref(
        key=provider.key, credential_ref="AI_TEST_ROTATED", caller=operator, reason=_REASON
    )
    assert not rotated.credential_bound
    confirmed = ai_config.confirm_provider_binding(
        key=provider.key, caller=operator, reason=_REASON
    )
    assert confirmed.credential_bound and confirmed.version == moved.version + 2
    metadata = [m for _, _, m, _ in _platform_rows(operator.user_id)]
    assert [m["change"] for m in metadata if m] == [
        "create_provider",
        "update_provider_endpoint",
        "update_provider_endpoint",
        "set_provider_credential_ref",
        "confirm_provider_binding",
    ]
    assert [m.get("binding_cleared") for m in metadata if m and "binding_cleared" in m] == [
        False,
        True,
        True,
    ]


def test_an_unresolvable_secret_name_is_refused_before_any_transaction(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Provisioned for AI use, but it does not resolve.
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,NOT_A_TEST_SECRET")
    operator = world.operator(P.AI_PROVIDER_MANAGE)
    with pytest.raises(AIConfigurationError) as caught:
        ai_config.create_provider(
            key=_unique("p"),
            protocol="openai_chat_completions",
            base_url="https://api.example.com/v1",
            credential_ref="NOT_A_TEST_SECRET",
            caller=operator,
            reason=_REASON,
        )
    assert caught.value.reason == "credential_ref_unresolved"
    assert _platform_rows(operator.user_id) == []


def test_a_resolving_secret_not_provisioned_for_ai_is_refused(world: _World) -> None:
    # `AI_TEST_UNLISTED` resolves through the secrets provider, like any other
    # installation secret would, but the deployment did not provision it for
    # AI provider use: existence alone makes no secret eligible.
    operator = world.operator(P.AI_PROVIDER_MANAGE)
    with pytest.raises(AIConfigurationError) as caught:
        ai_config.create_provider(
            key=_unique("p"),
            protocol="openai_chat_completions",
            base_url="https://api.example.com/v1",
            credential_ref="AI_TEST_UNLISTED",
            caller=operator,
            reason=_REASON,
        )
    assert caught.value.reason == "credential_ref_not_provisioned"
    provider = world.provider(operator)
    with pytest.raises(AIConfigurationError) as caught:
        ai_config.set_provider_credential_ref(
            key=provider.key, credential_ref="AI_TEST_UNLISTED", caller=operator, reason=_REASON
        )
    assert caught.value.reason == "credential_ref_not_provisioned"
    assert (
        _admin_scalar(
            "SELECT credential_ref FROM control_plane.ai_providers WHERE key = :k", k=provider.key
        )
        == _SECRET_NAME
    )
    assert [m["change"] for _, _, m, _ in _platform_rows(operator.user_id) if m] == [
        "create_provider"
    ]


def test_a_credential_change_clears_the_binding_until_it_is_reconfirmed(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator = world.operator(P.AI_PROVIDER_MANAGE)
    provider = world.provider(operator)
    assert provider.credential_bound
    rotated = ai_config.set_provider_credential_ref(
        key=provider.key, credential_ref="AI_TEST_ROTATED", caller=operator, reason=_REASON
    )
    assert not rotated.credential_bound
    assert (
        _admin_scalar(
            "SELECT credential_origin FROM control_plane.ai_providers WHERE key = :k",
            k=provider.key,
        )
        is None
    )
    # A name withdrawn from provisioning cannot be bound: the confirmation
    # re-checks it, refuses, and leaves the provider unbound.
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY")
    with pytest.raises(AIConfigurationError) as caught:
        ai_config.confirm_provider_binding(key=provider.key, caller=operator, reason=_REASON)
    assert caught.value.reason == "credential_ref_not_provisioned"
    assert (
        _admin_scalar(
            "SELECT credential_origin FROM control_plane.ai_providers WHERE key = :k",
            k=provider.key,
        )
        is None
    )
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,AI_TEST_ROTATED")
    confirmed = ai_config.confirm_provider_binding(
        key=provider.key, caller=operator, reason=_REASON
    )
    assert confirmed.credential_bound and confirmed.credential_ref == "AI_TEST_ROTATED"
    # Re-setting the same name is not a change and keeps the binding.
    same = ai_config.set_provider_credential_ref(
        key=provider.key, credential_ref="AI_TEST_ROTATED", caller=operator, reason=_REASON
    )
    assert same.credential_bound
    rows = [
        m for _, outcome, m, _ in _platform_rows(operator.user_id) if outcome == "success" and m
    ]
    changes = [(m["change"], m.get("credential_ref"), m.get("binding_cleared")) for m in rows]
    assert changes == [
        ("create_provider", _SECRET_NAME, None),
        ("set_provider_credential_ref", "AI_TEST_ROTATED", True),
        ("confirm_provider_binding", "AI_TEST_ROTATED", None),
        ("set_provider_credential_ref", "AI_TEST_ROTATED", False),
    ]
    assert rows[1]["previous_credential_ref"] == _SECRET_NAME
    assert rows[2]["origin"] == "https://api.example.com:443"
    # Names only: no secret value reaches the platform audit log.
    assert _SECRET_VALUE not in repr(_platform_rows(operator.user_id))


def test_models_aliases_policy_and_the_oversight_read(world: _World) -> None:
    operator = world.operator(
        P.AI_PROVIDER_MANAGE, P.AI_POLICY_MANAGE, P.AI_CONFIG_READ, P.AI_ENDPOINT_TRUST_MANAGE
    )
    provider = world.provider(operator)
    model = ai_config.create_model(
        provider_key=provider.key,
        model_id="model-a",
        capabilities=["text_input", "text_output"],
        max_output_tokens=1024,
        caller=operator,
        reason=_REASON,
    )
    with pytest.raises(AIConfigurationError):
        ai_config.create_model(
            provider_key=provider.key,
            model_id="model-a",
            capabilities=["text_input"],
            max_output_tokens=1,
            caller=operator,
            reason=_REASON,
        )
    alias = _unique("alias")
    world.aliases.append(alias)
    set_alias = ai_config.set_alias(
        alias=alias, candidates=[(provider.key, "model-a")], caller=operator, reason=_REASON
    )
    assert set_alias.candidates == (model.id,)
    policy = ai_config.set_destination_policy(
        provider_key=provider.key,
        classification="tenant_data",
        allowed=True,
        caller=operator,
        reason=_REASON,
    )
    assert policy.allowed
    deprecated = ai_config.set_model_lifecycle(
        provider_key=provider.key,
        model_id="model-a",
        lifecycle="deprecated",
        retire_after=datetime.now(UTC) + timedelta(days=90),
        caller=operator,
        reason=_REASON,
    )
    assert deprecated.lifecycle == "deprecated"

    view = ai_config.read_ai_configuration(caller=operator)
    assert provider.key in {p.key for p in view.providers}
    assert alias in {a.alias for a in view.aliases}
    assert (provider.key, "tenant_data", True) in {
        (d.provider_key, d.classification, d.allowed) for d in view.destination_policy
    }
    assert _SECRET_VALUE not in repr(view)
    actions = [a for a, _, _, _ in _platform_rows(operator.user_id)]
    # The oversight read writes its attempt row, then its completion row.
    reads = [a for a in actions if a.startswith("platform.ai_config.read")]
    assert len(reads) == 2 and reads[1] == "platform.ai_config.read"
    assert reads[0].startswith("platform.ai_config.read") and reads[0] != reads[1]


def test_trust_entries_are_exact_unique_while_live_and_revocable(world: _World) -> None:
    operator = world.operator(P.AI_ENDPOINT_TRUST_MANAGE)
    host = f"{_unique('llm')}.internal.example"
    world.hosts.append(host)
    expires = datetime.now(UTC) + timedelta(days=30)
    entry = ai_config.create_trust_entry(
        host=host,
        port=443,
        networks=["10.20.0.0/16"],
        expires_at=expires,
        caller=operator,
        reason=_REASON,
    )
    with pytest.raises(AIConfigurationError):
        ai_config.create_trust_entry(
            host=host,
            port=443,
            networks=["10.30.0.0/16"],
            expires_at=expires,
            caller=operator,
            reason=_REASON,
        )
    for networks in (["127.0.0.0/8"], ["169.254.169.254/32"], ["8.8.8.0/24"]):
        with pytest.raises(AIConfigurationError):
            ai_config.create_trust_entry(
                host=host,
                port=8443,
                networks=networks,
                expires_at=expires,
                caller=operator,
                reason=_REASON,
            )
    with pytest.raises(AIConfigurationError):
        ai_config.create_trust_entry(
            host=host,
            port=8443,
            networks=["10.0.0.0/8"],
            expires_at=datetime.now(UTC) + timedelta(days=400),
            caller=operator,
            reason=_REASON,
        )
    revoked = ai_config.revoke_trust_entry(entry_id=entry.id, caller=operator, reason=_REASON)
    assert revoked.revoked
    again = ai_config.create_trust_entry(
        host=host,
        port=443,
        networks=["10.20.0.0/16"],
        expires_at=expires,
        caller=operator,
        reason=_REASON,
    )
    assert again.id != entry.id


def test_the_runtime_role_cannot_delete_configuration(world: _World) -> None:
    operator = world.operator(P.AI_PROVIDER_MANAGE)
    provider = world.provider(operator)
    with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as session:
        session.execute(
            text("DELETE FROM control_plane.ai_providers WHERE key = :k"), {"k": provider.key}
        )


# --- tenant AI policy -------------------------------------------------------------------


def _tenant_with_model(world: _World) -> tuple[uuid.UUID, str]:
    operator = world.operator(P.AI_PROVIDER_MANAGE)
    provider = world.provider(operator)
    ai_config.create_model(
        provider_key=provider.key,
        model_id="model-t",
        capabilities=["text_input", "text_output"],
        max_output_tokens=256,
        caller=operator,
        reason=_REASON,
    )
    return world.tenant(), provider.key


def _tenant_audit(tenant_id: uuid.UUID) -> list[tuple[str, str]]:
    with tenant_session_scope(tenant_id) as session:
        return [
            (row[0], row[1])
            for row in session.execute(
                text(
                    "SELECT action, outcome FROM core.audit_log WHERE tenant_id = :t "
                    "AND resource_type = 'ai_tenant_policy' ORDER BY created_at, id"
                ),
                {"t": str(tenant_id)},
            )
        ]


def test_a_tenant_manager_sets_the_policy_with_audit(world: _World) -> None:
    tenant_id, provider_key = _tenant_with_model(world)
    manager = world.member(tenant_id, ("ai.policy", "manage"), ("ai.policy", "read"))
    assert tenant_policy.set_tenant_ai_policy(tenant_id, enabled=True, caller=manager) is True
    tenant_policy.grant_use_case(
        tenant_id, use_case="support.summarize", classifications=["tenant_data"], caller=manager
    )
    grant = tenant_policy.grant_destination(
        tenant_id,
        use_case="support.summarize",
        provider_key=provider_key,
        model_id="model-t",
        classifications=["none", "tenant_data"],
        caller=manager,
    )
    assert grant.classifications == ("none", "tenant_data")
    view = tenant_policy.read_tenant_ai_policy(tenant_id, caller=manager)
    assert view.exists and view.enabled and view.version == 1
    assert [u.use_case for u in view.use_cases] == ["support.summarize"]
    assert [(d.provider_key, d.model_id) for d in view.destinations] == [(provider_key, "model-t")]
    assert _tenant_audit(tenant_id) == [
        ("ai.policy.set", "success"),
        ("ai.policy.grant_use_case", "success"),
        ("ai.policy.grant_destination", "success"),
    ]


def test_without_the_permission_the_change_is_refused_and_recorded(world: _World) -> None:
    tenant_id, _ = _tenant_with_model(world)
    reader = world.member(tenant_id, ("ai.policy", "read"))
    with pytest.raises(AuthorityNotAuthorizedError):
        tenant_policy.set_tenant_ai_policy(tenant_id, enabled=True, caller=reader)
    assert _tenant_audit(tenant_id) == [("ai.policy.set", "denied")]
    view = tenant_policy.read_tenant_ai_policy(tenant_id, caller=reader)
    assert not view.exists and not view.enabled


def test_support_access_can_read_and_never_change_the_policy(world: _World) -> None:
    tenant_id, _ = _tenant_with_model(world)
    engineer = world.support_engineer(tenant_id)
    assert not tenant_policy.read_tenant_ai_policy(tenant_id, caller=engineer).exists
    with pytest.raises(AuthorityNotAuthorizedError):
        tenant_policy.set_tenant_ai_policy(tenant_id, enabled=True, caller=engineer)
    with pytest.raises(AuthorityNotAuthorizedError):
        tenant_policy.grant_use_case(
            tenant_id, use_case="x", classifications=["none"], caller=engineer
        )


def test_a_system_purpose_cannot_write_tenant_ai_policy(world: _World) -> None:
    tenant_id, _ = _tenant_with_model(world)
    for authority in (SystemAuthority.PROVISIONING, SystemAuthority.BILLING_OPERATIONS):
        with pytest.raises(AuthorityNotAuthorizedError):
            tenant_policy.set_tenant_ai_policy(
                tenant_id, enabled=True, caller=SystemCaller(authority)
            )


def test_a_manager_of_one_tenant_cannot_change_another(world: _World) -> None:
    tenant_a, _ = _tenant_with_model(world)
    tenant_b = world.tenant()
    manager_a = world.member(tenant_a, ("ai.policy", "manage"))
    with pytest.raises(AuthorityNotAuthorizedError):
        tenant_policy.set_tenant_ai_policy(tenant_b, enabled=True, caller=manager_a)
    tenant_policy.set_tenant_ai_policy(tenant_a, enabled=True, caller=manager_a)
    # Tenant RLS: B's session sees none of A's rows.
    with tenant_session_scope(tenant_b) as session:
        visible = session.execute(
            text("SELECT count(*) FROM control_plane.ai_tenant_policies")
        ).scalar_one()
    assert visible == 0


def test_invalid_tenant_policy_input_is_refused_before_any_transaction(world: _World) -> None:
    tenant_id, provider_key = _tenant_with_model(world)
    manager = world.member(tenant_id, ("ai.policy", "manage"))
    for use_case, classifications in (("Bad Name", ["none"]), ("ok", []), ("ok", ["secret"])):
        with pytest.raises(ValueError):
            tenant_policy.grant_use_case(
                tenant_id, use_case=use_case, classifications=classifications, caller=manager
            )
    assert _tenant_audit(tenant_id) == []
    del provider_key
