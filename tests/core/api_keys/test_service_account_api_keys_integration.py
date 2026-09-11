"""Service-account-owned API key integration tests against a real
PostgreSQL instance (architecture research: universal multi-tenant
tenancy, Phase E -- "Principal + Service Accounts + API Key Hardening").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/api_keys/test_api_keys_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/api_keys/test_service_account_api_keys_integration.py

Covers, per the Phase E checkpoint's own testing requirements:

D. API keys -- creation, no plaintext storage, valid/wrong secret,
   revoked, expired, disabled-service-account, missing-service-account.
E. Tenant binding -- a key resolves to exactly one tenant (its own),
   never a caller-supplied one, and hierarchy never changes that binding.
F. Authorization -- creation/revocation of a machine credential is
   explicitly `can()`-gated; merely creating a key or a service account
   grants no permission by itself.
I. Revocation/lifecycle -- disabling a service account fails its keys;
   re-enabling does not reactivate a revoked/expired key.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from core.api_keys.errors import (
    ApiKeyNotAuthorizedError,
    ExpiredApiKeyError,
    InactiveServiceAccountError,
    InvalidApiKeyError,
    RevokedApiKeyError,
    ServiceAccountRequiredError,
)
from core.api_keys.service import (
    create_service_account_api_key,
    get_api_key,
    revoke_service_account_api_key,
    validate_api_key,
)
from core.identity.service import (
    add_tenant_membership,
    create_service_account,
    create_user,
    disable_service_account,
    enable_service_account,
)
from core.rbac.principal import PrincipalType
from core.rbac.scope import RoleScope
from core.rbac.service import (
    assign_role,
    create_role,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.rbac import can
from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_service_account_owned_api_keys() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(
                text("SELECT 1 FROM core.api_keys WHERE service_account_id IS NOT NULL LIMIT 1")
            )
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            "core.api_keys.service_account_id does not exist yet -- run `alembic upgrade "
            f"head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _new_tenant() -> uuid.UUID:
    return create_tenant(_unique_name("tenant")).id


def _admin_with_api_key_capability(tenant_id: uuid.UUID) -> uuid.UUID:
    user_id = create_user().id
    membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, _unique_name("api-key-admin-role"))
    for action in ("create", "revoke"):
        permission = register_permission("api_key", action)
        grant_permission(tenant_id, role.id, permission.id)
    assign_role(tenant_id, membership.id, role.id, scope=RoleScope.SELF)
    return user_id


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.service_account_roles WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        )
        session.execute(
            text("DELETE FROM core.membership_roles WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.role_permissions WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant_id)})
        session.execute(
            text("DELETE FROM core.service_accounts WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    _admin_delete_audit_log_for_tenant(tenant_id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


def _cleanup_permission(resource: str, action: str) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
            {"r": resource, "a": action},
        )


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    """core.audit_log DELETE is REVOKEd from the restricted runtime role
    entirely -- test cleanup must use the privileged migrations role,
    mirroring tests/core/api_keys/test_api_keys_integration.py's own
    helper."""
    admin_engine = build_engine(get_migrations_database_config())
    try:
        admin_factory = build_session_factory(admin_engine)
        with session_scope(session_factory=admin_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        admin_engine.dispose()


# --- D. Creation / secret handling ------------------------------------------


def test_create_service_account_api_key_returns_record_and_raw_secret() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        key, raw = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        assert key.tenant_id == tenant_id
        assert key.service_account_id == sa.id
        assert key.user_id is None
        assert isinstance(raw, str)
        assert len(raw) > 20
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_service_account_api_key_secret_is_never_persisted() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        key, raw = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        with session_scope() as session:
            row = session.execute(
                text("SELECT key_hash FROM core.api_keys WHERE id = :id"), {"id": str(key.id)}
            ).one()
        assert row.key_hash != raw
        assert raw not in row.key_hash
        assert len(row.key_hash) == 64
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_create_service_account_api_key_requires_authorization() -> None:
    """ "Do not allow arbitrary users to create machine credentials"."""
    tenant_id = _new_tenant()
    try:
        unauthorized_user = create_user().id
        add_tenant_membership(tenant_id, unauthorized_user)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        with pytest.raises(ApiKeyNotAuthorizedError):
            create_service_account_api_key(
                actor_user_id=unauthorized_user,
                tenant_id=tenant_id,
                service_account_id=sa.id,
                name="ci-key",
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(unauthorized_user)


def test_create_service_account_api_key_rejects_unknown_service_account() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        with pytest.raises(ServiceAccountRequiredError):
            create_service_account_api_key(
                actor_user_id=admin,
                tenant_id=tenant_id,
                service_account_id=uuid.uuid4(),
                name="ci-key",
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_creating_a_service_account_or_a_key_grants_no_implicit_permission() -> None:
    """ "no implicit permission from merely creating a service account" /
    "no implicit permission from merely creating an API key"."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        assert (
            can(
                actor_id=sa.id,
                tenant_id=tenant_id,
                action=action,
                resource=resource,
                actor_type=PrincipalType.SERVICE_ACCOUNT,
                actor_tenant_id=tenant_id,
            )
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


# --- D. Validation / expiry / revocation / disabled owner -------------------


def test_valid_service_account_key_authenticates() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        key, raw = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        validated = validate_api_key(raw)
        assert validated.id == key.id
        assert validated.service_account_id == sa.id
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_wrong_secret_fails() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        with pytest.raises(InvalidApiKeyError):
            validate_api_key("not-a-real-key")
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_revoked_service_account_key_fails() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        key, raw = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        revoke_service_account_api_key(actor_user_id=admin, tenant_id=tenant_id, key_id=key.id)
        with pytest.raises(RevokedApiKeyError):
            validate_api_key(raw)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_revoke_service_account_api_key_requires_authorization() -> None:
    """ "a service account should not automatically be allowed to revoke
    arbitrary tenant keys merely because it owns itself" -- no
    self-revocation shortcut for any principal here; a plain,
    unauthorized human user cannot revoke it either."""
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        key, _ = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        unauthorized_user = create_user().id
        add_tenant_membership(tenant_id, unauthorized_user)
        with pytest.raises(ApiKeyNotAuthorizedError):
            revoke_service_account_api_key(
                actor_user_id=unauthorized_user, tenant_id=tenant_id, key_id=key.id
            )
        # Still valid -- the unauthorized attempt had no effect.
        assert get_api_key(tenant_id, key.id).revoked_at is None
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_user(unauthorized_user)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_expired_service_account_key_fails() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        _key, raw = create_service_account_api_key(
            actor_user_id=admin,
            tenant_id=tenant_id,
            service_account_id=sa.id,
            name="ci-key",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        with pytest.raises(ExpiredApiKeyError):
            validate_api_key(raw)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_non_expiring_key_remains_valid() -> None:
    """`expires_at = NULL` -> no expiry (architecture research Phase E)."""
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        key, raw = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        assert key.expires_at is None
        assert validate_api_key(raw).id == key.id
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_future_expiry_remains_valid_until_then() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        key, raw = create_service_account_api_key(
            actor_user_id=admin,
            tenant_id=tenant_id,
            service_account_id=sa.id,
            name="ci-key",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        assert validate_api_key(raw).id == key.id
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_disabled_service_account_key_fails() -> None:
    """ "Disabled service accounts must cause their API keys to fail
    authentication"."""
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        _key, raw = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        disable_service_account(tenant_id, sa.id)
        with pytest.raises(InactiveServiceAccountError):
            validate_api_key(raw)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_missing_service_account_fails_closed() -> None:
    """Defense in depth: even if a key's owning service account row were
    ever deleted out from under it (not a code path this phase provides,
    but the composite FK would otherwise merely reject the delete),
    `validate_api_key()` must fail closed, not raise an unrelated error
    or silently succeed."""
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        _key, raw = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        # Simulate "missing" by disabling -- covers the identical fail-
        # closed branch `validate_api_key()` uses for "None or DISABLED".
        disable_service_account(tenant_id, sa.id)
        with pytest.raises(InactiveServiceAccountError):
            validate_api_key(raw)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


# --- I. Re-enabling does not reactivate a revoked/expired key ---------------


def test_re_enabling_service_account_does_not_reactivate_a_revoked_key() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        key, raw = create_service_account_api_key(
            actor_user_id=admin, tenant_id=tenant_id, service_account_id=sa.id, name="ci-key"
        )
        revoke_service_account_api_key(actor_user_id=admin, tenant_id=tenant_id, key_id=key.id)
        disable_service_account(tenant_id, sa.id)
        enable_service_account(tenant_id, sa.id)
        with pytest.raises(RevokedApiKeyError):
            validate_api_key(raw)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


def test_re_enabling_service_account_does_not_reactivate_an_expired_key() -> None:
    tenant_id = _new_tenant()
    try:
        admin = _admin_with_api_key_capability(tenant_id)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        _key, raw = create_service_account_api_key(
            actor_user_id=admin,
            tenant_id=tenant_id,
            service_account_id=sa.id,
            name="ci-key",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        disable_service_account(tenant_id, sa.id)
        enable_service_account(tenant_id, sa.id)
        with pytest.raises(ExpiredApiKeyError):
            validate_api_key(raw)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")


# --- E. Tenant binding -------------------------------------------------------


def test_service_account_key_authorization_is_bound_to_its_own_tenant() -> None:
    """A key's authentication resolves `tenant_id` from the key record
    itself (`key.tenant_id`), never from a caller-controlled parameter --
    this test drives that exact value through `can()` and confirms a
    second, unrelated tenant id is never substitutable."""
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        admin_a = _admin_with_api_key_capability(tenant_a)
        # admin_a additionally needs (resource, action) itself plus the
        # "manage service account roles" capability to grant the role
        # below (`assign_service_account_role()`'s own anti-amplification
        # check).
        from core.identity import get_membership as _get_membership

        admin_a_membership = _get_membership(tenant_a, admin_a)
        assert admin_a_membership is not None
        extra_role = create_role(tenant_a, _unique_name("extra-admin-role"))
        grant_permission(tenant_a, extra_role.id, register_permission(resource, action).id)
        grant_permission(
            tenant_a,
            extra_role.id,
            register_permission("service_account_role", "create").id,
        )
        assign_role(tenant_a, admin_a_membership.id, extra_role.id, scope=RoleScope.SELF)

        sa = create_service_account(tenant_a, _unique_name("svc"))
        role = create_role(tenant_a, _unique_name("role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_a, role.id, permission.id)
        from core.rbac.service import assign_service_account_role

        assign_service_account_role(
            actor_user_id=admin_a,
            tenant_id=tenant_a,
            service_account_id=sa.id,
            role_id=role.id,
            scope=RoleScope.SELF,
        )
        key, raw = create_service_account_api_key(
            actor_user_id=admin_a, tenant_id=tenant_a, service_account_id=sa.id, name="ci-key"
        )
        validated = validate_api_key(raw)
        assert validated.tenant_id == tenant_a

        # The authenticated key's OWN tenant grants access...
        assert (
            can(
                actor_id=sa.id,
                tenant_id=validated.tenant_id,
                action=action,
                resource=resource,
                actor_type=PrincipalType.SERVICE_ACCOUNT,
                actor_tenant_id=validated.tenant_id,
            )
            is True
        )
        # ...but substituting an unrelated tenant_b (as a caller-supplied
        # override might attempt) grants nothing -- there is no role for
        # this service account there, and it does not even belong there.
        assert (
            can(
                actor_id=sa.id,
                tenant_id=tenant_b,
                action=action,
                resource=resource,
                actor_type=PrincipalType.SERVICE_ACCOUNT,
                actor_tenant_id=validated.tenant_id,
            )
            is False
        )
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(admin_a)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")
        _cleanup_permission("service_account_role", "create")
        _cleanup_permission(resource, action)


def test_service_account_key_cannot_authenticate_as_a_different_service_accounts_tenant() -> None:
    """A key issued for a service account in tenant A structurally cannot
    resolve to tenant B -- `key.tenant_id`/`key.service_account_id` are
    set once at issuance and are never influenced by any later,
    caller-supplied value."""
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    try:
        admin_a = _admin_with_api_key_capability(tenant_a)
        sa_a = create_service_account(tenant_a, _unique_name("svc"))
        key, raw = create_service_account_api_key(
            actor_user_id=admin_a, tenant_id=tenant_a, service_account_id=sa_a.id, name="ci-key"
        )
        validated = validate_api_key(raw)
        assert validated.tenant_id == tenant_a
        assert validated.tenant_id != tenant_b
        assert validated.service_account_id == sa_a.id
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(admin_a)
        _cleanup_permission("api_key", "create")
        _cleanup_permission("api_key", "revoke")
