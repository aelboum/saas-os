"""`core/api_keys` issuance/validation/revocation/rotation integration
tests against a real PostgreSQL instance with the Phase 4.1 table actually
migrated (docs/IMPLEMENTATION-ROADMAP.md Phase 4.1: "issuance/revocation
lifecycle"; Acceptance Criteria: "full key lifecycle passes tests; revoked
key access attempt is denied and audit-logged").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_rbac_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/api_keys/test_api_keys_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.api_keys.errors import (
    ApiKeyNotFoundError,
    InvalidApiKeyError,
    InvalidApiKeyNameError,
    RevokedApiKeyError,
    TenantMembershipRequiredError,
)
from core.api_keys.service import (
    create_api_key,
    get_api_key,
    list_api_keys,
    revoke_api_key,
    rotate_api_key,
    validate_api_key,
)
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    """core.audit_log DELETE is REVOKEd from the restricted runtime role
    entirely (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 -- immutability is
    enforced at the privilege level). Test cleanup must use the privileged
    migrations role here, exactly like Phase 3.4's own test cleanup
    (tests/core/audit_log/test_audit_log_integration.py::_cleanup_tenant)
    -- this is test hygiene, not a code path any real application code
    ever exercises.
    """
    admin_engine = build_engine(get_migrations_database_config())
    try:
        admin_factory = build_session_factory(admin_engine)
        with session_scope(session_factory=admin_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        admin_engine.dispose()


@pytest.fixture(autouse=True)
def _require_reachable_database_with_api_keys_table() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.api_keys LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(f"core.api_keys does not exist yet -- run `alembic upgrade head` first: {exc}")
    finally:
        probe_engine.dispose()


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique_name("tenant"))
        self.user = create_user()
        self.membership = add_tenant_membership(self.tenant.id, self.user.id)

    def cleanup(self) -> None:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(self.tenant.id)}
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(self.user.id)}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fixture():
    f = _Fixture()
    try:
        yield f
    finally:
        f.cleanup()


# --- Issuance ------------------------------------------------------------


def test_create_api_key_returns_record_and_raw_secret(fixture: _Fixture) -> None:
    key, raw = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    assert key.tenant_id == fixture.tenant.id
    assert key.user_id == fixture.user.id
    assert key.name == "CI key"
    assert key.revoked_at is None
    assert isinstance(raw, str)
    assert len(raw) > 20


def test_raw_secret_is_never_persisted(fixture: _Fixture) -> None:
    key, raw = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    with session_scope() as session:
        row = session.execute(
            text("SELECT key_hash FROM core.api_keys WHERE id = :id"), {"id": str(key.id)}
        ).one()
    assert row.key_hash != raw
    assert raw not in row.key_hash
    assert len(row.key_hash) == 64  # sha256 hex digest length


def test_create_api_key_requires_real_tenant_membership(fixture: _Fixture) -> None:
    other_tenant = create_tenant(_unique_name("other-tenant"))
    try:
        # fixture.user is NOT a member of other_tenant.
        with pytest.raises(TenantMembershipRequiredError):
            create_api_key(other_tenant.id, fixture.user.id, "orphan key")
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(other_tenant.id)}
            )


def test_create_api_key_rejects_empty_name(fixture: _Fixture) -> None:
    with pytest.raises(InvalidApiKeyNameError):
        create_api_key(fixture.tenant.id, fixture.user.id, "")


def test_create_api_key_writes_an_audit_entry(fixture: _Fixture) -> None:
    key, _ = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    entries = list_audit_entries(
        fixture.tenant.id, resource_type="api_key", resource_id=str(key.id)
    )
    assert any(e.action == "api_key.create" and e.outcome == "success" for e in entries)


# --- Validation ------------------------------------------------------------


def test_validate_api_key_resolves_a_valid_key(fixture: _Fixture) -> None:
    key, raw = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    validated = validate_api_key(raw)
    assert validated.id == key.id
    assert validated.tenant_id == fixture.tenant.id
    assert validated.user_id == fixture.user.id


def test_validate_api_key_rejects_unknown_key(fixture: _Fixture) -> None:
    with pytest.raises(InvalidApiKeyError):
        validate_api_key("a-key-that-was-never-issued")


def test_validate_revoked_key_is_denied_and_audit_logged(fixture: _Fixture) -> None:
    key, raw = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    revoke_api_key(fixture.tenant.id, key.id)

    with pytest.raises(RevokedApiKeyError) as excinfo:
        validate_api_key(raw)
    assert excinfo.value.key_id == key.id

    entries = list_audit_entries(
        fixture.tenant.id, resource_type="api_key", resource_id=str(key.id)
    )
    denied = [e for e in entries if e.action == "api_key.validate" and e.outcome == "denied"]
    assert len(denied) == 1


def test_revocation_takes_effect_immediately(fixture: _Fixture) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 4.1 Security Requirement: "no
    cache staleness window" -- the very next validation call after
    revocation must see it."""
    key, raw = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    assert validate_api_key(raw).id == key.id  # valid before revocation

    revoke_api_key(fixture.tenant.id, key.id)

    with pytest.raises(RevokedApiKeyError):
        validate_api_key(raw)  # immediately invalid after -- no delay, no retry loop


# --- get()/list() --------------------------------------------------------


def test_get_api_key(fixture: _Fixture) -> None:
    key, _ = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    fetched = get_api_key(fixture.tenant.id, key.id)
    assert fetched.id == key.id


def test_get_unknown_api_key_raises(fixture: _Fixture) -> None:
    with pytest.raises(ApiKeyNotFoundError):
        get_api_key(fixture.tenant.id, uuid.uuid4())


def test_list_api_keys_returns_only_this_tenants_keys(fixture: _Fixture) -> None:
    key_a, _ = create_api_key(fixture.tenant.id, fixture.user.id, "key-a")
    other_tenant = create_tenant(_unique_name("other-tenant"))
    other_user = create_user()
    add_tenant_membership(other_tenant.id, other_user.id)
    try:
        create_api_key(other_tenant.id, other_user.id, "key-b")

        keys = list_api_keys(fixture.tenant.id)
        assert {k.id for k in keys} == {key_a.id}
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(other_tenant.id)}
            )
        _admin_delete_audit_log_for_tenant(other_tenant.id)
        with tenant_session_scope(other_tenant.id) as session:
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(other_tenant.id)},
            )
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(other_user.id)}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(other_tenant.id)}
            )


# --- Revocation ------------------------------------------------------------


def test_revoke_api_key_is_idempotent(fixture: _Fixture) -> None:
    key, _ = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    revoke_api_key(fixture.tenant.id, key.id)
    revoke_api_key(fixture.tenant.id, key.id)  # must not raise

    entries = list_audit_entries(
        fixture.tenant.id, resource_type="api_key", resource_id=str(key.id)
    )
    revocations = [e for e in entries if e.action == "api_key.revoke"]
    assert len(revocations) == 1  # only the first revocation is audit-logged


def test_revoke_unknown_api_key_raises(fixture: _Fixture) -> None:
    with pytest.raises(ApiKeyNotFoundError):
        revoke_api_key(fixture.tenant.id, uuid.uuid4())


# --- Rotation ------------------------------------------------------------


def test_rotate_api_key_revokes_old_and_issues_new(fixture: _Fixture) -> None:
    old_key, old_raw = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    new_key, new_raw = rotate_api_key(fixture.tenant.id, old_key.id)

    assert new_key.id != old_key.id
    assert new_raw != old_raw
    assert new_key.name == old_key.name
    assert new_key.tenant_id == fixture.tenant.id
    assert new_key.user_id == fixture.user.id

    with pytest.raises(RevokedApiKeyError):
        validate_api_key(old_raw)
    assert validate_api_key(new_raw).id == new_key.id


def test_rotate_api_key_writes_an_audit_entry_referencing_the_old_key(fixture: _Fixture) -> None:
    old_key, _ = create_api_key(fixture.tenant.id, fixture.user.id, "CI key")
    new_key, _ = rotate_api_key(fixture.tenant.id, old_key.id)

    entries = list_audit_entries(
        fixture.tenant.id, resource_type="api_key", resource_id=str(new_key.id)
    )
    rotations = [e for e in entries if e.action == "api_key.rotate"]
    assert len(rotations) == 1
    assert rotations[0].entry_metadata == {"previous_key_id": str(old_key.id)}


def test_rotate_unknown_api_key_raises(fixture: _Fixture) -> None:
    with pytest.raises(ApiKeyNotFoundError):
        rotate_api_key(fixture.tenant.id, uuid.uuid4())


# --- Full lifecycle (roadmap's own literal phrase) --------------------------


def test_full_key_lifecycle(fixture: _Fixture) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 4.1 Acceptance Criteria:
    "full key lifecycle passes tests"."""
    key, raw = create_api_key(fixture.tenant.id, fixture.user.id, "lifecycle-key")
    assert validate_api_key(raw).id == key.id

    rotated, rotated_raw = rotate_api_key(fixture.tenant.id, key.id)
    with pytest.raises(RevokedApiKeyError):
        validate_api_key(raw)
    assert validate_api_key(rotated_raw).id == rotated.id

    revoke_api_key(fixture.tenant.id, rotated.id)
    with pytest.raises(RevokedApiKeyError):
        validate_api_key(rotated_raw)

    still_listed = list_api_keys(fixture.tenant.id)
    assert rotated.id in {k.id for k in still_listed}  # revocation does not delete the row
