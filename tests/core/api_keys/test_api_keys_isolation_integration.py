"""Cross-tenant integrity tests for `core.api_keys` against a real
PostgreSQL instance with the Phase 4.1 table actually migrated.

`core.api_keys` is deliberately GLOBAL, not RLS-protected
(`core/api_keys/models.py`'s own docstring) -- so this file's "isolation"
proof is structurally different from
`tests/core/rbac/test_rbac_isolation_integration.py`'s RLS-boundary
proofs: it proves the **composite foreign key**
`(tenant_id, user_id) -> core.tenant_memberships(tenant_id, user_id)` is
the real, database-enforced integrity guarantee (not merely a Python-level
check), and that every tenant-scoped read/write in
`core/api_keys/service.py` correctly filters by `tenant_id` even though
there is no RLS backstop to catch a missed filter.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/api_keys/test_api_keys_isolation_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.api_keys.errors import ApiKeyNotFoundError
from core.api_keys.service import create_api_key, get_api_key, list_api_keys, revoke_api_key
from core.identity.service import add_tenant_membership, create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_api_keys_table() -> None:
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

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    admin_engine = build_engine(get_migrations_database_config())
    try:
        admin_factory = build_session_factory(admin_engine)
        with session_scope(session_factory=admin_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        admin_engine.dispose()


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _TenantRig:
    def __init__(self, label: str) -> None:
        self.tenant = create_tenant(_unique_name(f"tenant-{label}"))
        self.user = create_user()
        self.membership = add_tenant_membership(self.tenant.id, self.user.id)


@pytest.fixture
def rig_a():
    return _TenantRig("a")


@pytest.fixture
def rig_b():
    return _TenantRig("b")


def _cleanup(rig: _TenantRig) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(rig.tenant.id)}
        )
    _admin_delete_audit_log_for_tenant(rig.tenant.id)
    with tenant_session_scope(rig.tenant.id) as session:
        session.execute(
            text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
            {"t": str(rig.tenant.id)},
        )
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(rig.user.id)})
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(rig.tenant.id)})


@pytest.fixture(autouse=True)
def _cleanup_rigs(rig_a: _TenantRig, rig_b: _TenantRig):
    yield
    _cleanup(rig_a)
    _cleanup(rig_b)


# --- Setup correctness -----------------------------------------------------


def test_api_keys_table_deliberately_has_no_rls() -> None:
    """Documents and proves the deliberate design choice
    (`core/api_keys/models.py`'s docstring): if a future change
    accidentally enabled RLS on this table, `validate_api_key()` would
    silently stop working for every key (an untenanted lookup would see
    zero rows) -- this test exists so that regression is caught here, not
    discovered as a production outage.
    """
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'api_keys'"
            )
        ).one()
    assert row[0] is False
    assert row[1] is False


def test_runtime_role_can_update_api_keys_unlike_audit_log() -> None:
    """Contrast with core.audit_log (Phase 3.4): api_keys legitimately
    needs UPDATE (revocation), so it is NOT revoked here."""
    with _admin_session() as session:
        rows = session.execute(
            text(
                "SELECT privilege_type FROM information_schema.role_table_grants "
                "WHERE grantee = 'saas_os_app' AND table_schema = 'core' "
                "AND table_name = 'api_keys'"
            )
        ).all()
    assert {r[0] for r in rows} == {"SELECT", "INSERT", "UPDATE", "DELETE"}


# --- Composite FK is the real, database-enforced boundary ------------------


def test_composite_fk_rejects_a_tenant_user_pair_with_no_real_membership(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    """Deliberately bypass `create_api_key()`'s own Python-level check and
    issue the raw SQL directly, as the real restricted runtime role, with
    rig_a's tenant_id paired with rig_b's user_id (who is NOT a member of
    rig_a's tenant) -- the composite FK must reject this at the database
    level, not merely via application code remembering to check.
    """
    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        with session_scope() as session:
            session.execute(
                text(
                    "INSERT INTO core.api_keys (id, tenant_id, user_id, name, key_hash) "
                    "VALUES (:id, :tid, :uid, 'forged', :hash)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tid": str(rig_a.tenant.id),
                    "uid": str(rig_b.user.id),
                    "hash": uuid.uuid4().hex + uuid.uuid4().hex,
                },
            )
    assert "foreign key" in str(excinfo.value).lower()


def test_composite_fk_accepts_a_genuine_membership_pair(rig_a: _TenantRig) -> None:
    key, _ = create_api_key(rig_a.tenant.id, rig_a.user.id, "genuine key")
    assert key.tenant_id == rig_a.tenant.id
    assert key.user_id == rig_a.user.id


# --- Explicit application-level tenant filtering (no RLS backstop) --------


def test_tenant_a_cannot_list_tenant_bs_keys(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    create_api_key(rig_a.tenant.id, rig_a.user.id, "a-key")
    create_api_key(rig_b.tenant.id, rig_b.user.id, "b-key")

    keys_for_a = list_api_keys(rig_a.tenant.id)
    assert all(k.tenant_id == rig_a.tenant.id for k in keys_for_a)
    assert "b-key" not in {k.name for k in keys_for_a}


def test_tenant_a_cannot_get_tenant_bs_key_by_id(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    key_b, _ = create_api_key(rig_b.tenant.id, rig_b.user.id, "b-key")

    with pytest.raises(ApiKeyNotFoundError):
        get_api_key(rig_a.tenant.id, key_b.id)


def test_tenant_a_cannot_revoke_tenant_bs_key(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    key_b, raw_b = create_api_key(rig_b.tenant.id, rig_b.user.id, "b-key")

    with pytest.raises(ApiKeyNotFoundError):
        revoke_api_key(rig_a.tenant.id, key_b.id)

    # Confirm it genuinely was not revoked -- still resolvable and valid
    # from tenant B's own perspective.
    from core.api_keys.service import validate_api_key

    still_valid = validate_api_key(raw_b)
    assert still_valid.id == key_b.id
    assert still_valid.revoked_at is None


def test_tenant_a_cannot_rotate_tenant_bs_key(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    key_b, raw_b = create_api_key(rig_b.tenant.id, rig_b.user.id, "b-key")

    from core.api_keys.errors import ApiKeyNotFoundError as NotFound
    from core.api_keys.service import rotate_api_key, validate_api_key

    with pytest.raises(NotFound):
        rotate_api_key(rig_a.tenant.id, key_b.id)

    still_valid = validate_api_key(raw_b)
    assert still_valid.id == key_b.id


def test_key_hash_lookup_resolves_to_its_own_tenant_never_another(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    """The one operation that must work *without* a tenant context
    (`validate_api_key`) must still resolve each key to exactly its own
    tenant -- never accidentally cross-associate two tenants' keys."""
    from core.api_keys.service import validate_api_key

    key_a, raw_a = create_api_key(rig_a.tenant.id, rig_a.user.id, "a-key")
    key_b, raw_b = create_api_key(rig_b.tenant.id, rig_b.user.id, "b-key")

    resolved_a = validate_api_key(raw_a)
    resolved_b = validate_api_key(raw_b)

    assert resolved_a.id == key_a.id
    assert resolved_a.tenant_id == rig_a.tenant.id
    assert resolved_b.id == key_b.id
    assert resolved_b.tenant_id == rig_b.tenant.id
    assert resolved_a.tenant_id != resolved_b.tenant_id
