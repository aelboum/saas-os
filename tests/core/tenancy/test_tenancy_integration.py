"""`core/tenancy` CRUD/lifecycle integration test against a real PostgreSQL
instance with the `core.tenants` table actually migrated
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.1 acceptance criteria: "tenant CRUD
works").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/infra/test_db_integration.py` (Phase 2.1).

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/tenancy/test_tenancy_integration.py

If PostgreSQL is not reachable, or `core.tenants` doesn't exist yet
(migration not applied), the test skips with a clear message rather than
failing with a raw traceback.
"""

from __future__ import annotations

import uuid

import pytest
from infra.db.config import get_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import (
    InvalidTenantTransitionError,
    TenantNotFoundError,
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_tenants_table() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.tenants LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(f"core.tenants does not exist yet -- run `alembic upgrade head` first: {exc}")
    finally:
        probe_engine.dispose()


def _unique_name() -> str:
    return f"phase31-tenant-{uuid.uuid4().hex[:8]}"


def test_create_tenant_persists_a_pending_tenant() -> None:
    tenant = create_tenant(_unique_name())
    try:
        assert tenant.status == TenantStatus.PENDING.value
        assert tenant.id is not None
        fetched = get_tenant(tenant.id)
        assert fetched.id == tenant.id
        assert fetched.name == tenant.name
    finally:
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


def test_get_tenant_raises_for_an_unknown_id() -> None:
    with pytest.raises(TenantNotFoundError):
        get_tenant(uuid.uuid4())


def test_full_lifecycle_pending_active_suspended_active_deleted_purged() -> None:
    tenant = create_tenant(_unique_name())

    t = transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    assert t.status == TenantStatus.ACTIVE.value

    t = transition_tenant_status(tenant.id, TenantStatus.SUSPENDED)
    assert t.status == TenantStatus.SUSPENDED.value

    t = transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    assert t.status == TenantStatus.ACTIVE.value

    t = transition_tenant_status(tenant.id, TenantStatus.DELETED)
    assert t.status == TenantStatus.DELETED.value

    purge_tenant(tenant.id)
    with pytest.raises(TenantNotFoundError):
        get_tenant(tenant.id)


def test_invalid_transition_is_rejected_and_status_is_unchanged() -> None:
    tenant = create_tenant(_unique_name())
    try:
        with pytest.raises(InvalidTenantTransitionError):
            transition_tenant_status(tenant.id, TenantStatus.PURGED)

        still_pending = get_tenant(tenant.id)
        assert still_pending.status == TenantStatus.PENDING.value
    finally:
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


def test_purge_requires_deleted_status_first() -> None:
    tenant = create_tenant(_unique_name())
    try:
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
        with pytest.raises(InvalidTenantTransitionError):
            purge_tenant(tenant.id)

        still_present = get_tenant(tenant.id)
        assert still_present.status == TenantStatus.ACTIVE.value
    finally:
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


def test_transition_validates_against_the_freshly_read_database_status_not_a_stale_value() -> None:
    """A caller cannot bypass lifecycle validation with a stale in-memory
    status: transition the tenant out-of-band (raw SQL, simulating a
    concurrent process), then confirm `transition_tenant_status` validates
    against what is *actually* in the database right now.
    """
    tenant = create_tenant(_unique_name())
    try:
        # Out-of-band transition straight to a terminal-ish state that
        # normal application code could never produce via the service
        # layer alone (pending -> deleted directly, which IS allowed --
        # then simulate reaching `purged` out of band to prove the
        # *next* call re-reads reality, not a cached value).
        with session_scope() as session:
            session.execute(
                text("UPDATE core.tenants SET status = :status WHERE id = :id"),
                {"status": TenantStatus.PURGED.value, "id": str(tenant.id)},
            )

        with pytest.raises(InvalidTenantTransitionError) as excinfo:
            transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
        assert excinfo.value.current_status == TenantStatus.PURGED
    finally:
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
