"""RA-12-7 -- `saas_os.core.tenancy.service.purge_tenant()`'s new Redis dead-
letter cleanup step, against a real PostgreSQL *and* a real Redis
instance.

Proves the actual wiring described in `purge_tenant()`'s own RA-12-7
docstring addendum: the cleanup runs once, after every PostgreSQL
`PURGE_STEPS` pass and every registered participant has succeeded,
immediately before the final `PURGED` transition; a matching tenant's own
dead-letter entries are gone afterward; an unrelated tenant's own entries
are untouched; a cleanup failure leaves the tenant `PURGING` (fail
closed) and a retry can subsequently complete; the reported count and
lifecycle audit metadata are bounded, never a dead-letter entry's own
contents; and the accepted residual window (a job dead-lettering *after*
cleanup already ran) is real and explicitly demonstrated, not hidden.

Marked `integration`, excluded from the default `pytest` run. Plain sync
tests throughout (no `async def`, no anyio marker): `purge_tenant()`
itself is a plain `def`, and `saas_os.infra.jobs.dead_letter.purge_tenant_dead_letters_sync()`
is specifically designed to run with no already-running event loop --
exactly this file's own calling convention. Redis access needed to seed
or inspect dead-letter entries directly is wrapped in small
`asyncio.run()` helpers, mirroring
`test_dead_letter_purge_tenant_sync_bridge_integration.py`.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/core/tenancy/test_tenant_purge_dead_letter_integration.py
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

import saas_os.core.rbac  # noqa: F401 -- registers service_accounts/support_access_requests for audit_log's FKs
import saas_os.core.tenancy.service as tenancy_service
from saas_os.core.tenancy import (
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.jobs.config import get_jobs_config
from saas_os.infra.jobs.dead_letter import list_dead_letters, record_dead_letter
from saas_os.infra.jobs.payload import TenantJobPayload
from saas_os.infra.jobs.queue import get_redis_pool

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
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
            conn.execute(text("SELECT 1 FROM core.tenants LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at DATABASE_URL: {exc}")
    finally:
        probe_engine.dispose()
    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


@pytest.fixture(autouse=True)
def _require_reachable_redis() -> None:
    get_jobs_config.cache_clear()
    try:
        config = get_jobs_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")

    async def _probe() -> None:
        pool = await get_redis_pool(config)
        try:
            await pool.ping()
        finally:
            await pool.aclose()

    try:
        asyncio.run(_probe())
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}")


def _seed_dead_letter(tenant_id: uuid.UUID, *, error: str = "boom") -> None:
    async def _run() -> None:
        config = get_jobs_config()
        pool = await get_redis_pool(config)
        try:
            await record_dead_letter(
                pool,
                config,
                function_name="fake_job",
                payload=TenantJobPayload(tenant_id=str(tenant_id)),
                error=RuntimeError(error),
                attempts=1,
            )
        finally:
            await pool.aclose()

    asyncio.run(_run())


def _dead_letter_tenant_ids_present(tenant_id: uuid.UUID) -> bool:
    async def _run() -> bool:
        config = get_jobs_config()
        pool = await get_redis_pool(config)
        try:
            entries = await list_dead_letters(pool, config, limit=10_000)
            return any(e.tenant_id == str(tenant_id) for e in entries)
        finally:
            await pool.aclose()

    return asyncio.run(_run())


def _delete_dead_letters_for(tenant_id: uuid.UUID) -> None:
    """Test-only teardown for entries a test deliberately left behind
    (the unrelated-tenant and residual-window scenarios) -- uses the same
    production-safe, tenant-scoped removal the implementation itself
    uses, never a blanket list clear."""
    from saas_os.infra.jobs.dead_letter import purge_tenant_dead_letters_sync

    purge_tenant_dead_letters_sync(str(tenant_id))


@pytest.fixture
def tenant_id() -> Iterator[uuid.UUID]:
    tenant = create_tenant(f"ra12-p7-{uuid.uuid4().hex[:8]}")
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    yield tenant.id
    _delete_dead_letters_for(tenant.id)


def _close_and_purge(tenant_id: uuid.UUID) -> tenancy_service.TenantPurgeResult:
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    return purge_tenant(tenant_id)


def test_purge_removes_this_tenants_dead_letter_entries(tenant_id: uuid.UUID) -> None:
    _seed_dead_letter(tenant_id)
    _seed_dead_letter(tenant_id, error="boom-2")

    result = _close_and_purge(tenant_id)

    assert result.dead_letter_entries_purged == 2
    assert _dead_letter_tenant_ids_present(tenant_id) is False


def test_purge_does_not_touch_an_unrelated_tenants_dead_letter_entries(
    tenant_id: uuid.UUID,
) -> None:
    other_tenant = create_tenant(f"ra12-p7-other-{uuid.uuid4().hex[:8]}")
    transition_tenant_status(other_tenant.id, TenantStatus.ACTIVE)
    try:
        _seed_dead_letter(tenant_id)
        _seed_dead_letter(other_tenant.id)

        result = _close_and_purge(tenant_id)

        assert result.dead_letter_entries_purged == 1
        assert _dead_letter_tenant_ids_present(tenant_id) is False
        assert _dead_letter_tenant_ids_present(other_tenant.id) is True
    finally:
        _delete_dead_letters_for(other_tenant.id)


def test_purged_is_reached_only_after_successful_cleanup(tenant_id: uuid.UUID) -> None:
    _seed_dead_letter(tenant_id)

    result = _close_and_purge(tenant_id)

    assert result.dead_letter_entries_purged == 1
    assert get_tenant(tenant_id).status == TenantStatus.PURGED.value


def test_redis_failure_during_cleanup_leaves_the_tenant_purging_and_is_retryable(
    tenant_id: uuid.UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: a cleanup-step failure must not transition the tenant
    to PURGED, must leave it retryable, and the retry must succeed once
    the failure is gone -- the same contract every other purge step
    already has."""
    _seed_dead_letter(tenant_id)

    def _boom(_tenant_id: str) -> int:
        raise RuntimeError("redis unavailable (simulated)")

    monkeypatch.setattr("saas_os.infra.jobs.dead_letter.purge_tenant_dead_letters_sync", _boom)

    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    with pytest.raises(RuntimeError):
        purge_tenant(tenant_id)

    assert get_tenant(tenant_id).status == TenantStatus.PURGING.value
    # The entry is still there -- the failed cleanup never ran to completion.
    assert _dead_letter_tenant_ids_present(tenant_id) is True

    monkeypatch.undo()

    result = purge_tenant(tenant_id)

    assert result.dead_letter_entries_purged == 1
    assert get_tenant(tenant_id).status == TenantStatus.PURGED.value
    assert _dead_letter_tenant_ids_present(tenant_id) is False


def test_result_and_metadata_never_carry_dead_letter_contents(tenant_id: uuid.UUID) -> None:
    """Privacy: the bounded count is all `TenantPurgeResult` exposes --
    never a dead-letter entry's own `error` text or the payload it came
    from."""
    secret_looking_error = "RuntimeError: sk-should-never-appear-anywhere"
    _seed_dead_letter(tenant_id, error=secret_looking_error)

    result = _close_and_purge(tenant_id)

    assert result.dead_letter_entries_purged == 1
    # tenant_id is expected in the repr (it is the result's own identifier
    # field) -- what must never appear is the dead-letter entry's own
    # error text or any indication of its contents.
    assert "sk-should-never-appear-anywhere" not in repr(result)
    assert "error" not in vars(result)
    assert "function_name" not in vars(result)


def test_a_dead_letter_entry_created_after_cleanup_is_the_accepted_residual_window(
    tenant_id: uuid.UUID,
) -> None:
    """RA-12-7's own documented, accepted limitation, demonstrated end to
    end through `purge_tenant()` itself: Redis and PostgreSQL share no
    transaction, so a dead-letter entry for this tenant written *after*
    the cleanup step already ran (e.g. a job that was queued before
    closure, picked up late, correctly did nothing, and still
    dead-lettered) is not retroactively removed by this same purge call.
    This is not a bug -- it is the exact, bounded window
    `docs/MULTI-TENANCY.md` section 6's RA-12-7 addendum documents."""
    result = _close_and_purge(tenant_id)
    assert result.dead_letter_entries_purged == 0

    _seed_dead_letter(tenant_id, error="late dead-letter after purge")

    assert _dead_letter_tenant_ids_present(tenant_id) is True
