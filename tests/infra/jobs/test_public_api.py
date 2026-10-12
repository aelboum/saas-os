"""`saas_os.infra.jobs`'s public API surface (docs/IMPLEMENTATION-ROADMAP.md Phase
2.4 correction, F4): the raw Redis connection (`get_redis_pool`) must not
be part of the top-level public namespace -- the intended surface is
enqueue/execute/retry/dead-letter only (ADR-0007's narrow interface), not
a general-purpose Redis client.

RA-12-7: `purge_tenant_dead_letters_sync` is exported (added to the
`expected` set below) as the one narrow, additional callable
`saas_os.core.tenancy.service.purge_tenant()` needs -- it still does not expose
`get_redis_pool` or any other raw connection primitive; the tests above
already prove that boundary independently.
"""

from __future__ import annotations

import pytest

import saas_os.infra.jobs


def test_get_redis_pool_is_not_in_all() -> None:
    assert "get_redis_pool" not in saas_os.infra.jobs.__all__


def test_get_redis_pool_is_not_a_module_attribute() -> None:
    assert not hasattr(saas_os.infra.jobs, "get_redis_pool")


def test_importing_get_redis_pool_from_the_top_level_package_fails() -> None:
    with pytest.raises(ImportError):
        from saas_os.infra.jobs import get_redis_pool  # type: ignore[attr-defined]  # noqa: F401


def test_get_redis_pool_remains_available_internally() -> None:
    """Removing it from the public surface must not delete the underlying
    functionality -- build_worker/enqueue_job still need it, and it
    remains importable from saas_os.infra.jobs.queue for internal/test use.
    """
    from saas_os.infra.jobs.queue import get_redis_pool

    assert callable(get_redis_pool)


def test_public_surface_matches_the_intended_narrow_interface() -> None:
    expected = {
        "JobsConfig",
        "get_jobs_config",
        "TenantJobPayload",
        "MissingTenantIdError",
        "InvalidJobPayloadError",
        "JobsConfigurationError",
        "JobDeadLetteredError",
        "DeadLetterEntry",
        "count_dead_letters",
        "list_dead_letters",
        "purge_tenant_dead_letters_sync",
        "enqueue_job",
        "register_tenant_job",
        "register_system_job",
        "registered_job_kind",
        "JobKind",
        "TenantJobContext",
        "SystemJobContext",
        "JobContractViolationError",
        "build_worker",
    }
    assert set(saas_os.infra.jobs.__all__) == expected
