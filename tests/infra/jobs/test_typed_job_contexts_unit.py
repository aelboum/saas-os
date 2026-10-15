"""Foundation Enforcement FE-5 -- typed tenant/system job contexts
(`saas_os/infra/jobs/context.py`; docs/ADR/0030-foundation-enforcement.md).

A job's registration kind decides which payload is valid. A mismatch is a
permanent contract failure: dead-lettered on the first attempt, never
retried, and the handler never runs. The worker hands handlers a typed
context; tenant handlers get a `uuid.UUID`, never a raw string.
"""

from __future__ import annotations

import ast
import inspect
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from arq import Retry

from saas_os.infra.jobs import (
    JobContractViolationError,
    JobKind,
    SystemJobContext,
    TenantJobContext,
    TenantJobPayload,
    registered_job_kind,
)
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.errors import JobDeadLetteredError, JobsConfigurationError
from saas_os.infra.jobs.queue import (
    _with_retry_and_dead_letter,
    enqueue_job,
    register_system_job,
    register_tenant_job,
)

if TYPE_CHECKING:
    from tests.infra.jobs.conftest import FakeRedisPool

pytestmark = pytest.mark.anyio

_CONFIG = JobsConfig(redis_url="redis://localhost:6379/0", max_tries=3)
_TENANT = "3f1c2e8b-7d4e-4619-8c0a-2f4d6b8e1a37"
_REPO = Path(__file__).resolve().parents[3]


@pytest.fixture
def dead_letters(monkeypatch: pytest.MonkeyPatch, fake_redis_pool: FakeRedisPool):  # type: ignore[no-untyped-def]
    async def _fake_get_redis_pool(config: object = None) -> FakeRedisPool:
        return fake_redis_pool

    monkeypatch.setattr("saas_os.infra.jobs.queue.get_redis_pool", _fake_get_redis_pool)
    return fake_redis_pool


# --- Every production job declares its kind ---------------------------------------


def test_every_registered_job_has_its_expected_explicit_kind() -> None:
    import saas_os.api.worker
    import saas_os.control_plane.self_learning.continuous_loop.service  # noqa: F401 -- registers its job

    worker_names = {function.name for function in saas_os.api.worker.registered_job_functions()}
    expected = {
        "_cleanup_expired_sessions_job": JobKind.SYSTEM,
        "_dispatch_notification_job": JobKind.TENANT,
        "_ingest_usage_event_job": JobKind.TENANT,
        "_deliver_webhook": JobKind.TENANT,
        "_run_continuous_learning_cycle_job": JobKind.TENANT,
        # RE-2: one claimed outbox event runs as its own tenant's job; the
        # dispatch cycle is a scheduled system job (a cron, not enqueued).
        "_run_outbox_event": JobKind.TENANT,
        "_dispatch_outbox_cycle": JobKind.SYSTEM,
        # ADR-0048: pruning the global billing-provider event ledger.
        "_prune_billing_provider_events_job": JobKind.SYSTEM,
    }
    assert worker_names == set(expected) - {
        "_run_continuous_learning_cycle_job",
        "_dispatch_outbox_cycle",
    }
    assert {name: registered_job_kind(name) for name in expected} == expected


def test_registering_a_name_again_with_another_kind_is_refused() -> None:
    async def _kind_conflict_job(context: object) -> None:
        return None

    register_system_job(_kind_conflict_job, config=_CONFIG)
    register_system_job(_kind_conflict_job, config=_CONFIG)  # same kind: fine
    with pytest.raises(JobsConfigurationError):
        register_tenant_job(_kind_conflict_job, config=_CONFIG)  # type: ignore[arg-type]


# --- Worker side: contract violations are permanent ----------------------------------


def _recording_tenant_handler():  # type: ignore[no-untyped-def]
    calls: list[tuple[object, object]] = []

    async def _tenant_job(context: TenantJobContext, payload: TenantJobPayload) -> str:
        calls.append((context, payload))
        return "ok"

    return _tenant_job, calls


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {"tenant_id": _TENANT},
        "not-a-payload",
        TenantJobPayload(tenant_id="tenant-a"),
        TenantJobPayload(tenant_id=_TENANT.upper()),
        TenantJobPayload(tenant_id="{" + _TENANT + "}"),
        TenantJobPayload(tenant_id=_TENANT.replace("-", "")),
        TenantJobPayload(tenant_id="urn:uuid:" + _TENANT),
    ],
    ids=["none", "dict", "str", "non-uuid-tenant", "upper", "braces", "no-hyphens", "urn"],
)
async def test_tenant_job_contract_violation_is_dead_lettered_without_retry(
    dead_letters: FakeRedisPool, payload: object
) -> None:
    handler, calls = _recording_tenant_handler()
    wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=JobKind.TENANT)
    with pytest.raises(JobDeadLetteredError) as excinfo:
        await wrapped({"job_try": 1, "job_id": "j"}, payload)  # first attempt: no Retry
    assert isinstance(excinfo.value.__cause__, JobContractViolationError)
    assert calls == []  # the handler never ran
    entries = dead_letters.lists[_CONFIG.dead_letter_key]
    assert len(entries) == 1
    assert b"JobContractViolationError" in entries[0]


async def test_system_job_given_a_tenant_payload_is_dead_lettered_without_retry(
    dead_letters: FakeRedisPool,
) -> None:
    calls: list[object] = []

    async def _system_job(context: SystemJobContext) -> None:
        calls.append(context)

    wrapped = _with_retry_and_dead_letter(_system_job, config=_CONFIG, kind=JobKind.SYSTEM)
    with pytest.raises(JobDeadLetteredError) as excinfo:
        await wrapped({"job_try": 1}, TenantJobPayload(tenant_id=_TENANT))
    assert isinstance(excinfo.value.__cause__, JobContractViolationError)
    assert calls == []
    assert len(dead_letters.lists[_CONFIG.dead_letter_key]) == 1


async def test_contract_violation_does_not_consume_the_retry_policy(
    dead_letters: FakeRedisPool,
) -> None:
    """Unlike a genuine handler failure, which is retried with backoff."""
    handler, _ = _recording_tenant_handler()
    wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=JobKind.TENANT)
    with pytest.raises(JobDeadLetteredError):
        await wrapped({"job_try": 1}, None)

    async def _failing(context: TenantJobContext, payload: TenantJobPayload) -> None:
        raise RuntimeError("transient")

    failing = _with_retry_and_dead_letter(_failing, config=_CONFIG, kind=JobKind.TENANT)
    with pytest.raises(Retry):
        await failing({"job_try": 1}, TenantJobPayload(tenant_id=_TENANT))


async def test_tenant_handler_receives_a_typed_uuid_context() -> None:
    handler, calls = _recording_tenant_handler()
    wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=JobKind.TENANT)
    payload = TenantJobPayload(tenant_id=_TENANT, correlation_id="req-1", data={"x": "1"})
    assert await wrapped({"job_try": 1}, payload) == "ok"
    ((context, received),) = calls
    assert isinstance(context, TenantJobContext)
    assert context.tenant_id == uuid.UUID(_TENANT)
    assert isinstance(context.tenant_id, uuid.UUID)
    assert context.correlation_id == "req-1"
    assert received is payload


async def test_system_handler_receives_a_system_context() -> None:
    seen: list[object] = []

    async def _system_job(context: SystemJobContext) -> None:
        seen.append(context)

    wrapped = _with_retry_and_dead_letter(_system_job, config=_CONFIG, kind=JobKind.SYSTEM)
    await wrapped({"job_try": 1}, None)
    assert seen == [SystemJobContext(correlation_id=None)]


# --- Enqueue side: the declared kind is enforced before Redis -------------------------


async def _enqueue_tenant_kind_job(context: TenantJobContext, payload: TenantJobPayload) -> None:
    return None


async def _enqueue_system_kind_job(context: SystemJobContext) -> None:
    return None


class _ExplodingPool:
    async def enqueue_job(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("must not reach Redis")


@pytest.mark.parametrize(
    ("handler", "register", "payload"),
    [
        (_enqueue_tenant_kind_job, register_tenant_job, None),
        (_enqueue_tenant_kind_job, register_tenant_job, TenantJobPayload(tenant_id="not-a-uuid")),
        (
            _enqueue_tenant_kind_job,
            register_tenant_job,
            TenantJobPayload(tenant_id=_TENANT.upper()),
        ),
        (_enqueue_system_kind_job, register_system_job, TenantJobPayload(tenant_id=_TENANT)),
    ],
    ids=["tenant-none", "tenant-non-uuid", "tenant-non-canonical", "system-with-payload"],
)
async def test_enqueue_refuses_a_payload_that_violates_the_declared_kind(
    handler,
    register,
    payload,  # type: ignore[no-untyped-def]
) -> None:
    register(handler, config=_CONFIG)
    with pytest.raises(JobContractViolationError):
        await enqueue_job(handler.__name__, payload, pool=_ExplodingPool())  # type: ignore[arg-type]


# --- D5: the existing lifecycle fences are pinned, not moved -----------------------------


def _calls_in_order(path: str, function: str) -> list[str]:
    tree = ast.parse((_REPO / path).read_text(encoding="utf-8"))
    target = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == function
    )
    calls = [node for node in ast.walk(target) if isinstance(node, ast.Call)]
    calls.sort(key=lambda node: (node.lineno, node.col_offset))
    return [ast.unparse(node.func) for node in calls]


def test_usage_job_keeps_its_manual_two_phase_fence() -> None:
    calls = _calls_in_order("saas_os/core/usage/service.py", "_ingest_usage_event_job")
    assert "tenant_job_session" not in calls
    assert calls.index("require_open_tenant") < calls.index("lock_open_tenant")


def test_notification_job_keeps_send_before_lock() -> None:
    calls = _calls_in_order("saas_os/core/notifications/service.py", "_dispatch_notification_job")
    assert "tenant_job_session" not in calls
    assert (
        calls.index("require_open_tenant")
        < calls.index("_send_email_channel")
        < calls.index("lock_open_tenant")
    )


def test_webhook_job_keeps_tenant_job_session() -> None:
    assert "tenant_job_session" in _calls_in_order(
        "saas_os/core/webhooks/service.py", "_deliver_webhook"
    )


def test_handlers_no_longer_parse_raw_tenant_ids() -> None:
    from saas_os.control_plane.self_learning.continuous_loop import service as loop
    from saas_os.core.notifications import service as notifications
    from saas_os.core.usage import service as usage
    from saas_os.core.webhooks import service as webhooks

    for handler in (
        usage._ingest_usage_event_job,
        notifications._dispatch_notification_job,
        webhooks._deliver_webhook,
        loop._run_continuous_learning_cycle_job,
    ):
        assert "uuid.UUID(payload.tenant_id)" not in inspect.getsource(handler)
        assert list(inspect.signature(handler).parameters) == ["context", "payload"]
