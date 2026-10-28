"""Ledger row 900: webhook destination errors stored before pull request
#110 carried the destination URL. `redact_stored_webhook_url_errors()`
rewrites those stored texts, in the outbox `last_error` of every tenant
(closed ones included) and in the Redis dead-letter list, and nothing else.
Real PostgreSQL and Redis; the dead-letter list is a per-test key."""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Iterator, Mapping
from typing import cast

import pytest
from sqlalchemy import text

import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.core.outbox import OUTBOX_STATUS_DEAD_LETTERED, OutboxEvent, append_event
from saas_os.core.outbox.dispatch import describe_error
from saas_os.core.tenancy import create_tenant, list_tenant_ids
from saas_os.core.webhooks.errors import WebhookDestinationRejectedError
from saas_os.core.webhooks.stored_errors import (
    REDACTED_MESSAGE,
    redact_stored_webhook_url_errors,
)
from saas_os.infra.db import select
from saas_os.infra.db.config import get_migrations_database_config
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.jobs import get_jobs_config
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.queue import get_redis_pool

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_URL = "https://u:pw-canary-0900@hooks.example.test/?t=tok-canary-0900"  # pragma: allowlist secret
_CANARIES = ("pw-canary-0900", "tok-canary-0900", "hooks.example.test")


def _legacy(type_name: str) -> str:
    # The stored text these errors had before pull request #110.
    return f"{type_name}: Invalid webhook URL: {_URL!r} (must be http:// or https://)."


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _admin(sql: str, params: Mapping[str, object]) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            session.execute(text(sql), params)
    finally:
        engine.dispose()


class _Tenants:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.ids: list[uuid.UUID] = []
        monkeypatch.setattr(
            dispatch, "list_tenant_ids", lambda: [t for t in list_tenant_ids() if t in self.ids]
        )

    def new(self) -> uuid.UUID:
        tenant_id = create_tenant(f"wh-redact-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
        self.ids.append(tenant_id)
        return tenant_id

    def cleanup(self) -> None:
        for tenant_id in self.ids:
            params = {"t": str(tenant_id)}
            _admin("DELETE FROM core.outbox_events WHERE tenant_id = :t", params)
            _admin(
                "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t",
                params,
            )
            _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
            _admin("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", params)
            _admin("DELETE FROM core.tenants WHERE id = :t", params)


@pytest.fixture
def tenants(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Tenants]:
    registry = _Tenants(monkeypatch)
    try:
        yield registry
    finally:
        registry.cleanup()


@pytest.fixture
async def jobs_config() -> JobsConfig:
    config = JobsConfig(
        redis_url=get_jobs_config().redis_url,
        dead_letter_key=f"test-dead-letter-{uuid.uuid4().hex[:8]}",
    )
    try:
        pool = await get_redis_pool(config)
        await pool.ping()
        await pool.aclose()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable: {exc}")
    return config


def _event(tenant_id: uuid.UUID, last_error: str | None) -> uuid.UUID:
    with tenant_session_scope(tenant_id) as session:
        event_id = append_event(
            session,
            tenant_id=tenant_id,
            event_type="webhook.delivery",
            aggregate_type="webhook_subscription",
            aggregate_id=str(uuid.uuid4()),
            payload={},
        )
    _admin(
        "UPDATE core.outbox_events SET status = :s, attempts = 3, last_error = :e WHERE id = :i",
        {"s": OUTBOX_STATUS_DEAD_LETTERED, "e": last_error, "i": str(event_id)},
    )
    return event_id


def _stored(tenant_id: uuid.UUID, event_id: uuid.UUID) -> tuple[str | None, str, int]:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        return row.last_error, row.status, row.attempts


async def _dead_letters(config: JobsConfig) -> list[bytes]:
    pool = await get_redis_pool(config)
    try:
        return await cast("Awaitable[list[bytes]]", pool.lrange(config.dead_letter_key, 0, -1))
    finally:
        await pool.aclose()


async def _push(config: JobsConfig, *raw: str) -> None:
    pool = await get_redis_pool(config)
    try:
        await cast("Awaitable[int]", pool.rpush(config.dead_letter_key, *raw))
    finally:
        await pool.aclose()


async def _drop(config: JobsConfig) -> None:
    pool = await get_redis_pool(config)
    try:
        await cast("Awaitable[int]", pool.delete(config.dead_letter_key))
    finally:
        await pool.aclose()


def _entry(error: str, tenant_id: str | None) -> str:
    return json.dumps(
        {
            "function_name": "_deliver_webhook",
            "tenant_id": tenant_id,
            "error": error,
            "attempts": 3,
            "dead_lettered_at": 1761600000.25,
        }
    )


async def test_stored_url_errors_are_counted_then_redacted_and_nothing_else(
    tenants: _Tenants, jobs_config: JobsConfig
) -> None:
    open_tenant, closed_tenant = tenants.new(), tenants.new()
    _admin("UPDATE core.tenants SET status = 'deleted' WHERE id = :t", {"t": str(closed_tenant)})
    rejected = _event(open_tenant, _legacy("WebhookDestinationRejectedError"))
    unresolved = _event(closed_tenant, _legacy("WebhookDestinationUnresolvedError"))
    fallback = _event(open_tenant, _legacy("InvalidWebhookUrlError"))
    current = describe_error(WebhookDestinationRejectedError(_URL))
    untouched: dict[uuid.UUID, tuple[uuid.UUID, str | None]] = {
        _event(open_tenant, current): (open_tenant, current),
        _event(open_tenant, "WebhookDeliveryError: HTTP 500"): (
            open_tenant,
            "WebhookDeliveryError: HTTP 500",
        ),
        _event(closed_tenant, None): (closed_tenant, None),
    }
    others = [
        _entry("WebhookDeliveryError: HTTP 503", str(open_tenant)),
        "not json at all",
        json.dumps({"error": None}),
    ]
    await _push(
        jobs_config,
        _entry(_legacy("WebhookDestinationRejectedError"), str(open_tenant)),
        others[0],
        _entry(_legacy("WebhookDestinationUnresolvedError"), None),
        others[1],
        others[2],
    )
    try:
        counted = await redact_stored_webhook_url_errors(apply=False, config=jobs_config)
        assert (counted.applied, counted.outbox_events, counted.dead_letter_entries) == (
            False,
            3,
            2,
        )
        assert _stored(open_tenant, rejected)[0] == _legacy("WebhookDestinationRejectedError")
        assert any(b"pw-canary-0900" in raw for raw in await _dead_letters(jobs_config))

        applied = await redact_stored_webhook_url_errors(apply=True, config=jobs_config)
        assert (applied.applied, applied.outbox_events, applied.dead_letter_entries) == (
            True,
            3,
            2,
        )
        for tenant_id, event_id, type_name in (
            (open_tenant, rejected, "WebhookDestinationRejectedError"),
            (closed_tenant, unresolved, "WebhookDestinationUnresolvedError"),
            (open_tenant, fallback, "InvalidWebhookUrlError"),
        ):
            assert _stored(tenant_id, event_id) == (
                f"{type_name}: {REDACTED_MESSAGE}",
                OUTBOX_STATUS_DEAD_LETTERED,
                3,
            )
        for event_id, (tenant_id, expected) in untouched.items():
            assert _stored(tenant_id, event_id)[0] == expected

        raw_entries = await _dead_letters(jobs_config)
        assert len(raw_entries) == 5
        for raw in raw_entries:
            for canary in _CANARIES:
                assert canary.encode() not in raw, raw
        first, second, third, fourth, fifth = raw_entries
        assert json.loads(first) == {
            "function_name": "_deliver_webhook",
            "tenant_id": str(open_tenant),
            "error": f"WebhookDestinationRejectedError: {REDACTED_MESSAGE}",
            "attempts": 3,
            "dead_lettered_at": 1761600000.25,
        }
        assert json.loads(third)["error"] == (
            f"WebhookDestinationUnresolvedError: {REDACTED_MESSAGE}"
        )
        assert json.loads(third)["tenant_id"] is None
        assert [second.decode(), fourth.decode(), fifth.decode()] == others

        again = await redact_stored_webhook_url_errors(apply=True, config=jobs_config)
        assert (again.outbox_events, again.dead_letter_entries) == (0, 0)
    finally:
        await _drop(jobs_config)
