"""The opt-in AI usage router (ADR-0054 amendment of 2026-11-11; Gap 22b)
against real PostgreSQL and Redis, through the real ingress chain.

Pinned: the two routes exist only on an application that registers the
router; the denial matrix for both (no credential 401, an authenticated
non-member 404, a member without `ai.usage:read` 403 -- also one holding
`billing.subscription:read` --, another tenant's reader naming this tenant
404); a reader gets the report with money as decimal strings per currency
and the limits block, and each call writes one `ai.usage.read` row naming its
view; an invalid window or grouping is a 400 that echoes nothing; the
response is a closed set of fields with no prompt, decision, request id or
credential in it. Rows are seeded directly: no provider, no network.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import AIWorld
from saas_os.api.platform import build_platform_app
from saas_os.api.v1.ai_usage import router as ai_usage_router
from saas_os.core.identity.sessions import issue_session
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.ratelimit.config import get_ratelimit_config

pytestmark = pytest.mark.integration

USAGE = ("ai.usage", "read")
OCT = "2026-10-01T00:00:00+00:00"
NOV = "2026-11-01T00:00:00+00:00"
_SENTINELS = ("DECISION-SENTINEL", "REQUEST-ID-SENTINEL")


@pytest.fixture(autouse=True)
def _require_reachable_database_and_redis() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_ratelimit_config.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
        config = get_ratelimit_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database or Redis not configured: {exc}")
    probe = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.ai_usage_monthly LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    finally:
        probe.dispose()
    import redis as redis_sync

    try:
        redis_sync.Redis.from_url(config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}")


def _admin(sql: str, **params: object) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(text(sql), params)
    finally:
        engine.dispose()


@pytest.fixture
def world() -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        _admin("DELETE FROM core.sessions WHERE user_id = ANY(:u)", u=[str(u) for u in w.user_ids])
        w.cleanup()


@pytest.fixture(scope="module")
def app() -> FastAPI:
    application = build_platform_app(title="ai usage router", version="test")
    application.include_router(ai_usage_router)
    return application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:  # runs the lifespan: route policies, DB role guard
        yield test_client


def _token(user_id: uuid.UUID) -> dict[str, str]:
    _, token = issue_session(user_id)
    return {"Authorization": f"Bearer {token}"}


def _reader(world: AIWorld, tenant_id: uuid.UUID, *permissions: tuple[str, str]) -> dict[str, str]:
    return _token(world.member(tenant_id, *permissions).user_id)


def _insert(tenant_id: uuid.UUID, *, at: str, currency: str | None, cost: str | None) -> None:
    _admin(
        "INSERT INTO control_plane.ai_inference_attempts (id, tenant_id, request_id, "
        "attempt_number, actor_type, use_case, alias, provider_key, model_id, "
        "provider_config_version, model_config_version, effective_classification, decision, "
        "state, started_at, finished_at, input_tokens, output_tokens, "
        "usage_provenance, provider_request_id, estimated_cost, currency) VALUES (:i, :t, :r, 1, "
        "'service_account', 'uc', 'alias', 'p1', 'm1', 1, 1, 'tenant_data', CAST(:d AS json), "
        "'succeeded', CAST(:at AS timestamptz), CAST(:at AS timestamptz), 10, 5, "
        "'provider_reported', 'REQUEST-ID-SENTINEL', CAST(:cost AS numeric), :cur)",
        i=str(uuid.uuid4()),
        t=str(tenant_id),
        r=str(uuid.uuid4()),
        d=json.dumps({"sentinel": "DECISION-SENTINEL"}),
        at=at,
        cost=cost,
        cur=currency,
    )


def _audits(tenant_id: uuid.UUID) -> list[tuple[str, Any]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return [
                (row[0], row[1] if isinstance(row[1], dict) else json.loads(row[1] or "null"))
                for row in conn.execute(
                    text(
                        "SELECT outcome, metadata FROM core.audit_log WHERE tenant_id = :t "
                        "AND action = 'ai.usage.read' ORDER BY created_at"
                    ),
                    {"t": str(tenant_id)},
                )
            ]
    finally:
        engine.dispose()


_ROUTES = ("ai/usage", "ai/limits")


def test_the_routes_exist_only_where_the_router_is_registered(world: AIWorld) -> None:
    tenant_id = world.tenant()
    headers = _reader(world, tenant_id, USAGE)
    with TestClient(build_platform_app(title="bare", version="test")) as bare:
        for route in _ROUTES:
            response = bare.get(f"/v1/tenants/{tenant_id}/{route}", headers=headers)
            assert (response.status_code, response.json()) == (404, {"detail": "Not Found"})


@pytest.mark.parametrize("route", _ROUTES)
def test_the_denial_matrix(world: AIWorld, client: TestClient, route: str) -> None:
    tenant_id, other_id = world.tenant(), world.tenant()
    path = f"/v1/tenants/{tenant_id}/{route}"
    assert client.get(path).status_code == 401
    assert client.get(path, headers=_token(world.user())).status_code == 404  # not a member
    member = _reader(world, tenant_id)
    assert client.get(path, headers=member).status_code == 403
    billing = _reader(world, tenant_id, ("billing.subscription", "read"))
    assert client.get(path, headers=billing).status_code == 403  # not derived from billing
    foreign_reader = _reader(world, other_id, USAGE)
    assert client.get(path, headers=foreign_reader).status_code == 404
    assert _audits(tenant_id) == []  # refused at the route: Core was never reached
    assert client.get(path, headers=_reader(world, tenant_id, USAGE)).status_code == 200


def test_a_reader_gets_the_report_with_money_as_strings_and_one_audit_row(
    world: AIWorld, client: TestClient
) -> None:
    tenant_id = world.tenant()
    _insert(tenant_id, at="2026-10-05T10:00:00+00:00", currency="USD", cost="0.00100000")
    _insert(tenant_id, at="2026-10-06T10:00:00+00:00", currency="EUR", cost="0.25000000")
    _insert(tenant_id, at="2026-10-07T10:00:00+00:00", currency=None, cost=None)
    headers = _reader(world, tenant_id, USAGE)
    response = client.get(
        f"/v1/tenants/{tenant_id}/ai/usage",
        params={"since": OCT, "until": NOV, "group_by": "model"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {
        "tenant_id",
        "since",
        "until",
        "timezone",
        "group_by",
        "basis",
        "totals",
        "groups",
        "token_quota",
        "budget",
    }
    totals = body["totals"]
    assert totals["attempts"] == 3
    assert totals["estimated_cost"] == [
        {"currency": "EUR", "estimated": "0.25000000"},
        {"currency": "USD", "estimated": "0.00100000"},
    ]
    assert totals["cost_unknown_attempts"] == 1
    assert [g["key"] for g in body["groups"]] == ["p1/m1"]
    assert body["timezone"] == "UTC" and body["group_by"] == "model"
    assert body["budget"]["state"] == "unconfigured"
    assert body["budget"]["basis"] == "estimated_platform_spend"
    assert body["token_quota"]["basis"] == "soft_monthly_token_quota"
    for sentinel in _SENTINELS:
        assert sentinel not in response.text

    limits = client.get(f"/v1/tenants/{tenant_id}/ai/limits", headers=headers)
    assert limits.status_code == 200, limits.text
    assert set(limits.json()) == {"tenant_id", "token_quota", "budget"}
    assert _audits(tenant_id) == [
        ("success", {"view": "usage", "since": OCT, "until": NOV, "group_by": "model"}),
        ("success", {"view": "limits"}),
    ]


def test_an_invalid_window_or_grouping_is_a_400_that_echoes_nothing(
    world: AIWorld, client: TestClient
) -> None:
    tenant_id = world.tenant()
    headers = _reader(world, tenant_id, USAGE)
    for params in (
        {"since": OCT},
        {"since": OCT, "until": "2027-02-01T00:00:00+00:00"},  # more than 93 days
        {"since": "2026-10-01T00:00:00", "until": "2026-10-02T00:00:00"},  # naive
        {"group_by": "decision-SENTINEL"},
    ):
        response = client.get(f"/v1/tenants/{tenant_id}/ai/usage", params=params, headers=headers)
        assert response.status_code == 400, params
        assert "SENTINEL" not in response.text and "2027" not in response.text
    assert _audits(tenant_id) == []  # nothing read, nothing recorded as read


def test_the_window_is_reported_in_utc(world: AIWorld, client: TestClient) -> None:
    tenant_id = world.tenant()
    response = client.get(
        f"/v1/tenants/{tenant_id}/ai/usage",
        params={"since": "2026-10-01T02:00:00+02:00", "until": "2026-10-02T02:00:00+02:00"},
        headers=_reader(world, tenant_id, USAGE),
    )
    assert response.status_code == 200
    since = datetime.fromisoformat(response.json()["since"])
    assert since == datetime(2026, 10, 1, tzinfo=UTC) and since.utcoffset() is not None
