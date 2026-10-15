"""The failed-credential limit (`saas_os/api/dependencies.py`) against real
PostgreSQL and Redis, through the real ingress chain.

A presented credential -- a session token or an API key -- that has been
refused `RATE_LIMIT_REQUESTS_PER_WINDOW` times in the current window is
answered `429` before it is looked up: no further database lookup, and for
an API key no further `api_key.validate` audit row. Only refusals count, so
a valid credential is never limited by it, and a valid key presented to
another tenant (`404`) is not a refusal. The limit is keyed by a
fingerprint, never the secret. `peek_rate_limit()` reads without counting.

Marked `integration`.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Iterator
from typing import Annotated, Any, cast

import pytest
import redis as redis_sync
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

import saas_os.api.dependencies as deps
import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import PROVISIONING
from saas_os.api.auth.config import get_auth_http_config
from saas_os.api.context import RequestContext
from saas_os.api.dependencies import get_current_actor, require_permission
from saas_os.api.platform import build_platform_app
from saas_os.core.api_keys import create_api_key, revoke_api_key
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.identity.sessions import issue_session
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import TenantStatus, create_tenant, transition_tenant_status
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.ratelimit import RateLimitBackendError, check_rate_limit, peek_rate_limit
from saas_os.infra.ratelimit.config import get_ratelimit_config

pytestmark = pytest.mark.integration

_SYSTEM = SystemCaller(SystemAuthority.PROVISIONING)
_LIMIT = 3
_RESOURCE = "cfl_widget"


@pytest.fixture(autouse=True)
def _require_reachable_database_and_redis(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", str(_LIMIT))
    get_ratelimit_config.cache_clear()
    try:
        get_database_config()
        config = get_ratelimit_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database or Redis not configured: {exc}")
    probe = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.api_keys LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    finally:
        probe.dispose()
    try:
        redis_sync.Redis.from_url(config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable: {exc}")
    yield
    get_ratelimit_config.cache_clear()


def _admin(statement: str, **params: object) -> list[tuple[Any, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(statement), params)
            return [tuple(row) for row in result.all()] if result.returns_rows else []
    finally:
        engine.dispose()


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    def tenant(self) -> uuid.UUID:
        tenant = create_tenant(f"cfl-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        self.tenant_ids.append(tenant.id)
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE, caller=PROVISIONING)
        return tenant.id

    def member(self, tenant_id: uuid.UUID) -> uuid.UUID:
        user = create_user()
        self.user_ids.append(user.id)
        membership = add_tenant_membership(tenant_id, user.id, caller=_SYSTEM)
        role = create_role(tenant_id, f"cfl-{uuid.uuid4().hex[:6]}", caller=_SYSTEM)
        grant_permission(
            tenant_id, role.id, register_permission(_RESOURCE, "read").id, caller=_SYSTEM
        )
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=_SYSTEM)
        return user.id

    def cleanup(self) -> None:
        tenants = [str(t) for t in self.tenant_ids]
        users = [str(u) for u in self.user_ids]
        for statement in (
            "DELETE FROM core.audit_log WHERE tenant_id = ANY(:t) OR actor_user_id = ANY(:u)",
            "DELETE FROM core.api_keys WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.sessions WHERE user_id = ANY(:u)",
            "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) OR ancestor_id = ANY(:t)",
            "DELETE FROM core.platform_audit_log WHERE target_tenant_id = ANY(:t)",
            "DELETE FROM core.tenants WHERE id = ANY(:t)",
            "DELETE FROM core.users WHERE id = ANY(:u)",
        ):
            _admin(statement, t=tenants, u=users)


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


_router = APIRouter()


@_router.get("/cfl/whoami")
def _whoami(actor: Annotated[uuid.UUID, Depends(get_current_actor)]) -> dict[str, str]:
    return {"actor": str(actor)}


@_router.get("/v1/tenants/{tenant_id}/cfl-widgets")
def _widgets(
    context: Annotated[
        RequestContext, Depends(require_permission(_RESOURCE, "read", api_key=True))
    ],
) -> dict[str, str]:
    return {"actor": str(context.actor_id)}


@pytest.fixture
def client() -> Iterator[TestClient]:
    app: FastAPI = build_platform_app(title="credential failures", version="test")
    app.include_router(_router)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def lookups(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """How often each credential was actually looked up."""
    counts = {"session": 0, "api_key": 0}
    real_session, real_key = deps.validate_session, deps.validate_api_key

    def counted_session(raw: str):  # type: ignore[no-untyped-def]
        counts["session"] += 1
        return real_session(raw)

    def counted_key(raw: str):  # type: ignore[no-untyped-def]
        counts["api_key"] += 1
        return real_key(raw)

    monkeypatch.setattr(deps, "validate_session", counted_session)
    monkeypatch.setattr(deps, "validate_api_key", counted_key)
    return counts


def test_an_unknown_session_token_is_limited_before_lookup(
    client: TestClient, lookups: dict[str, int]
) -> None:
    headers = {"Authorization": f"Bearer {secrets.token_urlsafe(32)}"}
    answers = [client.get("/cfl/whoami", headers=headers).status_code for _ in range(_LIMIT + 2)]
    assert answers == [401] * _LIMIT + [429, 429]
    assert lookups["session"] == _LIMIT


def test_a_revoked_key_stops_writing_audit_rows(
    world: _World, client: TestClient, lookups: dict[str, int]
) -> None:
    tenant = world.tenant()
    user = world.member(tenant)
    key, raw = create_api_key(tenant, "cfl", caller=UserCaller(user))
    revoke_api_key(tenant, key.id, caller=UserCaller(user))
    path = f"/v1/tenants/{tenant}/cfl-widgets"

    answers = [client.get(path, headers={"X-API-Key": raw}).status_code for _ in range(_LIMIT + 2)]

    assert answers == [401] * _LIMIT + [429, 429]
    assert lookups["api_key"] == _LIMIT
    refusals = _admin(
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t AND action = 'api_key.validate'",
        t=str(tenant),
    )
    assert refusals == [(_LIMIT,)]


def test_a_valid_session_is_never_limited_by_it(world: _World, client: TestClient) -> None:
    tenant = world.tenant()
    user = world.member(tenant)
    headers = {"Authorization": f"Bearer {issue_session(user)[1]}"}
    answers = [client.get("/cfl/whoami", headers=headers).status_code for _ in range(_LIMIT + 2)]
    assert answers == [200] * (_LIMIT + 2)


def test_a_valid_key_for_another_tenant_is_not_a_failed_credential(
    world: _World, client: TestClient
) -> None:
    home, other = world.tenant(), world.tenant()
    user = world.member(home)
    _, raw = create_api_key(home, "cfl", caller=UserCaller(user))
    elsewhere = [
        client.get(f"/v1/tenants/{other}/cfl-widgets", headers={"X-API-Key": raw}).status_code
        for _ in range(_LIMIT + 1)
    ]
    assert elsewhere == [404] * (_LIMIT + 1)
    home_answer = client.get(f"/v1/tenants/{home}/cfl-widgets", headers={"X-API-Key": raw})
    assert home_answer.status_code == 200


def test_one_credential_failing_does_not_limit_another(client: TestClient) -> None:
    failing = {"Authorization": f"Bearer {secrets.token_urlsafe(32)}"}
    for _ in range(_LIMIT):
        client.get("/cfl/whoami", headers=failing)
    assert client.get("/cfl/whoami", headers=failing).status_code == 429
    other = {"Authorization": f"Bearer {secrets.token_urlsafe(32)}"}
    assert client.get("/cfl/whoami", headers=other).status_code == 401


def test_the_limit_is_keyed_by_a_fingerprint_never_the_secret(client: TestClient) -> None:
    token = secrets.token_urlsafe(32)
    client.get("/cfl/whoami", headers={"Authorization": f"Bearer {token}"})
    config = get_ratelimit_config()
    raw_keys = cast("list[bytes]", redis_sync.Redis.from_url(config.redis_url).keys("*"))
    keys = [k.decode() for k in raw_keys]
    assert keys, "the refusal must have been counted"
    assert not any(token in k for k in keys)
    assert any(k.endswith(deps._credential_failure_key(token)) for k in keys)


def test_the_check_fails_open_when_redis_cannot_be_read(
    world: _World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Authentication never depends on Redis: with the check unavailable a
    valid session still passes and a bad one is still the plain 401."""

    async def unavailable(key: str, **_: object) -> None:
        raise RateLimitBackendError(key)

    monkeypatch.setattr(deps, "peek_rate_limit", unavailable)
    tenant = world.tenant()
    user = world.member(tenant)
    valid = {"Authorization": f"Bearer {issue_session(user)[1]}"}
    bad = {"Authorization": f"Bearer {secrets.token_urlsafe(32)}"}
    assert client.get("/cfl/whoami", headers=valid).status_code == 200
    assert client.get("/cfl/whoami", headers=bad).status_code == 401


def test_a_counting_failure_leaves_the_refusal_as_it_is(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unavailable(key: str, **_: object) -> None:
        raise RateLimitBackendError(key)

    monkeypatch.setattr(deps, "check_rate_limit", unavailable)
    bad = {"Authorization": f"Bearer {secrets.token_urlsafe(32)}"}
    assert client.get("/cfl/whoami", headers=bad).status_code == 401


def test_a_refused_cookie_session_is_counted_too(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, lookups: dict[str, int]
) -> None:
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://testserver/auth/callback")
    get_auth_http_config.cache_clear()
    try:
        client.cookies.set("saas_os_session", secrets.token_urlsafe(32))
        answers = [client.get("/cfl/whoami").status_code for _ in range(_LIMIT + 1)]
    finally:
        client.cookies.clear()
        get_auth_http_config.cache_clear()
    assert answers == [401] * _LIMIT + [429]
    assert lookups["session"] == _LIMIT


def test_a_429_does_not_extend_the_window(client: TestClient) -> None:
    token = secrets.token_urlsafe(32)
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(_LIMIT + 3):
        client.get("/cfl/whoami", headers=headers)
    config = get_ratelimit_config()
    stored = redis_sync.Redis.from_url(config.redis_url).get(
        f"{config.key_prefix}:{deps._credential_failure_key(token)}"
    )
    assert int(cast("bytes", stored)) == _LIMIT


@pytest.mark.parametrize("value", ["", "   ", "k" * 257])
def test_an_unusable_key_is_refused_without_lookup_or_counter(
    world: _World, client: TestClient, lookups: dict[str, int], value: str
) -> None:
    tenant = world.tenant()
    response = client.get(f"/v1/tenants/{tenant}/cfl-widgets", headers={"X-API-Key": value})
    assert response.status_code == 401
    assert lookups["api_key"] == 0
    config = get_ratelimit_config()
    stored = redis_sync.Redis.from_url(config.redis_url).get(
        f"{config.key_prefix}:{deps._credential_failure_key(value.strip())}"
    )
    assert stored is None


@pytest.mark.anyio
async def test_peek_reads_without_counting() -> None:
    config = get_ratelimit_config()
    key = f"cfl-peek:{uuid.uuid4().hex}"
    first = await peek_rate_limit(key, config=config)
    again = await peek_rate_limit(key, config=config)
    assert (first.allowed, first.remaining) == (again.allowed, again.remaining) == (True, _LIMIT)
    for _ in range(_LIMIT):
        await check_rate_limit(key, config=config)
    assert (await peek_rate_limit(key, config=config)).allowed is False


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
