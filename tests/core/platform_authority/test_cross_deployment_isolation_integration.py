"""Platform authority is installation-scoped: two deployments, two
databases, nothing shared
(docs/ADR/0045-installation-scoped-platform-authority.md section 2 and
Phase F).

A second, empty database is created on the same PostgreSQL server and
migrated to head: a second deployment. The process is pointed at one
database or the other by its environment, exactly as two deployments
are. What is shown:

- an operator enrolled in the first deployment has no authority in the
  second, and a user who authenticates in the second without being an
  operator there gets the 404 of an unknown path;
- a session issued by the first does not authenticate in the second;
- the same `(issuer, subject)` logging in to the second is an ordinary
  user there, and the second deployment's own bootstrap is unaffected by
  the first's.

Marked `integration`. Disposable databases only; the second database is
dropped afterwards.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from phase_c_helpers import REASON, P, Scene
from platform_helpers import BOOTSTRAP, PlatformWorld
from sqlalchemy import text
from sqlalchemy.engine import make_url

from saas_os.api.platform import build_platform_app
from saas_os.api.platform_admin import build_platform_admin_router, get_platform_admin_http_config
from saas_os.core.authority import UserCaller
from saas_os.core.identity import create_user
from saas_os.core.identity.errors import SessionNotFoundError
from saas_os.core.identity.service import get_or_create_user_for_external_identity
from saas_os.core.identity.sessions import issue_session, validate_session
from saas_os.core.platform_authority import (
    OperatorIdentity,
    PlatformNotAuthorizedError,
    bootstrap_platform_owner,
    is_active_platform_operator,
    platform_can,
)
from saas_os.core.tenancy import list_tenant_registry
from saas_os.infra.db import get_engine, get_session_factory, run_core_migrations
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine
from saas_os.infra.ratelimit.config import get_ratelimit_config

pytestmark = pytest.mark.integration

_ISSUER = "https://issuer.cross-deployment.test"


@dataclass(frozen=True)
class Deployment:
    """One deployment: the two database URLs its processes are given."""

    name: str
    database_url: str
    migrations_database_url: str


def _reset_database_caches() -> None:
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    for cached in (
        get_database_config,
        get_migrations_database_config,
        get_engine,
        get_session_factory,
    ):
        cached.cache_clear()


@contextmanager
def acting_in(monkeypatch: pytest.MonkeyPatch, deployment: Deployment) -> Iterator[None]:
    """Run the block as a process of `deployment`: its environment names
    that deployment's database, and nothing else distinguishes it."""
    previous = (get_database_config().url, get_migrations_database_config().url)
    monkeypatch.setenv("DATABASE_URL", deployment.database_url)
    monkeypatch.setenv("MIGRATIONS_DATABASE_URL", deployment.migrations_database_url)
    _reset_database_caches()
    try:
        yield
    finally:
        monkeypatch.setenv("DATABASE_URL", previous[0])
        monkeypatch.setenv("MIGRATIONS_DATABASE_URL", previous[1])
        _reset_database_caches()


@pytest.fixture
def deployments(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[Deployment, Deployment]]:
    """The configured database as the first deployment, and a second one
    created, migrated and finally dropped here."""
    app_url, admin_url = get_database_config().url, get_migrations_database_config().url
    first = Deployment("first", app_url, admin_url)
    database = f"second_deployment_{uuid.uuid4().hex[:12]}"

    def in_second(url: str) -> str:
        return make_url(url).set(database=database).render_as_string(hide_password=False)

    def admin_statement(statement: str) -> None:
        engine = build_engine(get_migrations_database_config())
        try:
            with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                connection.execute(text(statement))
        finally:
            engine.dispose()

    admin_statement(f'CREATE DATABASE "{database}"')
    second = Deployment("second", in_second(app_url), in_second(admin_url))
    try:
        with acting_in(monkeypatch, second):
            run_core_migrations()
        yield first, second
    finally:
        _reset_database_caches()
        admin_statement(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')


def _count(table: str) -> int:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as connection:
            return connection.execute(text(f"SELECT count(*) FROM core.{table}")).scalar_one()  # noqa: S608 -- fixed names
    finally:
        engine.dispose()


def test_an_operator_of_one_deployment_has_no_authority_in_another(
    scene: Scene,
    platform: PlatformWorld,
    deployments: tuple[Deployment, Deployment],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = deployments
    owner, _ = platform.owner()  # every permission, in the first deployment
    scene.tenant(active=True)

    with acting_in(monkeypatch, first):
        assert all(platform_can(user_id=owner.user_id, permission=p) for p in P)
        assert is_active_platform_operator(user_id=owner.user_id)
        assert list_tenant_registry(caller=owner, limit=1).tenants

    with acting_in(monkeypatch, second):
        # The second deployment has its own tables, and they are empty.
        assert _count("platform_operators") == _count("platform_grants") == 0
        assert _count("users") == 0
        assert not any(platform_can(user_id=owner.user_id, permission=p) for p in P)
        assert not is_active_platform_operator(user_id=owner.user_id)
        with pytest.raises(PlatformNotAuthorizedError):
            list_tenant_registry(caller=owner, limit=1)
        # Nothing was created there by being refused: no operator, no user,
        # and no audit row (the caller is not a user of this deployment).
        assert _count("platform_operators") == 0 and _count("users") == 0
        assert _count("platform_audit_log") == 0


def test_a_session_of_one_deployment_does_not_authenticate_in_another(
    platform: PlatformWorld,
    deployments: tuple[Deployment, Deployment],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = deployments
    owner, _ = platform.owner()
    monkeypatch.setenv("PLATFORM_ADMIN_HTTP_ENABLED", "true")
    get_platform_admin_http_config.cache_clear()
    get_ratelimit_config.cache_clear()
    app = build_platform_app(title="cross-deployment", version="test")
    app.include_router(build_platform_admin_router())
    client = TestClient(app)
    try:
        with acting_in(monkeypatch, first):
            _, raw = issue_session(owner.user_id)
            headers = {"Authorization": f"Bearer {raw}"}
            assert validate_session(raw).user_id == owner.user_id
            assert client.get("/v1/platform/operators", headers=headers).status_code == 200

        with acting_in(monkeypatch, second):
            with pytest.raises(SessionNotFoundError):
                validate_session(raw)
            # The same bearer token, the same route, the other deployment.
            assert client.get("/v1/platform/operators", headers=headers).status_code == 401
            assert _count("sessions") == 0
            # Someone who does authenticate there, and is no operator there:
            # the 404 of an unknown path, and no evidence written about them.
            _, local = issue_session(create_user().id)
            answer = client.get(
                "/v1/platform/operators", headers={"Authorization": f"Bearer {local}"}
            )
            assert (answer.status_code, answer.json()) == (404, {"detail": "Not Found"})
            assert _count("platform_audit_log") == 0
    finally:
        client.close()
        get_platform_admin_http_config.cache_clear()
        get_ratelimit_config.cache_clear()


def test_the_same_identity_is_an_ordinary_user_in_another_deployment(
    platform: PlatformWorld,
    deployments: tuple[Deployment, Deployment],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One person, one `(issuer, subject)`, two deployments. Being the
    owner of the first gives nothing in the second -- and the second's own
    bootstrap is still open, to whoever that deployment chooses."""
    first, second = deployments
    subject = f"owner-{uuid.uuid4().hex}"
    identity = OperatorIdentity(issuer=_ISSUER, subject=subject)

    with acting_in(monkeypatch, first):
        bootstrapped = bootstrap_platform_owner(
            identity, [P.AUTHORITY_MANAGE, P.TENANT_READ], caller=BOOTSTRAP, reason=REASON
        )
        platform.users.append(bootstrapped.user_id)
        assert platform_can(user_id=bootstrapped.user_id, permission=P.AUTHORITY_MANAGE)

    try:
        with acting_in(monkeypatch, second):
            # The login resolution of the second deployment: a new user.
            there = get_or_create_user_for_external_identity(_ISSUER, subject).id
            assert not is_active_platform_operator(user_id=there)
            assert not any(platform_can(user_id=there, permission=p) for p in P)
            with pytest.raises(PlatformNotAuthorizedError):
                list_tenant_registry(caller=UserCaller(there), limit=1)
            # Nor does the first deployment's user id mean anything here.
            assert not is_active_platform_operator(user_id=bootstrapped.user_id)
            assert _count("platform_operators") == 0

            # The second deployment bootstraps its own owner: someone else.
            other = bootstrap_platform_owner(
                OperatorIdentity(issuer=_ISSUER, subject=f"other-{uuid.uuid4().hex}"),
                [P.AUTHORITY_MANAGE],
                caller=BOOTSTRAP,
                reason=REASON,
            )
            assert other.created and other.user_id != there
            assert platform_can(user_id=other.user_id, permission=P.AUTHORITY_MANAGE)
            assert not platform_can(user_id=there, permission=P.AUTHORITY_MANAGE)

        with acting_in(monkeypatch, first):
            # And the second deployment's owner is nobody in the first.
            assert not is_active_platform_operator(user_id=other.user_id)
            assert platform_can(user_id=bootstrapped.user_id, permission=P.AUTHORITY_MANAGE)
    finally:
        platform.execute("DELETE FROM core.external_identities WHERE issuer = :i", {"i": _ISSUER})
