"""PRIV-03 Phase P12 -- the reference consumer's widget route runs through
SaaS OS's own ingress chain (privacy re-audit finding RA-08), against a
real, disposable PostgreSQL instance and a real Redis.

The audit showed `GET /widgets/{tenant_id}/{widget_id}` serving tenant
content with no authentication, no membership or permission check, no
lifecycle fence, no rate limit and no audit -- the URL's `tenant_id` was
used directly as the RLS session context, so the widget of a SUSPENDED,
DELETED, PURGING or even PURGED tenant was returned to anyone holding the
two UUIDs. The route now declares `api.dependencies.require_permission()`
and reads only the verified `RequestContext.tenant_id`; these tests pin
every leg of that contract, plus a local guard that the fixture package
imports nothing from `sqlalchemy` directly (finding 3).

Like `test_reference_consumer_scenarios_integration.py`, this imports the
fixture from the working tree (the `sys.path` insertion is a test-harness
convenience); the packaging-boundary proof stays in
`test_reference_consumer_integration.py`.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/test_reference_consumer_route_security_integration.py
"""

from __future__ import annotations

import sys
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_CONSUMER_ROOT = _REPO_ROOT / "examples" / "reference-consumer"
# The fixture's tool module imports `control_plane`; from a test module at
# the `tests/` root, pytest puts `tests/` first on `sys.path`, where the
# `tests/control_plane/` *test* directory would otherwise be picked up as
# a namespace package ahead of the installed one. Put the real package
# first -- a test-harness convenience local to this file, like the fixture
# root insertion below.
for _root in (_REPO_ROOT / "control-plane", _REFERENCE_CONSUMER_ROOT):
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from api.middleware import CORRELATION_ID_HEADER  # noqa: E402
from core.audit_log.service import list as list_audit_entries  # noqa: E402
from core.identity.service import add_tenant_membership, create_user  # noqa: E402
from core.identity.sessions import issue_session  # noqa: E402
from core.rbac.service import (  # noqa: E402
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from fastapi.testclient import TestClient  # noqa: E402
from infra.db.config import get_database_config, get_migrations_database_config  # noqa: E402
from infra.db.engine import build_engine, get_engine  # noqa: E402
from infra.db.session import (  # noqa: E402
    build_session_factory,
    session_scope,
    tenant_session_scope,
)
from infra.ratelimit.config import get_ratelimit_config  # noqa: E402
from reference_consumer.app import create_app  # noqa: E402
from reference_consumer.tools import ACTION, RESOURCE  # noqa: E402
from sqlalchemy import text  # noqa: E402

import core.rbac  # noqa: F401,E402 -- registers the mappers core.audit_log references by name
from core.tenancy import (  # noqa: E402
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_INACCESSIBLE = [
    TenantStatus.SUSPENDED,
    TenantStatus.DELETED,
    TenantStatus.PURGING,
    TenantStatus.PURGED,
]


@pytest.fixture(autouse=True)
def _require_reachable_database_and_redis() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_ratelimit_config.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.membership_roles LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.membership_roles not reachable: {exc}")
    finally:
        probe_engine.dispose()
    try:
        config = get_ratelimit_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    import redis as redis_sync

    try:
        redis_sync.Redis.from_url(config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}")


@pytest.fixture(scope="module", autouse=True)
def _consumer_schema() -> None:
    """The fixture's own migrations (ADR-0016), idempotent against a
    database where they already ran."""
    cfg = Config()
    cfg.set_main_option(
        "script_location", str(_REFERENCE_CONSUMER_ROOT / "reference_consumer" / "migrations")
    )
    command.upgrade(cfg, "head")


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


@dataclass
class Rig:
    tenant_id: uuid.UUID
    widget_id: uuid.UUID
    reader_token: str  # member holding reference_consumer.widgets:read
    reader_id: uuid.UUID
    member_token: str  # member with no role at all
    member_id: uuid.UUID
    outsider_token: str  # authenticated user, not a member of this tenant
    outsider_id: uuid.UUID


def _insert_widget(tenant_id: uuid.UUID, name: str) -> uuid.UUID:
    widget_id = uuid.uuid4()
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text(
                "INSERT INTO reference_consumer.widgets (id, tenant_id, name, status) "
                "VALUES (:id, :t, :n, 'active')"
            ),
            {"id": str(widget_id), "t": str(tenant_id), "n": name},
        )
    return widget_id


def _build_rig() -> Rig:
    tenant = create_tenant(f"priv03-p12-{uuid.uuid4().hex[:8]}")
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    reader, member, outsider = create_user(), create_user(), create_user()
    reader_membership = add_tenant_membership(tenant.id, reader.id)
    add_tenant_membership(tenant.id, member.id)
    role = create_role(tenant.id, "widget-reader")
    permission = register_permission(RESOURCE, ACTION)
    grant_permission(tenant.id, role.id, permission.id)
    assign_first_role_for_new_tenant(tenant.id, reader_membership.id, role.id)
    widget_id = _insert_widget(tenant.id, "private widget")
    _, reader_token = issue_session(reader.id)
    _, member_token = issue_session(member.id)
    _, outsider_token = issue_session(outsider.id)
    return Rig(
        tenant_id=tenant.id,
        widget_id=widget_id,
        reader_token=reader_token,
        reader_id=reader.id,
        member_token=member_token,
        member_id=member.id,
        outsider_token=outsider_token,
        outsider_id=outsider.id,
    )


def _teardown(rigs: list[Rig]) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            for rig in rigs:
                for table in (
                    "reference_consumer.widgets",
                    "core.audit_log",
                    "core.membership_roles",
                    "core.role_permissions",
                    "core.roles",
                    "core.tenant_memberships",
                    "core.tenant_ancestry",
                ):
                    session.execute(
                        text(f"DELETE FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
                        {"t": str(rig.tenant_id)},
                    )
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)}
                )
                for user_id in (rig.reader_id, rig.member_id, rig.outsider_id):
                    session.execute(
                        text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(user_id)}
                    )
                    session.execute(
                        text("DELETE FROM core.users WHERE id = :u"), {"u": str(user_id)}
                    )
    finally:
        engine.dispose()


@pytest.fixture
def rig() -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown([built])


@pytest.fixture
def other() -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown([built])


def _get(client: TestClient, tenant_id: uuid.UUID, widget_id: uuid.UUID, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get(f"/widgets/{tenant_id}/{widget_id}", headers=headers)


def _close(tenant_id: uuid.UUID, status: TenantStatus) -> None:
    if status is TenantStatus.SUSPENDED:
        transition_tenant_status(tenant_id, TenantStatus.SUSPENDED)
        return
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    if status is TenantStatus.PURGING:
        transition_tenant_status(tenant_id, TenantStatus.PURGING)
    elif status is TenantStatus.PURGED:
        purge_tenant(tenant_id)


# --- 1-5: authentication, membership, permission, the allowed path -------------


def test_unauthenticated_request_is_rejected_before_any_tenant_context(
    client: TestClient, rig: Rig
) -> None:
    response = _get(client, rig.tenant_id, rig.widget_id, None)
    assert response.status_code == 401
    assert "private widget" not in response.text


def test_authenticated_non_member_gets_the_non_enumerating_404(
    client: TestClient, rig: Rig
) -> None:
    response = _get(client, rig.tenant_id, rig.widget_id, rig.outsider_token)
    assert response.status_code == 404
    assert "private widget" not in response.text
    assert list_audit_entries(rig.tenant_id, resource_type="http_route") == []


def test_member_without_the_permission_is_denied_and_the_denial_is_audited(
    client: TestClient, rig: Rig
) -> None:
    response = _get(client, rig.tenant_id, rig.widget_id, rig.member_token)
    assert response.status_code == 403
    assert "private widget" not in response.text
    denials = list_audit_entries(rig.tenant_id, resource_type="http_route")
    assert len(denials) == 1
    assert denials[0].action == "api.access_denied"
    assert denials[0].outcome == "denied"
    assert denials[0].actor_user_id == rig.member_id
    assert denials[0].resource_id == f"{RESOURCE}:{ACTION}"
    assert denials[0].correlation_id == response.headers[CORRELATION_ID_HEADER]


def test_active_tenant_member_with_the_permission_reads_its_widget(
    client: TestClient, rig: Rig
) -> None:
    response = _get(client, rig.tenant_id, rig.widget_id, rig.reader_token)
    assert response.status_code == 200
    assert response.json() == {
        "id": str(rig.widget_id),
        "name": "private widget",
        "status": "active",
    }
    assert list_audit_entries(rig.tenant_id, resource_type="http_route") == []


# --- 6-9: lifecycle -- the RA-04 policy applies to the consumer route too ------


@pytest.mark.parametrize("status", _INACCESSIBLE)
def test_inaccessible_tenant_hides_its_widget_from_its_own_permitted_member(
    status: TenantStatus, client: TestClient, rig: Rig
) -> None:
    assert _get(client, rig.tenant_id, rig.widget_id, rig.reader_token).status_code == 200
    _close(rig.tenant_id, status)
    assert get_tenant(rig.tenant_id).status == status.value
    response = _get(client, rig.tenant_id, rig.widget_id, rig.reader_token)
    assert response.status_code == 404
    assert "private widget" not in response.text


# --- 10-11: foreign and nonexistent references, non-enumeration -----------------


def test_foreign_tenant_widget_is_not_reachable_through_a_valid_context(
    client: TestClient, rig: Rig, other: Rig
) -> None:
    # A permitted member of `rig` asks for `other`'s widget under its own
    # tenant context: RLS + the ownership check yield the same 404 as a
    # widget that does not exist at all.
    foreign = _get(client, rig.tenant_id, other.widget_id, rig.reader_token)
    assert foreign.status_code == 404
    assert "private widget" not in foreign.text
    # ...and naming `other`'s tenant in the URL does not switch context:
    # the caller is not a member there, so tenant resolution itself 404s.
    hijack = _get(client, other.tenant_id, other.widget_id, rig.reader_token)
    assert hijack.status_code == 404
    assert "private widget" not in hijack.text


def test_nonexistent_foreign_and_closed_references_are_indistinguishable(
    client: TestClient, rig: Rig, other: Rig
) -> None:
    missing = _get(client, rig.tenant_id, uuid.uuid4(), rig.reader_token)
    foreign = _get(client, rig.tenant_id, other.widget_id, rig.reader_token)
    _close(other.tenant_id, TenantStatus.DELETED)
    closed_other = _get(client, other.tenant_id, other.widget_id, rig.reader_token)
    no_tenant = _get(client, uuid.uuid4(), rig.widget_id, rig.reader_token)
    assert missing.status_code == foreign.status_code == 404
    assert closed_other.status_code == no_tenant.status_code == 404
    # Within the caller's own, verified tenant context "no such widget" and
    # "another tenant's widget" are the same response (`not_found("widget")`
    # from the route); naming another tenant -- live or closed -- or a
    # tenant that does not exist is the same response as well
    # (`not_found("tenant")` from the ingress chain, before any widget is
    # looked up). Neither response carries anything about the widget.
    assert missing.json() == foreign.json()
    assert closed_other.json() == no_tenant.json()
    for response in (missing, foreign, closed_other, no_tenant):
        assert "private widget" not in response.text
        assert str(other.widget_id) not in response.text


# --- 12: the route sits behind the per-tenant rate limiter ----------------------


def test_route_participates_in_the_ingress_rate_limit(
    client: TestClient, rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "2")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    get_ratelimit_config.cache_clear()
    try:
        assert _get(client, rig.tenant_id, rig.widget_id, rig.reader_token).status_code == 200
        assert _get(client, rig.tenant_id, rig.widget_id, rig.reader_token).status_code == 200
        third = _get(client, rig.tenant_id, rig.widget_id, rig.reader_token)
        assert third.status_code == 429
        assert "Retry-After" in third.headers
    finally:
        get_ratelimit_config.cache_clear()


# --- finding 3: the fixture never imports sqlalchemy directly -------------------


def test_reference_consumer_package_imports_nothing_from_sqlalchemy_directly() -> None:
    """A local guard for the fixture only (the repository-wide import-linter
    contract does not cover `examples/`): every data access goes through
    the installed package's `infra.db` boundary, as a real consumer's
    should. The fixture's own Alembic migration is the one place that may
    -- and must -- talk to SQLAlchemy/Alembic directly."""
    package = _REFERENCE_CONSUMER_ROOT / "reference_consumer"
    offenders = [
        path.relative_to(_REFERENCE_CONSUMER_ROOT)
        for path in package.glob("*.py")
        if any(
            line.strip().startswith(("import sqlalchemy", "from sqlalchemy"))
            for line in path.read_text(encoding="utf-8").splitlines()
        )
    ]
    assert offenders == [], offenders
