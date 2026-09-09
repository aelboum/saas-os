"""`core/identity` user / external-identity / session lifecycle integration
tests against a real PostgreSQL instance with the Phase 3.2 tables actually
migrated (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 section 12 "Security
Test Matrix > External identity / Users / Sessions").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/tenancy/test_tenancy_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/identity/test_identity_integration.py

If PostgreSQL is not reachable, or `core.users` doesn't exist yet
(migration not applied), the test skips with a clear message rather than
failing with a raw traceback.
"""

from __future__ import annotations

import time
import uuid
from datetime import timedelta

import pytest
from core.identity.errors import (
    DuplicateExternalIdentityError,
    SessionExpiredError,
    SessionNotFoundError,
    SessionRevokedError,
)
from core.identity.service import (
    add_tenant_membership,
    create_user,
    find_external_identity,
    get_or_create_user_for_external_identity,
    get_user,
    link_external_identity,
    list_tenant_members,
)
from core.identity.sessions import issue_session, revoke_session, validate_session
from infra.db.config import get_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_identity_tables() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.users LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(f"core.users does not exist yet -- run `alembic upgrade head` first: {exc}")
    finally:
        probe_engine.dispose()


def _cleanup_user(user_id: uuid.UUID, *, tenant_ids: list[uuid.UUID] | None = None) -> None:
    # core.tenant_memberships is RLS-protected (docs/MULTI-TENANCY.md
    # section 2) -- a bare session_scope() (no tenant context) sees zero
    # rows there, so any membership row must be removed through
    # tenant_session_scope() for its own tenant, same as the real
    # application would, or the FK from tenant_memberships would silently
    # survive and block the users delete below.
    for tenant_id in tenant_ids or []:
        with tenant_session_scope(tenant_id) as session:
            session.execute(
                text(
                    "DELETE FROM core.tenant_memberships WHERE user_id = :id AND tenant_id = :tid"
                ),
                {"id": str(user_id), "tid": str(tenant_id)},
            )
    with session_scope() as session:
        session.execute(text("DELETE FROM core.sessions WHERE user_id = :id"), {"id": str(user_id)})
        session.execute(
            text("DELETE FROM core.external_identities WHERE user_id = :id"), {"id": str(user_id)}
        )
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_id)})


# --- Users -----------------------------------------------------------------


def test_create_user_persists_an_active_user() -> None:
    user = create_user()
    try:
        assert user.is_active is True
        fetched = get_user(user.id)
        assert fetched is not None
        assert fetched.id == user.id
    finally:
        _cleanup_user(user.id)


def test_get_user_returns_none_for_an_unknown_id() -> None:
    assert get_user(uuid.uuid4()) is None


# --- External identity: uniqueness / duplicate handling --------------------


def test_link_external_identity_then_find_it() -> None:
    user = create_user()
    issuer, subject = "https://idp.example.test", f"subject-{uuid.uuid4().hex[:8]}"
    try:
        link_external_identity(user.id, issuer, subject)
        found = find_external_identity(issuer, subject)
        assert found is not None
        assert found.user_id == user.id
    finally:
        _cleanup_user(user.id)


def test_duplicate_issuer_subject_is_rejected() -> None:
    user_a = create_user()
    user_b = create_user()
    issuer, subject = "https://idp.example.test", f"subject-{uuid.uuid4().hex[:8]}"
    try:
        link_external_identity(user_a.id, issuer, subject)
        with pytest.raises(DuplicateExternalIdentityError):
            link_external_identity(user_b.id, issuer, subject)
    finally:
        _cleanup_user(user_a.id)
        _cleanup_user(user_b.id)


def test_same_subject_under_different_issuers_are_distinct_identities() -> None:
    user = create_user()
    subject = f"subject-{uuid.uuid4().hex[:8]}"
    try:
        link_external_identity(user.id, "https://idp-one.example.test", subject)
        link_external_identity(user.id, "https://idp-two.example.test", subject)

        assert find_external_identity("https://idp-one.example.test", subject) is not None
        assert find_external_identity("https://idp-two.example.test", subject) is not None
    finally:
        _cleanup_user(user.id)


def test_get_or_create_user_for_external_identity_is_idempotent_on_second_login() -> None:
    issuer, subject = "https://idp.example.test", f"subject-{uuid.uuid4().hex[:8]}"
    first_login_user = get_or_create_user_for_external_identity(issuer, subject)
    try:
        second_login_user = get_or_create_user_for_external_identity(issuer, subject)
        assert second_login_user.id == first_login_user.id
    finally:
        _cleanup_user(first_login_user.id)


def test_get_or_create_user_for_external_identity_provisions_a_new_user_on_first_login() -> None:
    issuer, subject = "https://idp.example.test", f"subject-{uuid.uuid4().hex[:8]}"
    user = get_or_create_user_for_external_identity(issuer, subject)
    try:
        assert user.is_active is True
        assert find_external_identity(issuer, subject) is not None
    finally:
        _cleanup_user(user.id)


# --- Sessions ----------------------------------------------------------------


def test_issue_session_then_validate_it() -> None:
    user = create_user()
    try:
        record, raw_token = issue_session(user.id)
        assert record.user_id == user.id
        assert record.revoked_at is None

        validated = validate_session(raw_token)
        assert validated.id == record.id
    finally:
        _cleanup_user(user.id)


def test_session_token_hash_is_persisted_not_the_raw_token() -> None:
    user = create_user()
    try:
        record, raw_token = issue_session(user.id)
        with session_scope() as session:
            row = session.execute(
                text("SELECT token_hash FROM core.sessions WHERE id = :id"), {"id": str(record.id)}
            ).one()
        assert row.token_hash != raw_token
        assert raw_token not in row.token_hash
        assert len(row.token_hash) == 64  # sha256 hex digest length
    finally:
        _cleanup_user(user.id)


def test_validate_session_rejects_unknown_token() -> None:
    with pytest.raises(SessionNotFoundError):
        validate_session("a-token-that-was-never-issued")


def test_validate_session_rejects_revoked_session() -> None:
    user = create_user()
    try:
        record, raw_token = issue_session(user.id)
        revoke_session(record.id)
        with pytest.raises(SessionRevokedError):
            validate_session(raw_token)
    finally:
        _cleanup_user(user.id)


def test_validate_session_rejects_expired_session() -> None:
    user = create_user()
    try:
        _, raw_token = issue_session(user.id, lifetime=timedelta(milliseconds=1))
        time.sleep(0.05)
        with pytest.raises(SessionExpiredError):
            validate_session(raw_token)
    finally:
        _cleanup_user(user.id)


def test_revoke_session_is_idempotent() -> None:
    user = create_user()
    try:
        record, _ = issue_session(user.id)
        revoke_session(record.id)
        revoke_session(record.id)  # must not raise
    finally:
        _cleanup_user(user.id)


def test_revoke_unknown_session_raises() -> None:
    with pytest.raises(SessionNotFoundError):
        revoke_session(uuid.uuid4())


# --- Tenant membership ---------------------------------------------------


def test_add_and_list_tenant_membership() -> None:
    tenant = create_tenant(f"identity-phase32-{uuid.uuid4().hex[:8]}")
    user = create_user()
    try:
        add_tenant_membership(tenant.id, user.id)

        members = list_tenant_members(tenant.id)
        assert [m.user_id for m in members] == [user.id]
    finally:
        _cleanup_user(user.id, tenant_ids=[tenant.id])
        _cleanup_tenant(tenant.id)


def test_user_can_belong_to_more_than_one_tenant_simultaneously() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 acceptance criteria: "the
    user can belong to more than one tenant simultaneously." Proven via two
    separate tenant-scoped `list_tenant_members` calls -- there is no
    single cross-tenant "list my tenants" query (see `core/identity/service.py`'s
    module docstring: `core.tenant_memberships` is genuinely RLS-protected,
    so an untenanted query against it can only ever see zero rows, by
    design, not by omission).
    """
    tenant_a = create_tenant(f"identity-phase32-a-{uuid.uuid4().hex[:8]}")
    tenant_b = create_tenant(f"identity-phase32-b-{uuid.uuid4().hex[:8]}")
    user = create_user()
    try:
        add_tenant_membership(tenant_a.id, user.id)
        add_tenant_membership(tenant_b.id, user.id)

        assert [m.user_id for m in list_tenant_members(tenant_a.id)] == [user.id]
        assert [m.user_id for m in list_tenant_members(tenant_b.id)] == [user.id]
    finally:
        _cleanup_user(user.id, tenant_ids=[tenant_a.id, tenant_b.id])
        _cleanup_tenant(tenant_a.id)
        _cleanup_tenant(tenant_b.id)
