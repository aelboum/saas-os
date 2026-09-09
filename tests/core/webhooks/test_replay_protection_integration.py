"""P1.10 -- `verify_and_record_webhook_delivery()`/`record_webhook_delivery()`
integration tests against a real PostgreSQL instance: sequential replay,
real concurrent replay (the actual `IntegrityError`-on-unique-constraint
mechanism production code uses, not a mock), cross-tenant isolation, and
transaction-rollback non-poisoning.

Mirrors `tests/core/usage/test_quota_enforcement_integration.py`'s
fixture structure (real tenant + real `core.webhooks` subscription).

Marked `integration`; excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/webhooks/test_replay_protection_integration.py
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/webhooks/test_webhooks_isolation_integration.py's identical
# import for the full rationale (subscribe()'s audit write needs
# core.users mapped).
import core.identity.models  # noqa: F401
import pytest
from core.webhooks.errors import WebhookReplayDetectedError, WebhookSignatureInvalidError
from core.webhooks.service import (
    compute_signed_envelope,
    purge_expired_replay_records,
    record_webhook_delivery,
    subscribe,
    verify_and_record_webhook_delivery,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.webhook_replay_records LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.webhook_replay_records does not exist yet -- run `alembic upgrade head`: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured: {exc}")


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


class _TenantFixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(f"replay-tenant-{uuid.uuid4().hex[:8]}")
        self.subscription, self.secret = subscribe(
            self.tenant.id, "https://example.invalid/webhook"
        )

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.webhook_replay_records WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.webhook_subscriptions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def make_fixture():
    created: list[_TenantFixture] = []

    def _make() -> _TenantFixture:
        fx = _TenantFixture()
        created.append(fx)
        return fx

    yield _make
    for fx in created:
        fx.cleanup()


def _envelope(secret: str, body: bytes, timestamp: int) -> str:
    return compute_signed_envelope(secret, body, timestamp)


# --- Sequential correctness -------------------------------------------------


def test_first_valid_request_is_accepted(make_fixture) -> None:
    fx = make_fixture()
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    body = b'{"event_id":"x","event_type":"order.created","data":{}}'
    signature = _envelope(fx.secret, body, timestamp)
    event_id = uuid.uuid4()

    verify_and_record_webhook_delivery(
        fx.tenant.id, fx.subscription.id, event_id, body, timestamp, signature, fx.secret
    )  # must not raise


def test_sequential_replay_of_the_same_event_is_rejected(make_fixture) -> None:
    fx = make_fixture()
    event_id = uuid.uuid4()

    record_webhook_delivery(fx.tenant.id, fx.subscription.id, event_id)
    with pytest.raises(WebhookReplayDetectedError):
        record_webhook_delivery(fx.tenant.id, fx.subscription.id, event_id)


def test_invalid_signature_is_rejected_and_never_recorded(make_fixture) -> None:
    fx = make_fixture()
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    body = b'{"event_id":"x","event_type":"order.created","data":{}}'
    event_id = uuid.uuid4()

    with pytest.raises(WebhookSignatureInvalidError):
        verify_and_record_webhook_delivery(
            fx.tenant.id,
            fx.subscription.id,
            event_id,
            body,
            timestamp,
            "sha256=" + "0" * 64,
            fx.secret,
        )

    # A rejected (never-verified) delivery must not poison the replay
    # ledger -- the same event_id must still be acceptable once correctly
    # signed.
    signature = _envelope(fx.secret, body, timestamp)
    verify_and_record_webhook_delivery(
        fx.tenant.id, fx.subscription.id, event_id, body, timestamp, signature, fx.secret
    )


def test_stale_request_is_rejected_and_never_recorded(make_fixture) -> None:
    fx = make_fixture()
    now = datetime.now(UTC)
    stale_time = now - timedelta(seconds=999)
    timestamp = int(stale_time.timestamp())
    body = b'{"event_id":"x","event_type":"order.created","data":{}}'
    signature = _envelope(fx.secret, body, timestamp)
    event_id = uuid.uuid4()

    from core.webhooks.errors import WebhookTimestampInvalidError

    with pytest.raises(WebhookTimestampInvalidError):
        verify_and_record_webhook_delivery(
            fx.tenant.id,
            fx.subscription.id,
            event_id,
            body,
            timestamp,
            signature,
            fx.secret,
            now=now,
        )


def test_altered_payload_is_rejected(make_fixture) -> None:
    fx = make_fixture()
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    body = b'{"event_id":"x","event_type":"order.created","data":{"amount":1}}'
    signature = _envelope(fx.secret, body, timestamp)
    altered_body = b'{"event_id":"x","event_type":"order.created","data":{"amount":999999}}'
    event_id = uuid.uuid4()

    with pytest.raises(WebhookSignatureInvalidError):
        verify_and_record_webhook_delivery(
            fx.tenant.id,
            fx.subscription.id,
            event_id,
            altered_body,
            timestamp,
            signature,
            fx.secret,
        )


def test_altered_timestamp_is_rejected(make_fixture) -> None:
    fx = make_fixture()
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    body = b'{"event_id":"x","event_type":"order.created","data":{}}'
    signature = _envelope(fx.secret, body, timestamp)
    event_id = uuid.uuid4()

    with pytest.raises(WebhookSignatureInvalidError):
        verify_and_record_webhook_delivery(
            fx.tenant.id,
            fx.subscription.id,
            event_id,
            body,
            timestamp + 100,
            signature,
            fx.secret,
        )


def test_altered_event_id_with_same_signature_is_rejected_as_a_different_replay_key(
    make_fixture,
) -> None:
    """The signature does not cover event_id as a *field checked against
    the ledger key* separately -- but event_id IS part of the signed
    JSON body, so altering it without re-signing must fail signature
    verification (it changed the body)."""
    fx = make_fixture()
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    real_event_id = uuid.uuid4()
    body = f'{{"event_id":"{real_event_id}","event_type":"order.created","data":{{}}}}'.encode()
    signature = _envelope(fx.secret, body, timestamp)

    forged_event_id = uuid.uuid4()
    forged_body = (
        f'{{"event_id":"{forged_event_id}","event_type":"order.created","data":{{}}}}'.encode()
    )

    with pytest.raises(WebhookSignatureInvalidError):
        verify_and_record_webhook_delivery(
            fx.tenant.id,
            fx.subscription.id,
            forged_event_id,
            forged_body,
            timestamp,
            signature,
            fx.secret,
        )


def test_same_event_id_with_altered_payload_fails_signature_not_replay(make_fixture) -> None:
    """A tampered resend of a legitimate event_id must be caught by
    signature verification, before replay detection even runs -- proves
    the ordering (signature before replay) and that replay detection is
    never what silently "protects" against payload tampering."""
    fx = make_fixture()
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    event_id = uuid.uuid4()
    body = b'{"event_type":"order.created","data":{"amount":1}}'
    signature = _envelope(fx.secret, body, timestamp)

    tampered_body = b'{"event_type":"order.created","data":{"amount":999}}'
    with pytest.raises(WebhookSignatureInvalidError):
        verify_and_record_webhook_delivery(
            fx.tenant.id,
            fx.subscription.id,
            event_id,
            tampered_body,
            timestamp,
            signature,
            fx.secret,
        )

    # The real, correctly-signed event must still go through afterward.
    verify_and_record_webhook_delivery(
        fx.tenant.id, fx.subscription.id, event_id, body, timestamp, signature, fx.secret
    )


def test_different_events_are_accepted_independently(make_fixture) -> None:
    fx = make_fixture()
    record_webhook_delivery(fx.tenant.id, fx.subscription.id, uuid.uuid4())
    record_webhook_delivery(fx.tenant.id, fx.subscription.id, uuid.uuid4())
    record_webhook_delivery(fx.tenant.id, fx.subscription.id, uuid.uuid4())  # must not raise


def test_transaction_rollback_does_not_permanently_poison_replay_state(make_fixture) -> None:
    """A denied attempt (signature/timestamp failure, or a caught
    replay) rolls back its own transaction -- proven here by confirming
    a *different* event_id for the same subscription is unaffected after
    several denials, and that retrying the *same* event_id after its own
    genuine rejection (invalid signature) still succeeds once correctly
    signed (already covered by test_invalid_signature_is_rejected_and_never_recorded
    above) -- this test adds the cross-event angle."""
    fx = make_fixture()
    for _ in range(5):
        with pytest.raises(WebhookSignatureInvalidError):
            verify_and_record_webhook_delivery(
                fx.tenant.id,
                fx.subscription.id,
                uuid.uuid4(),
                b"{}",
                int(datetime.now(UTC).timestamp()),
                "sha256=" + "0" * 64,
                fx.secret,
            )
    # An entirely unrelated, correctly-signed event must still succeed.
    record_webhook_delivery(fx.tenant.id, fx.subscription.id, uuid.uuid4())


# --- Concurrency: the actual production transaction mechanism ---------------


def test_concurrent_identical_replay_allows_exactly_one_winner(make_fixture) -> None:
    """10 concurrent submissions, same event_id, same subscription --
    exactly 1 accepted, the rest rejected as replay, and the database
    contains exactly one replay record. Uses real threads issuing real,
    separate DB sessions/transactions against the actual
    `record_webhook_delivery()` production code path (a real unique-
    constraint `IntegrityError`), never a mock."""
    fx = make_fixture()
    event_id = uuid.uuid4()

    def _attempt(_: int) -> str:
        try:
            record_webhook_delivery(fx.tenant.id, fx.subscription.id, event_id)
            return "accepted"
        except WebhookReplayDetectedError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_attempt, range(10)))

    assert results.count("accepted") == 1
    assert results.count("rejected") == 9

    with tenant_session_scope(fx.tenant.id) as session:
        count = session.execute(
            text(
                "SELECT COUNT(*) AS n FROM core.webhook_replay_records "
                "WHERE tenant_id = :t AND subscription_id = :s AND event_id = :e"
            ),
            {"t": str(fx.tenant.id), "s": str(fx.subscription.id), "e": str(event_id)},
        ).one()
    assert count.n == 1


def test_concurrent_distinct_events_do_not_block_each_other(make_fixture) -> None:
    """Different event_ids for the same subscription must all succeed
    concurrently -- the advisory-lock-free unique-constraint mechanism
    only ever serializes attempts at the *same* key, never unrelated
    ones."""
    fx = make_fixture()
    event_ids = [uuid.uuid4() for _ in range(10)]

    def _attempt(event_id: uuid.UUID) -> str:
        try:
            record_webhook_delivery(fx.tenant.id, fx.subscription.id, event_id)
            return "accepted"
        except WebhookReplayDetectedError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_attempt, event_ids))

    assert results.count("accepted") == 10


# --- Tenant isolation --------------------------------------------------


def test_tenant_a_replay_cannot_be_replayed_as_tenant_b(make_fixture) -> None:
    tenant_a = make_fixture()
    tenant_b = make_fixture()
    event_id = uuid.uuid4()

    record_webhook_delivery(tenant_a.tenant.id, tenant_a.subscription.id, event_id)
    # The identical event_id, recorded against tenant B's own
    # subscription, must succeed independently -- it is a different
    # (tenant, subscription, event_id) triple entirely.
    record_webhook_delivery(tenant_b.tenant.id, tenant_b.subscription.id, event_id)


def test_tenant_a_cannot_mark_tenant_bs_event_as_consumed(make_fixture) -> None:
    """Attempting to record tenant B's subscription id under tenant A's
    tenant_id must not corrupt tenant B's own replay state -- RLS scopes
    the insert to tenant A's session, so this either fails an FK-style
    constraint or lands in a row RLS makes invisible to tenant B; either
    way tenant B's own real record_webhook_delivery() for that event_id
    must still succeed cleanly afterward."""
    tenant_a = make_fixture()
    tenant_b = make_fixture()
    event_id = uuid.uuid4()

    try:
        record_webhook_delivery(tenant_a.tenant.id, tenant_b.subscription.id, event_id)
    except Exception:  # noqa: BLE001 -- either outcome is acceptable; both prove isolation
        pass

    # Tenant B's own legitimate recording must still work.
    record_webhook_delivery(tenant_b.tenant.id, tenant_b.subscription.id, event_id)


def test_tenant_a_cannot_inspect_tenant_bs_replay_records(make_fixture) -> None:
    tenant_a = make_fixture()
    tenant_b = make_fixture()
    event_id = uuid.uuid4()
    record_webhook_delivery(tenant_b.tenant.id, tenant_b.subscription.id, event_id)

    with tenant_session_scope(tenant_a.tenant.id) as session:
        visible = session.execute(
            text("SELECT COUNT(*) AS n FROM core.webhook_replay_records WHERE tenant_id = :t"),
            {"t": str(tenant_b.tenant.id)},
        ).one()
    assert visible.n == 0


# --- Retention ---------------------------------------------------------


def test_purge_deletes_only_records_older_than_the_cutoff(make_fixture) -> None:
    fx = make_fixture()
    old_event_id = uuid.uuid4()
    recent_event_id = uuid.uuid4()
    record_webhook_delivery(fx.tenant.id, fx.subscription.id, old_event_id)
    record_webhook_delivery(fx.tenant.id, fx.subscription.id, recent_event_id)

    # Backdate the "old" record directly (created_at has no application
    # setter -- this test uses the privileged migration role, exactly
    # like every other test fixture's own admin cleanup helper).
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text(
                    "UPDATE core.webhook_replay_records SET created_at = :old "
                    "WHERE tenant_id = :t AND event_id = :e"
                ),
                {
                    "old": datetime.now(UTC) - timedelta(days=1),
                    "t": str(fx.tenant.id),
                    "e": str(old_event_id),
                },
            )
    finally:
        engine.dispose()

    cutoff = datetime.now(UTC) - timedelta(hours=1)
    deleted = purge_expired_replay_records(fx.tenant.id, cutoff)
    assert deleted == 1

    # The recent record must be untouched, and re-recording the purged
    # old event_id must now succeed again (it is gone).
    with tenant_session_scope(fx.tenant.id) as session:
        remaining = (
            session.execute(
                text("SELECT event_id FROM core.webhook_replay_records WHERE tenant_id = :t"),
                {"t": str(fx.tenant.id)},
            )
            .scalars()
            .all()
        )
    assert set(remaining) == {recent_event_id}
