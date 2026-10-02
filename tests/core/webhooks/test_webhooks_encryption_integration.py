"""F-02 (Platform Safety/Security/Privacy/General Readiness Audit):
`core.webhook_subscriptions.signing_secret` is now stored as a
`core.crypto.EncryptionService` ciphertext envelope, not plaintext.

Complements the existing end-to-end proof that signing itself still works
through this new encrypted-at-rest path --
`tests/core/webhooks/test_webhooks_delivery_integration.py::
test_delivery_sends_a_correctly_signed_event_to_the_mock_endpoint`
already exercises `subscribe()` (encrypt) -> a real worker ->
`_deliver_webhook()` (decrypt) -> a real HTTP POST, and asserts the
received signature matches `compute_signed_envelope(raw_secret, ...)` --
this file does not duplicate that, it proves the properties specific to
F-02 itself: what is actually persisted, that plaintext never comes back
out of the read paths, that decryption failure fails closed, and that a
pre-F-02 legacy plaintext row keeps working unmodified.

Marked `integration` and excluded from the default `pytest` run -- same
posture and fixture shape as `test_webhooks_integration.py`, Postgres
only (no Redis/worker needed, since these tests exercise the
encrypt/decrypt/persistence boundary directly, not a queued delivery).

How to run this test locally: same `docker compose up -d db` / `alembic
upgrade head` / `DATABASE_URL`/`MIGRATIONS_DATABASE_URL` placeholder dev
credentials as `tests/core/webhooks/test_webhooks_integration.py`'s own
module docstring (see that file for the exact values), then:

    pytest -m integration tests/core/webhooks/test_webhooks_encryption_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.authority import SystemAuthority, SystemCaller
from core.webhooks.models import WebhookSubscription
from core.webhooks.service import get_subscription, list_subscriptions, subscribe
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

# RA-11-F6: registers the RBAC/support-access/delegation mappers
# core.audit_log's model references by name before SQLAlchemy configures
# its mappers -- so this module passes standalone instead of depending on
# some earlier-collected test having imported core.rbac first (same
# precedent as tests/infra/db/test_backup_restore_drill_integration.py).
import core.rbac  # noqa: F401
from core.crypto import DecryptionAuthenticationError
from core.tenancy import create_tenant
from core.webhooks import service as webhooks_service

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from infra.db.config import get_migrations_database_config
    from infra.db.engine import build_engine
    from infra.db.session import build_session_factory, session_scope
    from sqlalchemy import text

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
    finally:
        engine.dispose()


_ENVELOPE_PREFIX = webhooks_service._SIGNING_SECRET_ENVELOPE_PREFIX

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_webhooks_table() -> None:
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
            conn.execute(text("SELECT 1 FROM core.webhook_subscriptions LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.webhook_subscriptions does not exist yet -- "
            f"run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    # core.audit_log DELETE is REVOKEd from the restricted runtime role
    # (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4) -- subscribe()'s own
    # audit write means teardown must use the privileged migrations role
    # here, mirroring test_webhooks_integration.py's identical helper.
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(f"webhooks-crypto-tenant-{uuid.uuid4().hex[:8]}")

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.webhook_subscriptions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            _admin_clear_audit_references({"id": str(self.tenant.id)}, table="tenants")
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


def _raw_column_value(tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> str:
    """Reads `signing_secret` exactly as PostgreSQL stores it -- no ORM,
    no decryption -- the ground truth for "what is actually persisted"."""
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(
            text("SELECT signing_secret FROM core.webhook_subscriptions WHERE id = :id"),
            {"id": str(subscription_id)},
        ).one()
    return row[0]


# --- Persisted value is not plaintext ---------------------------------------


def test_persisted_signing_secret_is_not_the_raw_plaintext_value(fx: _Fixture) -> None:
    subscription, raw_secret = subscribe(
        fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )

    stored = _raw_column_value(fx.tenant.id, subscription.id)

    assert stored != raw_secret
    assert raw_secret not in stored
    assert stored.startswith(_ENVELOPE_PREFIX)


def test_two_subscriptions_never_produce_the_same_ciphertext_even_by_chance(
    fx: _Fixture,
) -> None:
    """A fresh, random nonce every `encrypt()` call (core/crypto/service.py)
    means encrypting the same-shaped secret twice never produces the same
    envelope -- a non-vacuous check that this isn't a deterministic/ECB-like
    scheme that would leak equality information about secrets."""
    sub_a, _ = subscribe(fx.tenant.id, "https://example.com/hook-a", caller=_PROVISIONING)
    sub_b, _ = subscribe(fx.tenant.id, "https://example.com/hook-b", caller=_PROVISIONING)

    stored_a = _raw_column_value(fx.tenant.id, sub_a.id)
    stored_b = _raw_column_value(fx.tenant.id, sub_b.id)

    assert stored_a != stored_b


# --- Plaintext never returned by the read paths -----------------------------


def test_get_subscription_never_returns_the_raw_plaintext_secret(fx: _Fixture) -> None:
    subscription, raw_secret = subscribe(
        fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )

    fetched = get_subscription(fx.tenant.id, subscription.id)

    assert fetched.signing_secret != raw_secret
    assert fetched.signing_secret.startswith(_ENVELOPE_PREFIX)


def test_list_subscriptions_never_returns_the_raw_plaintext_secret(fx: _Fixture) -> None:
    _subscription, raw_secret = subscribe(
        fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )

    listed = list_subscriptions(fx.tenant.id)

    assert len(listed) == 1
    assert listed[0].signing_secret != raw_secret
    assert listed[0].signing_secret.startswith(_ENVELOPE_PREFIX)


# --- Round trip via the module's own encrypt/decrypt helpers ---------------


def test_encrypted_secret_decrypts_back_to_the_exact_raw_secret(fx: _Fixture) -> None:
    subscription, raw_secret = subscribe(
        fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )

    stored = _raw_column_value(fx.tenant.id, subscription.id)
    decrypted = webhooks_service._decrypt_signing_secret(fx.tenant.id, stored)

    assert decrypted == raw_secret


# --- Fail-closed on decryption failure --------------------------------------


def test_decryption_of_a_tampered_ciphertext_fails_closed(fx: _Fixture) -> None:
    """A stored envelope that has been corrupted (bit-flipped) must never
    decrypt to a usable value -- `EncryptionService`'s own AEAD
    authentication guarantee, unweakened by this module's own thin
    wrapper: `_decrypt_signing_secret()` adds no fallback of its own."""
    subscription, _raw_secret = subscribe(
        fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )
    stored = _raw_column_value(fx.tenant.id, subscription.id)
    tampered = stored[:-1] + ("A" if stored[-1] != "A" else "B")

    with pytest.raises(DecryptionAuthenticationError):
        webhooks_service._decrypt_signing_secret(fx.tenant.id, tampered)


def test_decryption_under_the_wrong_tenant_binding_fails_closed(fx: _Fixture) -> None:
    """A genuine envelope, decrypted under a *different* tenant_id's
    associated-data binding, must fail exactly like a tampered ciphertext
    -- proves the AAD tenant-binding this module adds is actually load-
    bearing, not merely present."""
    subscription, _raw_secret = subscribe(
        fx.tenant.id, "https://example.com/hook", caller=_PROVISIONING
    )
    stored = _raw_column_value(fx.tenant.id, subscription.id)
    other_tenant_id = uuid.uuid4()

    with pytest.raises(DecryptionAuthenticationError):
        webhooks_service._decrypt_signing_secret(other_tenant_id, stored)


# --- Backward compatibility with a pre-F-02 plaintext row -------------------


def test_a_legacy_plaintext_row_is_still_usable_after_the_widening_migration(
    fx: _Fixture,
) -> None:
    """`76a55dfb1782` (the widening migration) performs no data rewrite --
    a row written before F-02 existed keeps its raw secret as-is. Proves
    the migration's own "never silently makes old records unreadable"
    requirement: inserting a legacy-shaped (no `efv1:` prefix) value
    directly, bypassing `subscribe()`'s new encryption entirely, must
    still round-trip through `_decrypt_signing_secret()` unchanged."""
    legacy_secret = "legacy-plaintext-secret-not-an-envelope"  # pragma: allowlist secret
    with tenant_session_scope(fx.tenant.id) as session:
        subscription = WebhookSubscription(
            tenant_id=fx.tenant.id, url="https://example.com/hook", signing_secret=legacy_secret
        )
        session.add(subscription)
        session.flush()
        session.refresh(subscription)
        subscription_id = subscription.id

    stored = _raw_column_value(fx.tenant.id, subscription_id)
    assert stored == legacy_secret
    assert not stored.startswith(_ENVELOPE_PREFIX)

    assert webhooks_service._decrypt_signing_secret(fx.tenant.id, stored) == legacy_secret


def test_encrypt_then_decrypt_helper_round_trip_is_pure_and_tenant_bound() -> None:
    """Unit-shaped check of the two module-private helpers directly (no
    database needed) -- the same `f"tenant:{tenant_id}"`-style associated-
    data binding `tests/core/crypto/test_service_unit.py` already
    demonstrates, applied here to confirm this module's own wrapper
    actually uses it correctly in both directions."""
    tenant_id = uuid.uuid4()
    other_tenant_id = uuid.uuid4()
    raw_secret = "a-representative-raw-secret-value"  # pragma: allowlist secret

    envelope = webhooks_service._encrypt_signing_secret(tenant_id, raw_secret)
    assert envelope.startswith(_ENVELOPE_PREFIX)
    assert envelope != raw_secret

    assert webhooks_service._decrypt_signing_secret(tenant_id, envelope) == raw_secret
    with pytest.raises(DecryptionAuthenticationError):
        webhooks_service._decrypt_signing_secret(other_tenant_id, envelope)
