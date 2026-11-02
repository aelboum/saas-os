"""Operator re-encryption of legacy plaintext webhook signing secrets
(finding F7; owner decision of 2026-11-01): `platform.webhook_secret:reencrypt`,
one tenant, a dry run that changes nothing, a key check before anything is
read, each secret verified before it is written, per-subscription tenant
audit and a platform audit row, idempotent, and no secret anywhere in the
output, the audit or the logs. PostgreSQL.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, REASON, P, Scene
from platform_helpers import PlatformWorld
from psycopg.errors import LockNotAvailable
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

import saas_os.core.webhooks.reencryption as reencryption
import saas_os.core.webhooks.service as webhooks_service
from saas_os.core.authority import ServiceAccountCaller
from saas_os.core.platform_authority import InvalidPlatformRequestError, PlatformNotAuthorizedError
from saas_os.core.tenancy import TenantClosedError, TenantStatus
from saas_os.core.webhooks import (
    WebhookSecretReencryptionError,
    WebhookSecretReencryptionKeyError,
    compute_signed_envelope,
    reencrypt_legacy_signing_secrets,
    subscribe,
    verify_webhook_signature,
)
from saas_os.core.webhooks.reencryption import MAX_REENCRYPT_SUBSCRIPTIONS

pytestmark = pytest.mark.integration

_ENVELOPE = "efv1:"  # pragma: allowlist secret
_ACTION = "platform.webhook_secret.reencrypt"  # pragma: allowlist secret
_TENANT_ACTION = "webhook_subscription.secret_reencrypted"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _remove_subscriptions(scene: Scene, platform: PlatformWorld) -> Iterator[None]:
    """Delete every subscription of this test's tenants afterwards. Scene's
    clean-up only marks tenants purged; an encrypted secret left behind
    would make the webhook migration's downgrade (which narrows the column
    back to 64 characters) fail in later migration tests."""
    yield
    if scene.tenants:
        platform.execute(
            "DELETE FROM core.webhook_subscriptions WHERE tenant_id = ANY(:t)",
            {"t": scene.tenants},
        )


def _legacy(platform: PlatformWorld, tenant_id: uuid.UUID, n: int) -> dict[uuid.UUID, str]:
    """`n` subscriptions whose stored secret is plaintext, as rows written
    before field encryption are: created normally, then rewritten by the
    migration role to the raw secret."""
    by_id = {}
    for i in range(n):
        subscription, raw = subscribe(tenant_id, f"https://example.com/f7-{i}", caller=PROVISIONING)
        platform.execute(
            "UPDATE core.webhook_subscriptions SET signing_secret = :s WHERE id = :i",
            {"s": raw, "i": subscription.id},
        )
        by_id[subscription.id] = raw
    return by_id


def _stored(platform: PlatformWorld, subscription_id: uuid.UUID) -> str:
    return platform.scalar(
        "SELECT signing_secret FROM core.webhook_subscriptions WHERE id = :i",
        {"i": subscription_id},
    )


def _decrypt(tenant_id: uuid.UUID, stored: str) -> str:
    return webhooks_service._decrypt_signing_secret(tenant_id, stored)  # pyright: ignore[reportPrivateUsage]


def test_a_dry_run_counts_and_changes_nothing(scene: Scene, platform: PlatformWorld) -> None:
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 2)
    subscribe(tenant, "https://example.com/already-encrypted", caller=PROVISIONING)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])
    platform.clear_audit()

    result = reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON)

    assert (result.matched, result.reencrypted, result.applied) == (2, 0, False)
    assert all(_stored(platform, sid) == raw for sid, raw in legacy.items())
    assert platform.audit(action=_ACTION) == []
    assert scene.tenant_audit(tenant, _TENANT_ACTION) == []


def test_apply_encrypts_in_place_verifies_and_audits_each_subscription(
    scene: Scene, platform: PlatformWorld, caplog: pytest.LogCaptureFixture
) -> None:
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 2)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])
    platform.clear_audit()

    with caplog.at_level(logging.DEBUG):
        result = reencrypt_legacy_signing_secrets(
            tenant, caller=operator, reason=REASON, apply=True
        )

    assert (result.matched, result.reencrypted, result.applied) == (2, 2, True)
    body, timestamp = b'{"event_id":"x"}', 1_800_000_000
    for subscription_id, raw in legacy.items():
        stored = _stored(platform, subscription_id)
        assert stored.startswith(_ENVELOPE) and raw not in stored
        # The same secret as before: what the delivery path reads back signs
        # exactly as the receiver, holding the original secret, verifies.
        assert _decrypt(tenant, stored) == raw
        signature = compute_signed_envelope(_decrypt(tenant, stored), body, timestamp)
        verify_webhook_signature(raw, body, timestamp, signature, tolerance_seconds=10**10)

    rows = scene.tenant_audit(tenant, _TENANT_ACTION)
    assert sorted(r["resource_id"] for r in rows) == sorted(str(s) for s in legacy)
    assert all(r["actor_user_id"] == operator.user_id for r in rows)
    (audit,) = platform.audit(action=_ACTION, outcome="success")
    assert audit["actor_user_id"] == operator.user_id and audit["reason"] == REASON
    assert audit["metadata"] == {"secrets_reencrypted": 2}

    # Neither the secret nor its new ciphertext appears in any audit row, the
    # result or the logs; the audit rows name the subscription only.
    everything = str(rows) + str(audit) + str(result) + caplog.text
    for subscription_id, raw in legacy.items():
        assert raw not in everything
        envelope = _stored(platform, subscription_id)
        assert envelope not in everything
        assert envelope.removeprefix(_ENVELOPE)[:16] not in everything
    assert all(r["metadata"] == {"platform": True} for r in rows)


def test_a_second_run_finds_nothing(scene: Scene, platform: PlatformWorld) -> None:
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 1)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])
    reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=True)
    (sid,) = legacy
    first = _stored(platform, sid)

    again = reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=True)

    assert (again.matched, again.reencrypted) == (0, 0)
    assert _stored(platform, sid) == first  # never re-encrypted twice


def test_another_tenants_secrets_are_never_touched(scene: Scene, platform: PlatformWorld) -> None:
    tenant, other = scene.tenant(), scene.tenant()
    _legacy(platform, tenant, 1)
    theirs = _legacy(platform, other, 1)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])

    reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=True)

    ((sid, raw),) = theirs.items()
    assert _stored(platform, sid) == raw


def test_a_missing_key_stops_before_anything_is_read_or_written(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 1)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])
    platform.clear_audit()

    def no_key(tenant_id: uuid.UUID, raw_secret: str) -> str:
        from saas_os.core.crypto import EncryptionKeyUnavailableError

        raise EncryptionKeyUnavailableError(key_version="<active>")

    monkeypatch.setattr(webhooks_service, "_encrypt_signing_secret", no_key)
    with pytest.raises(WebhookSecretReencryptionKeyError) as excinfo:
        reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=True)

    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None
    ((sid, raw),) = legacy.items()
    assert _stored(platform, sid) == raw
    assert platform.audit(action=_ACTION) == []


def test_a_secret_that_does_not_read_back_rolls_the_whole_tenant_back(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No destructive conversion without verification: when the second of
    two secrets does not decrypt to its stored value, neither is changed."""
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 2)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])
    real = webhooks_service._decrypt_signing_secret  # pyright: ignore[reportPrivateUsage]
    calls: list[int] = []

    def corrupt_third(tenant_id: uuid.UUID, stored: str, **kwargs: object) -> str:
        value = real(tenant_id, stored)
        calls.append(1)
        # Call 1 is the key probe, call 2 the first secret's check; 3 breaks.
        return value + "-corrupted" if len(calls) == 3 else value

    monkeypatch.setattr(webhooks_service, "_decrypt_signing_secret", corrupt_third)
    with pytest.raises(WebhookSecretReencryptionError) as excinfo:
        reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=True)

    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None
    for sid, raw in legacy.items():
        assert _stored(platform, sid) == raw
        assert raw not in str(excinfo.value)
    assert scene.tenant_audit(tenant, _TENANT_ACTION) == []


@pytest.mark.parametrize("who", ["no_permission", "other_permission", "service_account", "system"])
def test_only_a_holder_of_the_permission_may_run_it(
    scene: Scene, platform: PlatformWorld, who: str
) -> None:
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 1)
    callers: dict[str, Any] = {
        "no_permission": lambda: platform.operator([])[0],
        "other_permission": lambda: platform.operator([P.OUTBOX_REPLAY])[0],
        "service_account": lambda: ServiceAccountCaller(uuid.uuid4(), tenant),
        "system": lambda: PROVISIONING,
    }
    caller = callers[who]()
    platform.clear_audit()
    with pytest.raises(PlatformNotAuthorizedError):
        reencrypt_legacy_signing_secrets(tenant, caller=caller, reason=REASON, apply=True)
    with pytest.raises(PlatformNotAuthorizedError):
        reencrypt_legacy_signing_secrets(tenant, caller=BILLING, reason=REASON)
    ((sid, raw),) = legacy.items()
    assert _stored(platform, sid) == raw
    assert platform.audit(action=_ACTION, outcome="success") == []


@pytest.mark.parametrize("status", [TenantStatus.DELETED, TenantStatus.PURGED])
def test_a_closed_tenant_is_refused(
    scene: Scene, platform: PlatformWorld, status: TenantStatus
) -> None:
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 1)
    scene.set_status(tenant, status)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])
    platform.clear_audit()
    with pytest.raises(TenantClosedError):
        reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=True)
    ((sid, raw),) = legacy.items()
    assert _stored(platform, sid) == raw
    denied = platform.audit(action=_ACTION, outcome="denied")
    assert [row["reason"] for row in denied] == ["tenant_closed"]


# --- follow-up to #192 (owner, 2026-11-02) ----------------------------------


def _bulk_legacy(platform: PlatformWorld, tenant_id: uuid.UUID, n: int) -> None:
    """`n` plaintext subscriptions inserted directly by the migration role;
    the boundary tests need more rows than `subscribe()` can create quickly."""
    platform.execute(
        "INSERT INTO core.webhook_subscriptions (id, tenant_id, url, signing_secret) "
        "SELECT gen_random_uuid(), :t, 'https://example.com/f7-bulk-' || g, "
        "'f7-bulk-plaintext-' || g FROM generate_series(1, :n) AS g",
        {"t": tenant_id, "n": n},
    )


def _plaintext_count(platform: PlatformWorld, tenant_id: uuid.UUID) -> int:
    return platform.scalar(
        "SELECT count(*) FROM core.webhook_subscriptions "
        "WHERE tenant_id = :t AND signing_secret NOT LIKE 'efv1:%'",
        {"t": tenant_id},
    )


@pytest.mark.parametrize("apply", [False, True])
def test_only_an_applied_run_locks_the_tenant_row(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, apply: bool
) -> None:
    """A dry run locks no row: while it is still inside its transaction
    (held there by a hook on its result), another transaction can lock the
    tenant row and the subscription rows `FOR UPDATE NOWAIT` at once. An
    applied run, probed the same way, holds the tenant row `FOR SHARE` --
    the control showing the probe detects a lock."""
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 1)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])
    real = reencryption.WebhookSecretReencryptionResult
    probed: dict[str, str] = {}

    def probe(table: str, ids: list[uuid.UUID]) -> str:
        try:
            with platform.admin.begin() as conn:
                conn.execute(
                    text(f"SELECT id FROM core.{table} WHERE id = ANY(:i) FOR UPDATE NOWAIT"),
                    {"i": ids},
                )
                conn.rollback()
        except OperationalError as error:
            assert isinstance(error.orig, LockNotAvailable), error
            return "locked"
        return "free"

    def held_open(*args: Any, **kwargs: Any) -> Any:
        probed["tenant"] = probe("tenants", [tenant])
        if not apply:
            probed["subscriptions"] = probe("webhook_subscriptions", list(legacy))
        return real(*args, **kwargs)

    monkeypatch.setattr(reencryption, "WebhookSecretReencryptionResult", held_open)
    result = reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=apply)

    assert result.matched == 1
    if apply:
        assert probed == {"tenant": "locked"}
    else:
        assert probed == {"tenant": "free", "subscriptions": "free"}


def test_a_refused_caller_is_denied_before_the_key_is_touched(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Authorization comes first: an unauthorised `apply` with an unusable
    key is refused for want of authority, writes its `denied` platform row,
    and never reaches the key."""
    tenant = scene.tenant()
    legacy = _legacy(platform, tenant, 1)
    caller, _ = platform.operator([])
    platform.clear_audit()
    key_calls: list[str] = []

    def no_key(*args: object, **kwargs: object) -> str:
        key_calls.append("called")
        raise KeyError("the key must not be used for a refused caller")

    monkeypatch.setattr(webhooks_service, "_encrypt_signing_secret", no_key)
    monkeypatch.setattr(webhooks_service, "_decrypt_signing_secret", no_key)
    with pytest.raises(PlatformNotAuthorizedError):
        reencrypt_legacy_signing_secrets(tenant, caller=caller, reason=REASON, apply=True)

    assert key_calls == []
    (denied,) = platform.audit(action=_ACTION, outcome="denied")
    assert denied["actor_user_id"] == caller.user_id
    assert platform.audit(action=_ACTION, outcome="success") == []
    ((sid, raw),) = legacy.items()
    assert _stored(platform, sid) == raw


def test_exactly_the_maximum_is_allowed(scene: Scene, platform: PlatformWorld) -> None:
    tenant = scene.tenant()
    _bulk_legacy(platform, tenant, MAX_REENCRYPT_SUBSCRIPTIONS)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])

    counted = reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON)
    assert (counted.matched, counted.applied) == (MAX_REENCRYPT_SUBSCRIPTIONS, False)

    applied = reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=True)
    assert (applied.matched, applied.reencrypted) == (MAX_REENCRYPT_SUBSCRIPTIONS,) * 2
    assert _plaintext_count(platform, tenant) == 0


@pytest.mark.parametrize("apply", [False, True])
def test_one_more_than_the_maximum_is_refused_and_changes_nothing(
    scene: Scene, platform: PlatformWorld, apply: bool
) -> None:
    tenant = scene.tenant()
    _bulk_legacy(platform, tenant, MAX_REENCRYPT_SUBSCRIPTIONS + 1)
    operator, _ = platform.operator([P.WEBHOOK_SECRET_REENCRYPT])
    platform.clear_audit()

    with pytest.raises(InvalidPlatformRequestError, match="more than 1000"):
        reencrypt_legacy_signing_secrets(tenant, caller=operator, reason=REASON, apply=apply)

    assert _plaintext_count(platform, tenant) == MAX_REENCRYPT_SUBSCRIPTIONS + 1
    assert platform.audit(action=_ACTION, outcome="success") == []
    assert scene.tenant_audit(tenant, _TENANT_ACTION) == []
