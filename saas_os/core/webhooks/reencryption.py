"""Operator re-encryption of legacy plaintext webhook signing secrets
(finding F7; owner decision of 2026-11-01; proposed ADR-0045 amendment of
2026-11-01).

A subscription created before field encryption (F-02) stores its signing
secret as plaintext; `_decrypt_signing_secret()` still accepts it so that
existing receivers keep working. This module is the one way to convert
those rows: a platform operator holding `platform.webhook_secret:reencrypt`
names one tenant, and each plaintext secret of that tenant is encrypted in
place with the existing `EncryptionService` and the existing tenant-bound
associated data. The secret value does not change, so receivers need
nothing. Nothing here refuses plaintext at run time; that is a later,
separately approved release.

**Dry run by default.** Without `apply` nothing is written and nothing is
locked: the call counts the tenant's plaintext secrets.

**Key first, nothing changed without it.** With `apply`, the encryption key
is checked before any row is read (an encrypt-then-decrypt round trip on a
fixed probe value); a missing or unusable key raises
`WebhookSecretReencryptionKeyError` and nothing is written.

**Verified before written.** Each new ciphertext is decrypted again and
compared, in constant time, with the stored plaintext before the row is
changed; any mismatch or error rolls the whole tenant back and raises
`WebhookSecretReencryptionError`. A row already carrying the envelope prefix
is never touched, so a second run finds nothing (idempotent).

**Authorized and evidenced in one transaction** (ADR-0045 sections 9c and
8): `authorize_platform_caller` for `webhook_secret.reencrypt` -- a person
only, no system purpose -- then, with `apply`, one tenant audit row per
re-encrypted subscription (`webhook_subscription.secret_reencrypted`, the
subscription id as resource, the operator as actor), and one platform audit
row with the count. A refusal writes one `denied` platform row. A closed or
unknown tenant is refused.

**No secret leaves this module.** No secret, ciphertext or URL is logged,
returned, put in an exception message or in audit metadata. Errors raised
here carry fixed text and are raised outside the `except` block that caught
the underlying failure, so they chain nothing that could carry a value.

**Tenancy.** Rows are read and changed under the tenant's own row-level
security scope (`bind_tenant_scope`) with an explicit tenant predicate; the
tenant row is held `FOR SHARE` (`lock_open_tenant`).
"""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass

from saas_os.core.authority import UserCaller
from saas_os.core.tenancy import TenantClosedError, TenantNotFoundError, lock_open_tenant
from saas_os.core.webhooks.models import WebhookSubscription
from saas_os.infra.db import bind_tenant_scope, select

MAX_REENCRYPT_SUBSCRIPTIONS = 1000

_TARGET_TENANT = "tenant"
_RESOURCE_TYPE = "webhook_subscription"
_TENANT_AUDIT_ACTION = "webhook_subscription.secret_reencrypted"
_CODE_TENANT_CLOSED = "tenant_closed"
_CODE_TENANT_NOT_FOUND = "tenant_not_found"
_KEY_PROBE = "saas-os-webhook-secret-reencryption-probe"


class WebhookSecretReencryptionError(Exception):
    """A re-encryption could not be verified; nothing was written for the
    tenant. The message names the problem, never a value."""


class WebhookSecretReencryptionKeyError(WebhookSecretReencryptionError):
    """The encryption key is missing or unusable; nothing was read or
    written."""


@dataclass(frozen=True)
class WebhookSecretReencryptionResult:
    """`matched`: the tenant's subscriptions whose secret is still
    plaintext. `reencrypted`: how many were converted -- 0 unless
    `applied`."""

    tenant_id: uuid.UUID
    matched: int
    reencrypted: int
    applied: bool


def _require_usable_key(tenant_id: uuid.UUID) -> None:
    from saas_os.core.webhooks.service import _decrypt_signing_secret, _encrypt_signing_secret

    usable = False
    try:
        envelope = _encrypt_signing_secret(tenant_id, _KEY_PROBE)
        usable = hmac.compare_digest(
            _decrypt_signing_secret(tenant_id, envelope).encode(), _KEY_PROBE.encode()
        )
    except Exception:  # noqa: BLE001 -- any key failure means: do not start
        usable = False
    if not usable:
        raise WebhookSecretReencryptionKeyError(
            "the field-encryption key is missing or unusable; nothing was changed."
        )


def _reencrypted(tenant_id: uuid.UUID, plaintext: str) -> str | None:
    """The verified envelope for `plaintext`, or None if it could not be
    produced and read back identically."""
    from saas_os.core.webhooks.service import (
        _SIGNING_SECRET_ENVELOPE_PREFIX,
        _decrypt_signing_secret,
        _encrypt_signing_secret,
    )

    try:
        envelope = _encrypt_signing_secret(tenant_id, plaintext)
        if not envelope.startswith(_SIGNING_SECRET_ENVELOPE_PREFIX):
            return None
        if not hmac.compare_digest(
            _decrypt_signing_secret(tenant_id, envelope).encode(), plaintext.encode()
        ):
            return None
    except Exception:  # noqa: BLE001 -- reported by the caller, with no value
        return None
    return envelope


def reencrypt_legacy_signing_secrets(
    tenant_id: uuid.UUID,
    *,
    caller: object,
    reason: str,
    apply: bool = False,
) -> WebhookSecretReencryptionResult:
    """Count, or with `apply` re-encrypt, `tenant_id`'s legacy plaintext
    webhook signing secrets. See the module docstring for the authority,
    the verification and the evidence."""
    from saas_os.core.audit_log import record_in_transaction
    from saas_os.core.platform_authority import (
        InvalidPlatformRequestError,
        authorize_platform_caller,
        platform_change_session,
        platform_operation,
        record_platform_event_in_transaction,
        record_platform_refusal,
        recording_platform_refusal,
        validate_reason,
    )
    from saas_os.core.platform_authority.operations import WEBHOOK_SECRET_REENCRYPT
    from saas_os.core.webhooks.service import _SIGNING_SECRET_ENVELOPE_PREFIX

    if not isinstance(tenant_id, uuid.UUID):
        raise InvalidPlatformRequestError("tenant_id must be a uuid.UUID.")
    reason = validate_reason(reason)
    spec = platform_operation(WEBHOOK_SECRET_REENCRYPT)
    if apply:
        _require_usable_key(tenant_id)

    try:
        with (
            recording_platform_refusal(
                caller=caller,
                operation=WEBHOOK_SECRET_REENCRYPT,
                target_type=_TARGET_TENANT,
                target_id=str(tenant_id),
            ),
            platform_change_session(caller, WEBHOOK_SECRET_REENCRYPT) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=WEBHOOK_SECRET_REENCRYPT)
            assert isinstance(caller, UserCaller)  # the operation accepts no system purpose
            with bind_tenant_scope(session, tenant_id):
                lock_open_tenant(session, tenant_id)
                query = (
                    select(WebhookSubscription)
                    .where(
                        WebhookSubscription.tenant_id == tenant_id,
                        ~WebhookSubscription.signing_secret.startswith(
                            _SIGNING_SECRET_ENVELOPE_PREFIX
                        ),
                    )
                    .order_by(WebhookSubscription.id)
                    .limit(MAX_REENCRYPT_SUBSCRIPTIONS + 1)
                )
                if apply:
                    query = query.with_for_update()
                rows = session.execute(query).scalars().all()
                if len(rows) > MAX_REENCRYPT_SUBSCRIPTIONS:
                    raise InvalidPlatformRequestError(
                        f"the tenant has more than {MAX_REENCRYPT_SUBSCRIPTIONS} plaintext "
                        "secrets; run again after this batch."
                    )
                if not apply:
                    return WebhookSecretReencryptionResult(tenant_id, len(rows), 0, applied=False)
                for row in rows:
                    envelope = _reencrypted(tenant_id, row.signing_secret)
                    if envelope is None:
                        raise WebhookSecretReencryptionError(
                            "a re-encrypted secret did not decrypt to the stored value; "
                            "nothing was changed for this tenant."
                        )
                    row.signing_secret = envelope
                    record_in_transaction(
                        session,
                        caller=caller,
                        tenant_id=tenant_id,
                        action=_TENANT_AUDIT_ACTION,
                        resource_type=_RESOURCE_TYPE,
                        resource_id=str(row.id),
                        metadata={"platform": True},
                    )
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=_TARGET_TENANT,
                target_id=str(tenant_id),
                target_tenant_id=tenant_id,
                reason=reason,
                metadata={"secrets_reencrypted": len(rows)},
            )
            return WebhookSecretReencryptionResult(tenant_id, len(rows), len(rows), applied=True)
    except (TenantClosedError, TenantNotFoundError) as refused:
        record_platform_refusal(
            caller=caller,
            action=spec.audit_action,
            target_type=_TARGET_TENANT,
            target_id=str(tenant_id),
            code=_CODE_TENANT_CLOSED
            if isinstance(refused, TenantClosedError)
            else _CODE_TENANT_NOT_FOUND,
        )
        raise
