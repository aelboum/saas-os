"""API key issuance, validation, rotation, and revocation
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.1).

Every function here uses `infra.db.session_scope()` (untenanted) --
`core.api_keys` is global (`core/api_keys/models.py`'s own docstring), the
same reasoning `core/identity/sessions.py` already uses for `Session`.
Tenant-scoped operations (`list_api_keys`, `get_api_key`, `revoke_api_key`,
`rotate_api_key`) filter explicitly on `tenant_id` in the query itself,
since there is no RLS backstop here to enforce it a second time -- the
composite foreign key in `core/api_keys/models.py` is this table's
substitute integrity guarantee, not a replacement for the caller's own
explicit tenant scoping.

`core/api_keys` depends on `core.audit_log` (Phase 3.4) for exactly the
one case the roadmap's own Acceptance Criteria names: "revoked key access
attempt is denied and audit-logged" -- plus, per docs/SECURITY.md section
8's standing platform-wide mandate ("the single append-only store for
every privileged action platform-wide"), the three lifecycle mutations
(issuance, revocation, rotation) are privileged actions in exactly the
same sense a role grant or permission change already is. `validate_api_key()`
does NOT audit-log a *successful* validation -- that would be "automatic
logging of every request," explicitly out of scope
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 2's own prohibition,
still binding here).

`core/api_keys` does NOT call `core.rbac.can()` for its own operations --
every function here trusts its caller's `tenant_id`/`user_id` arguments,
the same as every other Core service function in this codebase
(`core/rbac/service.py::create_role`, `core/identity/service.py::add_tenant_membership`,
etc.). Authorizing *who* may call these functions is Phase 8's ingress
layer's job, not this module's.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from core.api_keys.errors import (
    ApiKeyNotFoundError,
    InvalidApiKeyError,
    InvalidApiKeyNameError,
    RevokedApiKeyError,
    TenantMembershipRequiredError,
)
from core.api_keys.models import ApiKey
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from infra.db import IntegrityError, select, session_scope

# 256 bits of entropy -- the same standard, non-guessable bearer-secret
# size `core/identity/sessions.py` uses.
_TOKEN_BYTES = 32
_MAX_NAME_LENGTH = 200


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _validate_name(name: str) -> None:
    if not name or not name.strip():
        raise InvalidApiKeyNameError("name must be a non-empty string.")
    if len(name) > _MAX_NAME_LENGTH:
        raise InvalidApiKeyNameError(f"name exceeds {_MAX_NAME_LENGTH} characters.")


def create_api_key(tenant_id: uuid.UUID, user_id: uuid.UUID, name: str) -> tuple[ApiKey, str]:
    """Issue a new API key for `user_id` within `tenant_id`. Returns the
    persisted record (never carrying the raw secret -- only its hash) and
    the raw key. This is the ONLY point the raw value exists; it is never
    stored, logged, or reconstructable afterward.

    `(tenant_id, user_id)` must be a real `TenantMembership` -- enforced
    structurally by the composite foreign key in `core/api_keys/models.py`,
    not merely by this function remembering to check. A pair that is not a
    genuine membership fails at the database level with an `IntegrityError`,
    surfaced here as `TenantMembershipRequiredError`.
    """
    _validate_name(name)
    raw_key = secrets.token_urlsafe(_TOKEN_BYTES)
    key_hash = _hash_key(raw_key)

    try:
        with session_scope() as session:
            key = ApiKey(tenant_id=tenant_id, user_id=user_id, name=name, key_hash=key_hash)
            session.add(key)
            session.flush()
            session.refresh(key)
            session.expunge(key)
    except IntegrityError as exc:
        raise TenantMembershipRequiredError(tenant_id, user_id) from exc

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=user_id,
        action="api_key.create",
        resource_type="api_key",
        resource_id=str(key.id),
        outcome=AuditOutcome.SUCCESS,
    )
    return key, raw_key


def validate_api_key(raw_key: str) -> ApiKey:
    """Resolve a raw API key to its record, enforcing revocation.

    Looks up by the key's hash, never the raw value. An unknown key
    raises `InvalidApiKeyError` (no audit entry -- there is no resolvable
    `tenant_id` to attribute one to, the same structural reason
    `core/audit_log` never records tenant-less events, docs/IMPLEMENTATION-
    ROADMAP.md Phase 3.4 section 12). A *revoked* key raises
    `RevokedApiKeyError` and DOES write an audit entry first -- it has a
    real `tenant_id` and `user_id` on the row, satisfying the roadmap's
    literal Acceptance Criteria: "revoked key access attempt is denied and
    audit-logged."
    """
    key_hash = _hash_key(raw_key)
    with session_scope() as session:
        key = session.execute(
            select(ApiKey).where(ApiKey.key_hash == key_hash)
        ).scalar_one_or_none()
        if key is None:
            raise InvalidApiKeyError()
        session.expunge(key)

    if key.revoked_at is not None:
        record_audit_event(
            tenant_id=key.tenant_id,
            actor_type=ActorType.USER,
            actor_user_id=key.user_id,
            action="api_key.validate",
            resource_type="api_key",
            resource_id=str(key.id),
            outcome=AuditOutcome.DENIED,
        )
        raise RevokedApiKeyError(key.id)

    return key


def get_api_key(tenant_id: uuid.UUID, key_id: uuid.UUID) -> ApiKey:
    with session_scope() as session:
        key = session.execute(
            select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if key is None:
            raise ApiKeyNotFoundError(tenant_id, key_id)
        session.expunge(key)
        return key


def list_api_keys(tenant_id: uuid.UUID) -> list[ApiKey]:
    with session_scope() as session:
        keys = (
            session.execute(
                select(ApiKey)
                .where(ApiKey.tenant_id == tenant_id)
                .order_by(ApiKey.created_at.desc())
            )
            .scalars()
            .all()
        )
        for key in keys:
            session.expunge(key)
        return list(keys)


def revoke_api_key(tenant_id: uuid.UUID, key_id: uuid.UUID) -> None:
    """Revoke a key. Idempotent: revoking an already-revoked key is a
    no-op, not an error (mirrors `core/identity/sessions.py::revoke_session`).
    Revocation takes effect immediately -- the very next `validate_api_key()`
    call for this key sees the update (docs/IMPLEMENTATION-ROADMAP.md
    Phase 4.1 Security Requirement: "revocation takes effect immediately";
    there is no cache in front of this table, so there is no staleness
    window to document or test beyond "none").
    """
    with session_scope() as session:
        key = session.execute(
            select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if key is None:
            raise ApiKeyNotFoundError(tenant_id, key_id)
        already_revoked = key.revoked_at is not None
        if not already_revoked:
            key.revoked_at = datetime.now(UTC)
        user_id = key.user_id

    if not already_revoked:
        record_audit_event(
            tenant_id=tenant_id,
            actor_type=ActorType.USER,
            actor_user_id=user_id,
            action="api_key.revoke",
            resource_type="api_key",
            resource_id=str(key_id),
            outcome=AuditOutcome.SUCCESS,
        )


def rotate_api_key(tenant_id: uuid.UUID, key_id: uuid.UUID) -> tuple[ApiKey, str]:
    """Rotate a key: atomically revoke `key_id` and issue a brand new key
    with the same `tenant_id`/`user_id`/`name`. The old key's secret
    cannot itself be reused as the new one -- rotation always produces a
    genuinely new secret, the same convention established SaaS API
    providers (Stripe, GitHub, ...) use: the old key id becomes
    permanently invalid, a new key id is issued.
    """
    raw_key = secrets.token_urlsafe(_TOKEN_BYTES)
    key_hash = _hash_key(raw_key)

    with session_scope() as session:
        old_key = session.execute(
            select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if old_key is None:
            raise ApiKeyNotFoundError(tenant_id, key_id)

        if old_key.revoked_at is None:
            old_key.revoked_at = datetime.now(UTC)

        new_key = ApiKey(
            tenant_id=old_key.tenant_id,
            user_id=old_key.user_id,
            name=old_key.name,
            key_hash=key_hash,
        )
        session.add(new_key)
        session.flush()
        session.refresh(new_key)
        session.expunge(new_key)
        user_id = old_key.user_id

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=user_id,
        action="api_key.rotate",
        resource_type="api_key",
        resource_id=str(new_key.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"previous_key_id": str(key_id)},
    )
    return new_key, raw_key
