"""API key issuance, validation, rotation, and revocation
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.1; hardened by architecture
research Phase E -- "Principal + Service Accounts + API Key Hardening").

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

**Phase 4.1's original functions are unchanged in spirit** -- `create_api_key()`,
`get_api_key()`, `list_api_keys()`, `revoke_api_key()`, and
`rotate_api_key()` still do NOT call `core.rbac.can()`: every one of them
trusts its caller's `tenant_id`/`user_id` arguments, the same as every
other Core service function in this codebase (`core/rbac/service.py
::create_role`, `core/identity/service.py::add_tenant_membership`,
etc.) -- authorizing *who* may call them for a human's own key remains
Phase 8's ingress layer's job, not this module's.

**Machine credentials are held to a stricter standard (architecture
research Phase E: "Do not allow arbitrary users to create machine
credentials" / "Revocation must also be explicitly authorized").**
`create_service_account_api_key()` and `revoke_service_account_api_key()`
are new, separately-gated functions for service-account-owned keys only
-- each checks `core.rbac.can()` (the dedicated
`(resource="api_key", action="create"/"revoke")` capability) before
touching `core.api_keys` at all. This is the one place `core/api_keys`
depends on `core.rbac` and `core.identity` (`get_service_account`,
`ServiceAccountStatus`) -- a one-directional dependency (neither module
depends back on `core/api_keys`), and still not a second authorization
engine: the gate is exactly the same `can()` chokepoint every other
`core/rbac`-adjacent management operation uses, and a created key confers
no authority of its own -- it only ever resolves to the owning service
account's principal, whose *effective* permissions still come entirely
from that service account's own `ServiceAccountRole`/`DelegationGrant`
rows, independently anti-amplification-checked at assignment time
(`core/rbac/service.py::assign_service_account_role()`'s own docstring).
Creating or revoking a key therefore cannot itself grant, and merely
creating a service account or a key grants nothing by itself.

`validate_api_key()` (architecture research Phase E) is the complete
*authentication* step: secret match, then not-revoked, then not-expired,
then (for a service-account-owned key) the owning `ServiceAccount` must
resolve and be `ACTIVE`. It still does not itself call `can()` --
*authorization* (does this now-authenticated principal have permission
for a given action) remains the caller's own subsequent, explicit
`core.rbac.can(actor_id=..., actor_type=..., tenant_id=key.tenant_id, ...)`
call, using whichever of `key.user_id`/`key.service_account_id` is set --
`core/api_keys` still does not implement its own parallel
permission-grant mechanism (this module's own `__init__.py` docstring).
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from core.api_keys.errors import (
    ApiKeyNotAuthorizedError,
    ApiKeyNotFoundError,
    ExpiredApiKeyError,
    InactiveServiceAccountError,
    InvalidApiKeyError,
    InvalidApiKeyNameError,
    RevokedApiKeyError,
    ServiceAccountRequiredError,
    TenantMembershipRequiredError,
)
from core.api_keys.models import ApiKey
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.identity import ServiceAccountStatus, get_service_account
from core.rbac import can, register_permission
from infra.db import IntegrityError, select, session_scope

# 256 bits of entropy -- the same standard, non-guessable bearer-secret
# size `core/identity/sessions.py` uses.
_TOKEN_BYTES = 32
_MAX_NAME_LENGTH = 200


def _audit_actor(key: ApiKey) -> tuple[ActorType, uuid.UUID | None]:
    """Which `core.audit_log` actor a `validate_api_key()` denial event
    for `key` should be attributed to (architecture research Phase E) --
    `ActorType.USER`/`key.user_id` for a human-owned key (Phase 4.1's
    original, unchanged behavior), `ActorType.SYSTEM`/`None` for a
    service-account-owned key: `core/audit_log` supports no
    `SERVICE_ACCOUNT` actor type of its own (`core/audit_log/models.py
    ::ActorType`'s own "Do NOT add actor types merely speculatively"
    discipline, deliberately left untouched by this phase), and
    `ActorType.SYSTEM` -- "a platform-internal actor with no associated
    User row" -- is the exact, already-existing shape a machine-initiated
    audit event needs.
    """
    if key.user_id is not None:
        return ActorType.USER, key.user_id
    return ActorType.SYSTEM, None


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _validate_name(name: str) -> None:
    if not name or not name.strip():
        raise InvalidApiKeyNameError("name must be a non-empty string.")
    if len(name) > _MAX_NAME_LENGTH:
        raise InvalidApiKeyNameError(f"name exceeds {_MAX_NAME_LENGTH} characters.")


def create_api_key(
    tenant_id: uuid.UUID, user_id: uuid.UUID, name: str, *, expires_at: datetime | None = None
) -> tuple[ApiKey, str]:
    """Issue a new API key for `user_id` within `tenant_id`. Returns the
    persisted record (never carrying the raw secret -- only its hash) and
    the raw key. This is the ONLY point the raw value exists; it is never
    stored, logged, or reconstructable afterward.

    `(tenant_id, user_id)` must be a real `TenantMembership` -- enforced
    structurally by the composite foreign key in `core/api_keys/models.py`,
    not merely by this function remembering to check. A pair that is not a
    genuine membership fails at the database level with an `IntegrityError`,
    surfaced here as `TenantMembershipRequiredError`.

    `expires_at` (architecture research Phase E) is optional and defaults
    to `None` (no expiry) -- Phase 4.1's original, unchanged behavior for
    every caller that does not pass it.
    """
    _validate_name(name)
    raw_key = secrets.token_urlsafe(_TOKEN_BYTES)
    key_hash = _hash_key(raw_key)

    try:
        with session_scope() as session:
            key = ApiKey(
                tenant_id=tenant_id,
                user_id=user_id,
                name=name,
                key_hash=key_hash,
                expires_at=expires_at,
            )
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


def create_service_account_api_key(
    *,
    actor_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    service_account_id: uuid.UUID,
    name: str,
    expires_at: datetime | None = None,
) -> tuple[ApiKey, str]:
    """Issue a new API key owned by `service_account_id` within
    `tenant_id` (architecture research Phase E -- machine credentials).
    Unlike `create_api_key()`, this function is explicitly gated: it does
    not exist to let an arbitrary user mint machine credentials
    (`core/api_keys/errors.py::ApiKeyNotAuthorizedError`'s own docstring).

    Fails closed, in this order, before any row is written:

    1. `name` must be valid (`InvalidApiKeyNameError` otherwise).
    2. `service_account_id` must resolve within `tenant_id`
       (`ServiceAccountRequiredError` otherwise) -- checked explicitly
       here (not left to the composite FK alone) so this function can
       give a caller a clean, typed error before ever generating a
       secret.
    3. `actor_user_id` must hold the dedicated "manage API keys in this
       tenant" capability (`(resource="api_key", action="create")`,
       registered here idempotently, checked via the existing `can()`
       chokepoint -- no second authorization mechanism)
       (`ApiKeyNotAuthorizedError` otherwise).

    The created key confers no authority of its own: it resolves to
    `service_account_id` as a principal, whose effective permissions come
    entirely from that service account's own independently-authorized
    `ServiceAccountRole`/`DelegationGrant` rows (`core/api_keys/service.py`'s
    own module docstring) -- so this function needs no anti-amplification
    check beyond the management-capability gate above.
    """
    _validate_name(name)

    service_account = get_service_account(tenant_id, service_account_id)
    if service_account is None:
        raise ServiceAccountRequiredError(tenant_id, service_account_id)

    register_permission("api_key", "create")
    if not can(actor_id=actor_user_id, tenant_id=tenant_id, action="create", resource="api_key"):
        raise ApiKeyNotAuthorizedError(actor_user_id, tenant_id)

    raw_key = secrets.token_urlsafe(_TOKEN_BYTES)
    key_hash = _hash_key(raw_key)

    try:
        with session_scope() as session:
            key = ApiKey(
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                name=name,
                key_hash=key_hash,
                expires_at=expires_at,
            )
            session.add(key)
            session.flush()
            session.refresh(key)
            session.expunge(key)
    except IntegrityError as exc:
        raise ServiceAccountRequiredError(tenant_id, service_account_id) from exc

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="api_key.create",
        resource_type="api_key",
        resource_id=str(key.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"service_account_id": str(service_account_id)},
    )
    return key, raw_key


def validate_api_key(raw_key: str) -> ApiKey:
    """Resolve a raw API key to its record -- the complete *authentication*
    step (architecture research Phase E's own "Authorization Flow": verify
    secret -> verify not revoked -> verify not expired -> resolve
    ServiceAccount -> verify ServiceAccount active), stopping short of
    *authorization* (that is the caller's own subsequent `core.rbac.can()`
    call -- this module's own docstring).

    Looks up by the key's hash, never the raw value. An unknown key
    raises `InvalidApiKeyError` (no audit entry -- there is no resolvable
    `tenant_id` to attribute one to, the same structural reason
    `core/audit_log` never records tenant-less events, docs/IMPLEMENTATION-
    ROADMAP.md Phase 3.4 section 12). Every later failure DOES write an
    audit entry first -- the row has a real `tenant_id` and owner,
    satisfying the roadmap's literal Acceptance Criteria: "revoked key
    access attempt is denied and audit-logged" (architecture research
    Phase E extends this identical treatment to an expired key and to a
    missing/disabled owning service account):

    - `revoked_at IS NOT NULL` -> `RevokedApiKeyError` (Phase 4.1, unchanged).
    - `expires_at IS NOT NULL AND expires_at <= now` -> `ExpiredApiKeyError`
      (Phase E) -- checked only once revocation is ruled out, so a key
      that is both revoked and expired reports as revoked, matching
      `RevokedApiKeyError`'s pre-existing precedence over every other
      state.
    - a service-account-owned key (`key.service_account_id is not None`)
      whose owning `ServiceAccount` no longer exists or is `DISABLED` ->
      `InactiveServiceAccountError` (Phase E). Never checked for a
      user-owned key.

    Fails closed throughout: an expired/revoked/inactive-owner key never
    reaches the `return key` at the end, regardless of which check fires
    first.
    """
    key_hash = _hash_key(raw_key)
    with session_scope() as session:
        key = session.execute(
            select(ApiKey).where(ApiKey.key_hash == key_hash)
        ).scalar_one_or_none()
        if key is None:
            raise InvalidApiKeyError()
        session.expunge(key)

    actor_type, actor_user_id = _audit_actor(key)

    if key.revoked_at is not None:
        record_audit_event(
            tenant_id=key.tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            action="api_key.validate",
            resource_type="api_key",
            resource_id=str(key.id),
            outcome=AuditOutcome.DENIED,
        )
        raise RevokedApiKeyError(key.id)

    if key.expires_at is not None and key.expires_at <= datetime.now(UTC):
        record_audit_event(
            tenant_id=key.tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            action="api_key.validate",
            resource_type="api_key",
            resource_id=str(key.id),
            outcome=AuditOutcome.DENIED,
        )
        raise ExpiredApiKeyError(key.id)

    if key.service_account_id is not None:
        service_account = get_service_account(key.tenant_id, key.service_account_id)
        if service_account is None or service_account.status != ServiceAccountStatus.ACTIVE.value:
            record_audit_event(
                tenant_id=key.tenant_id,
                actor_type=actor_type,
                actor_user_id=actor_user_id,
                action="api_key.validate",
                resource_type="api_key",
                resource_id=str(key.id),
                outcome=AuditOutcome.DENIED,
            )
            raise InactiveServiceAccountError(key.id, key.service_account_id)

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

    Ungated, exactly like `create_api_key()` (this module's own docstring)
    -- for a service-account-owned key, prefer the gated
    `revoke_service_account_api_key()` instead.
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
            session.flush()
        session.expunge(key)

    if not already_revoked:
        actor_type, actor_user_id = _audit_actor(key)
        record_audit_event(
            tenant_id=tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            action="api_key.revoke",
            resource_type="api_key",
            resource_id=str(key_id),
            outcome=AuditOutcome.SUCCESS,
        )


def revoke_service_account_api_key(
    *, actor_user_id: uuid.UUID, tenant_id: uuid.UUID, key_id: uuid.UUID
) -> None:
    """Revoke a service-account-owned key, explicitly authorized
    (architecture research Phase E: "Revocation must also be explicitly
    authorized" -- "a service account should not automatically be allowed
    to revoke arbitrary tenant keys merely because it owns itself").
    `actor_user_id` must hold the same dedicated "manage API keys in this
    tenant" capability (`(resource="api_key", action="revoke")`)
    `create_service_account_api_key()` requires for creation, checked via
    the existing `can()` chokepoint -- no self-revocation shortcut, and
    no distinct check for "is this actually a service-account-owned key"
    (delegates entirely to `revoke_api_key()`'s own existing,
    owner-agnostic behavior once authorization is confirmed).
    """
    register_permission("api_key", "revoke")
    if not can(actor_id=actor_user_id, tenant_id=tenant_id, action="revoke", resource="api_key"):
        raise ApiKeyNotAuthorizedError(actor_user_id, tenant_id)
    revoke_api_key(tenant_id, key_id)


def rotate_api_key(tenant_id: uuid.UUID, key_id: uuid.UUID) -> tuple[ApiKey, str]:
    """Rotate a key: atomically revoke `key_id` and issue a brand new key
    with the same `tenant_id`/owner (`user_id` or `service_account_id`,
    architecture research Phase E)/`name`/`expires_at`. The old key's
    secret cannot itself be reused as the new one -- rotation always
    produces a genuinely new secret, the same convention established
    SaaS API providers (Stripe, GitHub, ...) use: the old key id becomes
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
            service_account_id=old_key.service_account_id,
            name=old_key.name,
            key_hash=key_hash,
            expires_at=old_key.expires_at,
        )
        session.add(new_key)
        session.flush()
        session.refresh(new_key)
        session.expunge(new_key)
        session.expunge(old_key)

    actor_type, actor_user_id = _audit_actor(old_key)
    record_audit_event(
        tenant_id=tenant_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action="api_key.rotate",
        resource_type="api_key",
        resource_id=str(new_key.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"previous_key_id": str(key_id)},
    )
    return new_key, raw_key
