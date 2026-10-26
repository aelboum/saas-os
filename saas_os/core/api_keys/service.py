"""API key issuance, validation, rotation, and revocation
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.1; hardened by architecture
research Phase E -- "Principal + Service Accounts + API Key Hardening").

Every function here uses `saas_os.infra.db.session_scope()` (untenanted) --
`saas_os.core.api_keys` is global (`saas_os/core/api_keys/models.py`'s own docstring), the
same reasoning `saas_os/core/identity/sessions.py` already uses for `Session`.
Tenant-scoped operations (`list_api_keys`, `get_api_key`, `revoke_api_key`,
`rotate_api_key`) filter explicitly on `tenant_id` in the query itself,
since there is no RLS backstop here to enforce it a second time -- the
composite foreign key in `saas_os/core/api_keys/models.py` is this table's
substitute integrity guarantee, not a replacement for the caller's own
explicit tenant scoping.

`saas_os/core/api_keys` depends on `core.audit_log` (Phase 3.4) for exactly the
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

**Explicit callers (Foundation Authority & Evidence, ADR-0031).** Every
key mutation takes a required typed `caller` (`saas_os.core.authority`):
`create_api_key()` issues a key to the caller itself (an active user);
`revoke_api_key()`/`rotate_api_key()` let a user manage their own key
(and a service account revoke its own), and otherwise require
`(api_key, revoke|rotate)` through `saas_os.core.rbac.can()`. Each mutation and
its audit entry -- naming the caller, never merely the key's owner -- are
written in one `tenant_session_scope()` transaction. `get_api_key()`/
`list_api_keys()` are reads and remain ungated.

**Machine credentials are held to a stricter standard (architecture
research Phase E: "Do not allow arbitrary users to create machine
credentials" / "Revocation must also be explicitly authorized").**
`create_service_account_api_key()` and `revoke_service_account_api_key()`
are new, separately-gated functions for service-account-owned keys only
-- each checks `saas_os.core.rbac.can()` (the dedicated
`(resource="api_key", action="create"/"revoke")` capability) before
touching `saas_os.core.api_keys` at all. This is the one place `saas_os/core/api_keys`
depends on `saas_os.core.rbac` and `saas_os.core.identity` (`get_service_account`,
`ServiceAccountStatus`) -- a one-directional dependency (neither module
depends back on `saas_os/core/api_keys`), and still not a second authorization
engine: the gate is exactly the same `can()` chokepoint every other
`saas_os/core/rbac`-adjacent management operation uses, and a created key confers
no authority of its own -- it only ever resolves to the owning service
account's principal, whose *effective* permissions still come entirely
from that service account's own `ServiceAccountRole`/`DelegationGrant`
rows, independently anti-amplification-checked at assignment time
(`saas_os/core/rbac/service.py::assign_service_account_role()`'s own docstring).
Creating or revoking a key therefore cannot itself grant, and merely
creating a service account or a key grants nothing by itself.

`validate_api_key()` (architecture research Phase E) is the complete
*authentication* step: secret match, then not-revoked, then not-expired,
then (for a service-account-owned key) the owning `ServiceAccount` must
resolve and be `ACTIVE`. It still does not itself call `can()` --
*authorization* (does this now-authenticated principal have permission
for a given action) remains the caller's own subsequent, explicit
`saas_os.core.rbac.can(actor_id=..., actor_type=..., tenant_id=key.tenant_id, ...)`
call, using whichever of `key.user_id`/`key.service_account_id` is set --
`saas_os/core/api_keys` still does not implement its own parallel
permission-grant mechanism (this module's own `__init__.py` docstring).
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from saas_os.core.api_keys.errors import (
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
from saas_os.core.api_keys.models import ApiKey
from saas_os.core.audit_log import ActorType, AuditOutcome, record_in_transaction
from saas_os.core.audit_log import record as record_audit_event
from saas_os.core.authority import Caller, ServiceAccountCaller, UserCaller, require_caller
from saas_os.core.identity import (
    ServiceAccountStatus,
    get_service_account,
    get_user,
    lock_user_is_active,
)
from saas_os.core.rbac import can, register_permission
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import authorize_caller, require_active_user
from saas_os.core.tenancy import (
    TenantStatus,
    get_tenant,
    is_accessible_to_principals,
    lock_accessible_tenant,
    require_open_tenant,
    require_purging_tenant,
)
from saas_os.infra.db import (
    IntegrityError,
    Session,
    bind_tenant_scope,
    select,
    session_scope,
    tenant_session_scope,
    update,
)

# 256 bits of entropy -- the same standard, non-guessable bearer-secret
# size `saas_os/core/identity/sessions.py` uses.
_TOKEN_BYTES = 32

# ADR-0047: every key issued since carries this visible prefix, so that a
# key is recognisable to a person and to a secret scanner and cannot be
# mistaken for a session token. It is part of the secret that is hashed;
# keys issued before it, without the prefix, keep working.
API_KEY_PREFIX = "sok_"  # pragma: allowlist secret -- the public key prefix


def _new_raw_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)


_MAX_NAME_LENGTH = 200


def _audit_actor(key: ApiKey) -> tuple[ActorType, uuid.UUID | None, uuid.UUID | None]:
    """Which `saas_os.core.audit_log` actor an `api_key.*` audit event for `key`
    should be attributed to -- `ActorType.USER`/`key.user_id`/`None` for a
    human-owned key (Phase 4.1's original, unchanged behavior),
    `ActorType.SERVICE_ACCOUNT`/`None`/`key.service_account_id` for a
    service-account-owned key (Phase J-RBAC-02 -- "Service Account Audit
    Attribution": `saas_os/core/audit_log` now has a dedicated `SERVICE_ACCOUNT`
    actor type + `actor_service_account_id` column,
    `saas_os/core/audit_log/models.py::ActorType`'s own docstring -- an earlier
    revision of this function collapsed a service-account-owned key's
    events to `ActorType.SYSTEM` with no id at all, discarding
    `key.service_account_id` entirely: a forensic attribution gap this
    closes). The API key itself is only ever the *credential* here; the
    service account it resolves to is the *actor* this function returns
    -- never the key's own id.

    Returns `(actor_type, actor_user_id, actor_service_account_id)`, the
    exact keyword shape `saas_os.core.audit_log.record()` expects.
    """
    if key.user_id is not None:
        return ActorType.USER, key.user_id, None
    return ActorType.SERVICE_ACCOUNT, None, key.service_account_id


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _validate_name(name: str) -> None:
    if not name or not name.strip():
        raise InvalidApiKeyNameError("name must be a non-empty string.")
    if len(name) > _MAX_NAME_LENGTH:
        raise InvalidApiKeyNameError(f"name exceeds {_MAX_NAME_LENGTH} characters.")


def create_api_key(
    tenant_id: uuid.UUID,
    name: str,
    *,
    caller: UserCaller,
    expires_at: datetime | None = None,
) -> tuple[ApiKey, str]:
    """Issue a new API key for `user_id` within `tenant_id`. Returns the
    persisted record (never carrying the raw secret -- only its hash) and
    the raw key. This is the ONLY point the raw value exists; it is never
    stored, logged, or reconstructable afterward.

    `(tenant_id, user_id)` must be a real `TenantMembership` -- enforced
    structurally by the composite foreign key in `saas_os/core/api_keys/models.py`,
    not merely by this function remembering to check. A pair that is not a
    genuine membership fails at the database level with an `IntegrityError`,
    surfaced here as `TenantMembershipRequiredError`.

    `expires_at` (architecture research Phase E) is optional and defaults
    to `None` (no expiry) -- Phase 4.1's original, unchanged behavior for
    every caller that does not pass it.

    RA-12-8: `require_open_tenant()` alone admits `SUSPENDED` (it is not a
    *closed* status -- tenant data may still be mutated while suspended).
    A new credential is different: it is authority a tenant principal
    could later exercise, so it must not be issuable while the tenant is
    inaccessible to its own principals either
    (`saas_os.core.tenancy.lifecycle.PRINCIPAL_INACCESSIBLE_STATUSES`, the same
    RA-04 policy `validate_api_key()` already enforces at use time).

    RA-12-9 (privacy re-audit finding P9-1): the wider check is performed
    a second time, race-safely, *inside* the same transaction as the
    insert below -- `lock_accessible_tenant()`, the identical
    `core.tenants` row `FOR SHARE` primitive and in-transaction pattern
    `saas_os.core.identity.service.create_service_account()` already uses. The
    unlocked `require_open_tenant()` call above is only a fast pre-check
    (existence + not-closed, before any key material is even generated);
    the locked call below is what actually decides the outcome, so a
    concurrent `transition_tenant_status()` can no longer commit *between*
    the check and the write: either it commits first and this raises, or
    this holds the share lock first and the transition waits until this
    transaction ends. `DELETED`/`PURGING`/`PURGED` are terminal (no
    transition ever leads back out of them, `saas_os.core.tenancy.lifecycle
    ._ALLOWED_TRANSITIONS`), so a stray row from the old, unlocked-only
    check was always going to be removed by `purge_tenant()` regardless
    of timing. `SUSPENDED` is different -- it is reversible -- so that
    reasoning never applied to it; the actual, narrower reason a
    `SUSPENDED`-window race was low-impact even before this fix is that
    the resulting key was already independently rejected by
    `validate_api_key()`'s own live check for as long as the tenant
    stayed `SUSPENDED`. This change closes the race itself rather than
    continuing to rely on that narrower argument.
    """
    # ADR-0031: a user key is issued to the explicit caller itself, who
    # must be an active user; the key and its audit entry commit together.
    require_caller("create_api_key", caller, (UserCaller,))
    require_open_tenant(tenant_id)
    user_id = caller.user_id
    _validate_name(name)
    require_open_tenant(tenant_id)
    raw_key = _new_raw_key()
    key_hash = _hash_key(raw_key)

    try:
        with tenant_session_scope(tenant_id) as session:
            require_active_user(
                caller, session=session, operation="create_api_key", tenant_id=tenant_id
            )
            lock_accessible_tenant(session, tenant_id)
            key = ApiKey(
                tenant_id=tenant_id,
                user_id=user_id,
                name=name,
                key_hash=key_hash,
                expires_at=expires_at,
            )
            session.add(key)
            session.flush()
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action="api_key.create",
                resource_type="api_key",
                resource_id=str(key.id),
            )
            session.refresh(key)
            session.expunge(key)
    except IntegrityError as exc:
        raise TenantMembershipRequiredError(tenant_id, user_id) from exc

    return key, raw_key


def create_service_account_api_key(
    *,
    caller: UserCaller,
    tenant_id: uuid.UUID,
    service_account_id: uuid.UUID,
    name: str,
    expires_at: datetime | None = None,
) -> tuple[ApiKey, str]:
    """Issue a new API key owned by `service_account_id` within
    `tenant_id` (architecture research Phase E -- machine credentials).
    Unlike `create_api_key()`, this function is explicitly gated: it does
    not exist to let an arbitrary user mint machine credentials
    (`saas_os/core/api_keys/errors.py::ApiKeyNotAuthorizedError`'s own docstring).

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
    `ServiceAccountRole`/`DelegationGrant` rows (`saas_os/core/api_keys/service.py`'s
    own module docstring) -- so this function needs no anti-amplification
    check beyond the management-capability gate above.
    """
    require_caller("create_service_account_api_key", caller, (UserCaller,))
    actor_user_id = caller.user_id
    _validate_name(name)
    require_open_tenant(tenant_id)

    service_account = get_service_account(tenant_id, service_account_id)
    if service_account is None:
        raise ServiceAccountRequiredError(tenant_id, service_account_id)

    raw_key = _new_raw_key()
    key_hash = _hash_key(raw_key)

    try:
        with tenant_session_scope(tenant_id) as session:
            register_permission("api_key", "create", session=session)
            if not can(
                actor_id=actor_user_id,
                tenant_id=tenant_id,
                action="create",
                resource="api_key",
                session=session,
            ):
                raise ApiKeyNotAuthorizedError(actor_user_id, tenant_id)
            key = ApiKey(
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                name=name,
                key_hash=key_hash,
                expires_at=expires_at,
            )
            session.add(key)
            session.flush()
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action="api_key.create",
                resource_type="api_key",
                resource_id=str(key.id),
                metadata={"service_account_id": str(service_account_id)},
            )
            session.refresh(key)
            session.expunge(key)
    except IntegrityError as exc:
        raise ServiceAccountRequiredError(tenant_id, service_account_id) from exc

    return key, raw_key


def validate_api_key(raw_key: str) -> ApiKey:
    """Resolve a raw API key to its record -- the complete *authentication*
    step (architecture research Phase E's own "Authorization Flow": verify
    secret -> verify not revoked -> verify not expired -> resolve
    ServiceAccount -> verify ServiceAccount active), stopping short of
    *authorization* (that is the caller's own subsequent `saas_os.core.rbac.can()`
    call -- this module's own docstring).

    Looks up by the key's hash, never the raw value. An unknown key
    raises `InvalidApiKeyError` (no audit entry -- there is no resolvable
    `tenant_id` to attribute one to, the same structural reason
    `saas_os/core/audit_log` never records tenant-less events, docs/IMPLEMENTATION-
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

    actor_type, actor_user_id, actor_service_account_id = _audit_actor(key)

    if key.revoked_at is not None:
        record_audit_event(
            tenant_id=key.tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            actor_service_account_id=actor_service_account_id,
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
            actor_service_account_id=actor_service_account_id,
            action="api_key.validate",
            resource_type="api_key",
            resource_id=str(key.id),
            outcome=AuditOutcome.DENIED,
        )
        raise ExpiredApiKeyError(key.id)

    # PRIV-03 P8 (privacy re-audit RA-04): a key is a *tenant* credential,
    # so it authenticates only while its tenant still admits tenant
    # principals (`saas_os.core.tenancy.lifecycle.PRINCIPAL_INACCESSIBLE_STATUSES`:
    # SUSPENDED/DELETED/PURGING/PURGED all deny). Checked after the key's
    # own revoked/expired states -- those keep their existing, more
    # specific errors and precedence -- and before the service-account
    # resolution below. Audited exactly like the other denials (a real
    # `tenant_id` exists), under its own gate name; surfaced to the caller
    # as the generic `InvalidApiKeyError`, which reveals nothing about the
    # tenant's existence or lifecycle to whoever holds the key. The row
    # itself is left in place: purge revokes and deletes it, and this
    # check does not depend on that deletion. An unlocked read is
    # sufficient here -- authentication only; the authorization decision
    # that follows (`saas_os.core.rbac.can()`) re-reads the lifecycle under
    # `lock_accessible_tenant()`.
    if not is_accessible_to_principals(TenantStatus(get_tenant(key.tenant_id).status)):
        record_audit_event(
            tenant_id=key.tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            actor_service_account_id=actor_service_account_id,
            action="api_key.validate",
            resource_type="api_key",
            resource_id=str(key.id),
            outcome=AuditOutcome.DENIED,
            metadata={"denied_gate": "tenant_lifecycle"},
        )
        raise InvalidApiKeyError()

    # Foundation Authority & Evidence (ADR-0031): a user-owned key
    # authenticates only while its user is active (`User.is_active`). An
    # inactive user's key is denied, audited under its own gate name, and
    # surfaced as the generic `InvalidApiKeyError` like the lifecycle gate.
    if key.user_id is not None:
        owner = get_user(key.user_id)
        if owner is None or not owner.is_active:
            record_audit_event(
                tenant_id=key.tenant_id,
                actor_type=actor_type,
                actor_user_id=actor_user_id,
                actor_service_account_id=actor_service_account_id,
                action="api_key.validate",
                resource_type="api_key",
                resource_id=str(key.id),
                outcome=AuditOutcome.DENIED,
                metadata={"denied_gate": "inactive_user"},
            )
            raise InvalidApiKeyError()

    if key.service_account_id is not None:
        service_account = get_service_account(key.tenant_id, key.service_account_id)
        if service_account is None or service_account.status != ServiceAccountStatus.ACTIVE.value:
            record_audit_event(
                tenant_id=key.tenant_id,
                actor_type=actor_type,
                actor_user_id=actor_user_id,
                actor_service_account_id=actor_service_account_id,
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


def _key_owner(tenant_id: uuid.UUID, key_id: uuid.UUID) -> ApiKey:
    with tenant_session_scope(tenant_id) as session:
        key = session.execute(
            select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if key is None:
            raise ApiKeyNotFoundError(tenant_id, key_id)
        session.expunge(key)
        return key


def _authorize_key_management(
    caller: Caller,
    key: ApiKey,
    *,
    session: Session,
    operation: str,
    action: str,
    tenant_id: uuid.UUID,
) -> None:
    """A user may always manage their *own* key (revoking only removes
    authority; rotating requires them to be active), and a service account
    may revoke -- never rotate -- its own key. Anything else (another
    principal's key, a service account rotating) needs `(api_key, <action>)`
    through `can()`. Evaluated in the key mutation's own transaction
    (`session`, ADR-0031), against the key row that transaction holds
    locked."""
    if isinstance(caller, UserCaller) and key.user_id == caller.user_id:
        if action != "revoke":
            require_active_user(caller, session=session, operation=operation, tenant_id=tenant_id)
        return
    if (
        isinstance(caller, ServiceAccountCaller)
        and action == "revoke"
        and key.service_account_id == caller.service_account_id
        and key.tenant_id == caller.tenant_id
    ):
        return
    authorize_caller(
        caller,
        session=session,
        operation=operation,
        tenant_id=tenant_id,
        resource="api_key",
        action=action,
    )


def _lock_key(session: Session, tenant_id: uuid.UUID, key_id: uuid.UUID) -> ApiKey:
    key = session.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id).with_for_update()
    ).scalar_one_or_none()
    if key is None:
        raise ApiKeyNotFoundError(tenant_id, key_id)
    return key


def _revoke_locked_key(
    session: Session, key: ApiKey, *, tenant_id: uuid.UUID, caller: Caller
) -> None:
    if key.revoked_at is not None:
        return
    key.revoked_at = datetime.now(UTC)
    session.flush()
    record_in_transaction(
        session,
        caller=caller,
        tenant_id=tenant_id,
        action="api_key.revoke",
        resource_type="api_key",
        resource_id=str(key.id),
        metadata=_owner_metadata(key),
    )


def _owner_metadata(key: ApiKey) -> dict[str, object]:
    if key.user_id is not None:
        return {"owner_user_id": str(key.user_id)}
    return {"owner_service_account_id": str(key.service_account_id)}


def revoke_api_key(tenant_id: uuid.UUID, key_id: uuid.UUID, *, caller: Caller) -> None:
    """Revoke a key. Idempotent: revoking an already-revoked key is a
    no-op, not an error (mirrors `saas_os/core/identity/sessions.py::revoke_session`).
    Revocation takes effect immediately -- the very next `validate_api_key()`
    call for this key sees the update (docs/IMPLEMENTATION-ROADMAP.md
    Phase 4.1 Security Requirement: "revocation takes effect immediately";
    there is no cache in front of this table, so there is no staleness
    window to document or test beyond "none").

    Authority (ADR-0031): a user or service account may revoke its own
    key; any other key needs `(api_key, revoke)` at `tenant_id`. The audit entry names the
    explicit `caller` as the actor (the key's owner is recorded in its
    metadata) and is written in the same transaction as the revocation.
    """
    require_caller("revoke_api_key", caller)
    with tenant_session_scope(tenant_id) as session:
        key = _lock_key(session, tenant_id, key_id)
        _authorize_key_management(
            caller,
            key,
            session=session,
            operation="revoke_api_key",
            action="revoke",
            tenant_id=tenant_id,
        )
        _revoke_locked_key(session, key, tenant_id=tenant_id, caller=caller)


def revoke_service_account_api_key(
    *, caller: UserCaller, tenant_id: uuid.UUID, key_id: uuid.UUID
) -> None:
    """Revoke a service-account-owned key, explicitly authorized
    (architecture research Phase E: "Revocation must also be explicitly
    authorized" -- "a service account should not automatically be allowed
    to revoke arbitrary tenant keys merely because it owns itself").
    `caller` must hold the same dedicated "manage API keys in this
    tenant" capability (`(resource="api_key", action="revoke")`)
    `create_service_account_api_key()` requires for creation, checked via
    the existing `can()` chokepoint -- no self-revocation shortcut, and
    no distinct check for "is this actually a service-account-owned key".
    Audited in the same transaction as the revocation (ADR-0031).
    """
    require_caller("revoke_service_account_api_key", caller, (UserCaller,))
    actor_user_id = caller.user_id
    with tenant_session_scope(tenant_id) as session:
        register_permission("api_key", "revoke", session=session)
        if not can(
            actor_id=actor_user_id,
            tenant_id=tenant_id,
            action="revoke",
            resource="api_key",
            session=session,
        ):
            raise ApiKeyNotAuthorizedError(actor_user_id, tenant_id)
        key = _lock_key(session, tenant_id, key_id)
        _revoke_locked_key(session, key, tenant_id=tenant_id, caller=caller)


def _earlier(first: datetime | None, second: datetime | None) -> datetime | None:
    """The earlier of two expiries, where `None` means "never"."""
    if first is None:
        return second
    if second is None:
        return first
    return min(first, second)


def rotate_api_key(
    tenant_id: uuid.UUID,
    key_id: uuid.UUID,
    *,
    caller: Caller,
    expires_no_later_than: datetime | None = None,
) -> tuple[ApiKey, str]:
    """Rotate a key: atomically revoke `key_id` and issue a brand new key
    with the same `tenant_id`/owner (`user_id` or `service_account_id`,
    architecture research Phase E)/`name`/`expires_at`. The old key's
    secret cannot itself be reused as the new one -- rotation always
    produces a genuinely new secret, the same convention established
    SaaS API providers (Stripe, GitHub, ...) use: the old key id becomes
    permanently invalid, a new key id is issued.

    RA-12-8: same tightened lifecycle gate as `create_api_key()` -- a
    rotation issues a brand new credential, so `SUSPENDED` is denied here
    too, not merely `require_open_tenant()`'s narrower closed-status
    check (module docstring above this function's sibling).

    RA-12-9 (privacy re-audit finding P9-1): same race-safe, in-transaction
    fence as `create_api_key()` -- `lock_accessible_tenant()` is held for
    the *entire* locate-old-key/revoke-old/insert-new sequence below, all
    inside one transaction, not merely at entry, so a concurrent lifecycle
    transition cannot commit partway through rotation either. See
    `create_api_key()`'s own docstring for why this matters for
    `SUSPENDED` specifically (reversible) and not for the terminal
    `DELETED`/`PURGING`/`PURGED` states (already purge-cleaned regardless
    of timing).

    Authority (ADR-0031): an active user may rotate their own key; any
    other key needs `(api_key, rotate)` at `tenant_id`. The audit entry
    names the explicit `caller` and is written in the same transaction as
    the revoke-and-reissue.

    ADR-0045 section 11d: a user-owned key is rotated only while its
    *owner* is active, whoever the caller is, and the owner's `core.users`
    row is held `FOR SHARE` for the whole rotation. A deactivation takes
    that row exclusively before it revokes the user's keys, so a rotation
    in flight makes it wait and the new key is revoked with the rest; a
    rotation that starts later reads the owner as inactive and is refused
    (`AuthorityNotAuthorizedError`). The owner row is locked before the key
    row -- the order the deactivation uses -- so the two cannot deadlock.

    `expires_no_later_than` (ADR-0047) caps the new key's expiry: it keeps
    the old key's `expires_at` when that is earlier, and otherwise expires
    at the cap -- also when the old key never expired. The HTTP route
    passes it so that a rotated key is bounded like a new one.

    A key that is already revoked is not rotated (`RevokedApiKeyError`,
    after authorization, so only a caller allowed to rotate the key learns
    that it is revoked): revocation is permanent, and a rotation must not
    turn a revoked key -- for example one `revoke_user_api_keys()` revoked
    -- back into a live credential.
    """
    require_caller("rotate_api_key", caller)
    require_open_tenant(tenant_id)
    owner_user_id = _key_owner(tenant_id, key_id).user_id  # unlocked existence pre-check
    raw_key = _new_raw_key()
    key_hash = _hash_key(raw_key)

    with tenant_session_scope(tenant_id) as session:
        lock_accessible_tenant(session, tenant_id)
        if owner_user_id is not None and not lock_user_is_active(session, owner_user_id):
            raise AuthorityNotAuthorizedError("rotate_api_key", tenant_id)
        old_key = _lock_key(session, tenant_id, key_id)
        _authorize_key_management(
            caller,
            old_key,
            session=session,
            operation="rotate_api_key",
            action="rotate",
            tenant_id=tenant_id,
        )

        if old_key.revoked_at is not None:
            raise RevokedApiKeyError(old_key.id)
        old_key.revoked_at = datetime.now(UTC)

        new_key = ApiKey(
            tenant_id=old_key.tenant_id,
            user_id=old_key.user_id,
            service_account_id=old_key.service_account_id,
            name=old_key.name,
            key_hash=key_hash,
            expires_at=_earlier(old_key.expires_at, expires_no_later_than),
        )
        session.add(new_key)
        session.flush()
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action="api_key.rotate",
            resource_type="api_key",
            resource_id=str(new_key.id),
            metadata={"previous_key_id": str(key_id)},
        )
        session.refresh(new_key)
        session.expunge(new_key)
        session.expunge(old_key)

    return new_key, raw_key


# --- ADR-0045 section 11: a user's keys, across tenants ------------------------


def revoke_user_api_keys_in_transaction(
    session: Session, user_id: uuid.UUID
) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Revoke every unrevoked **user-owned** key of `user_id`, in every
    tenant, inside the caller's own transaction. Returns `(key id, tenant
    id)` of each key revoked; nothing else about a key is read.

    `core.api_keys` is a global table with no row-level security (a key is
    resolved by its hash before any tenant is known), so one statement
    reaches the user's keys in every tenant with no tenant scan and no
    tenant scope. Service-account keys have no `user_id` and are untouched.
    Revocation is permanent: nothing clears `revoked_at`.

    Authorizes nothing: its callers are the platform operations of
    `saas_os.core.identity.user_authority`, which authorized the caller and
    locked the user's row exclusively in this transaction first -- so a
    key creation in flight (which holds that row `FOR SHARE`) has committed
    and is revoked here too.

    Cost: one update over the user's keys, by the index on `user_id`. No
    limit on the number of keys a user may hold exists, so the statement
    and the evidence rows it leads to are bounded by that user's key count,
    not by a constant."""
    rows = session.execute(
        update(ApiKey)
        .where(ApiKey.user_id == user_id, ApiKey.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
        .returning(ApiKey.id, ApiKey.tenant_id)
    ).all()
    return sorted(((row.id, row.tenant_id) for row in rows), key=lambda r: (str(r[1]), str(r[0])))


def record_platform_key_revocations(
    session: Session,
    *,
    caller: UserCaller,
    user_id: uuid.UUID,
    keys: list[tuple[uuid.UUID, uuid.UUID]],
) -> None:
    """One `api_key.revoke` row per revoked key, in that key's own
    tenant's `core.audit_log`, naming the platform operator as the actor
    (ADR-0045 section 8, dual evidence): the tenant's administrators see in
    their own trail who revoked the key. Same metadata shape
    `revoke_api_key()` writes, plus a marker that the platform acted. Each
    row is written under its tenant's row-level-security scope; call this
    after the platform audit row, never inside another bind block."""
    for key_id, tenant_id in keys:
        with bind_tenant_scope(session, tenant_id):
            record_in_transaction(
                session,
                caller=caller,
                tenant_id=tenant_id,
                action="api_key.revoke",
                resource_type="api_key",
                resource_id=str(key_id),
                metadata={"owner_user_id": str(user_id), "platform": True},
            )


# --- PRIV-03 Phase P3: tenant purge ------------------------------------------


def purge_tenant_api_keys(tenant_id: uuid.UUID) -> int:
    """Revoke, then delete, every API key `tenant_id` owns (human- and
    service-account-owned alike) -- one module-owned step of
    `saas_os.core.tenancy.purge_tenant()`. Only callable once the tenant is in
    the purge phase (`TenantNotPurgingError` otherwise). Idempotent: a
    second call finds nothing and returns 0.

    `saas_os.core.api_keys` is deliberately not RLS-scoped (its own module
    docstring; PRIV-12), so this is the one purge step whose isolation
    rests on its explicit `tenant_id` predicate alone -- exactly like
    every other query in this module. Rows are locked `FOR UPDATE` so two
    concurrent purge attempts serialize on them rather than racing. No
    audit entry: the tenant-level purge is the audited event (a later
    phase), not each of its constituent deletes.
    """
    require_purging_tenant(tenant_id)
    deleted = 0
    revoked_at = datetime.now(UTC)
    with session_scope() as session:
        keys = (
            session.execute(
                select(ApiKey)
                .where(ApiKey.tenant_id == tenant_id)
                .order_by(ApiKey.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for key in keys:
            if key.revoked_at is None:
                key.revoked_at = revoked_at  # explicit revoke, then removal
            session.delete(key)
            deleted += 1
    return deleted


def purge_user_api_keys_in_tenant(tenant_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """RA-12-3 -- revoke, then delete, every API key `user_id` owns
    *within `tenant_id`* -- one module-owned step of
    `saas_os.core.identity.erasure.erase_user_identity()`, mirroring
    `purge_tenant_api_keys()`'s own "revoke, then remove" shape exactly,
    scoped to one user's own keys in one tenant rather than every key the
    tenant owns. Never touches a service-account-owned key (this is
    identity erasure for a human user, not a tenant-wide purge) or any
    other member's own keys. Idempotent: a second call finds nothing and
    returns 0. Must run before the user's own `core.tenant_memberships`
    row in this tenant is removed -- `(tenant_id, user_id)` is a
    composite FK onto it.
    """
    deleted = 0
    revoked_at = datetime.now(UTC)
    with session_scope() as session:
        keys = (
            session.execute(
                select(ApiKey)
                .where(ApiKey.tenant_id == tenant_id, ApiKey.user_id == user_id)
                .order_by(ApiKey.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for key in keys:
            if key.revoked_at is None:
                key.revoked_at = revoked_at
            session.delete(key)
            deleted += 1
    return deleted
