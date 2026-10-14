"""Opt-in capability router: a member's own API keys (docs/ADR/0040-...).

    app.include_router(saas_os.api.v1.api_keys_router)

Not mounted by `build_platform_app()`. A member creates, lists, rotates
and revokes **their own** keys in the tenant. Every route requires
`api_key:self_manage` (`saas_os/api/v1/permissions.py` explains why HTTP
is stricter than Core here), and every route is confined to keys whose
owner is the session's own user: a key that belongs to another member or
to a service account is reported as not found, exactly like a key that
does not exist. Managing other principals' keys, and service accounts,
are not exposed.

**The key itself is returned exactly once**, by create and by rotate.
Only its SHA-256 hash is stored; `key_hash` is never part of any
response.

**Every key issued or rotated here expires** (ADR-0047): create takes
`expires_in_days`, 1 to 365, default 365; rotate gives the new key the
old one's expiry or 365 days, whichever is earlier, also when the old key
never expired.

This router manages keys; it never accepts one (`api_key` is an authority
resource). A route accepts a key for authentication only if it declares
`require_permission(..., api_key=True)` (ADR-0047).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel, Field

from saas_os.api.context import RequestContext
from saas_os.api.dependencies import require_permission
from saas_os.api.errors import invalid_request, not_found
from saas_os.api.v1._common import (
    DEFAULT_PAGE_SIZE,
    PRINTABLE,
    TENANT_UNAVAILABLE,
    Limit,
    Offset,
    denied,
    page,
    user_caller,
)
from saas_os.api.v1.permissions import API_KEY, SELF_MANAGE
from saas_os.core.api_keys import (
    ApiKey,
    create_api_key,
    get_api_key,
    list_api_keys,
    revoke_api_key,
    rotate_api_key,
)
from saas_os.core.api_keys.errors import (
    ApiKeyNotFoundError,
    InvalidApiKeyNameError,
    TenantMembershipRequiredError,
)
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError, InvalidPrincipalError

router = APIRouter(prefix="/v1/tenants/{tenant_id}/api-keys", tags=["api-keys"])

_self_manage = require_permission(API_KEY, SELF_MANAGE)


# ADR-0047: a key issued or rotated over HTTP always expires, at most this
# many days after it is issued.
MAX_KEY_LIFETIME_DAYS = 365


class ApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200, pattern=PRINTABLE)
    expires_in_days: int = Field(default=MAX_KEY_LIFETIME_DAYS, ge=1, le=MAX_KEY_LIFETIME_DAYS)


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class IssuedApiKeyResponse(ApiKeyResponse):
    # The only place the key ever appears. It is not stored and cannot be
    # retrieved again.
    key: str


def _fields(key: ApiKey) -> dict[str, Any]:
    return {
        "id": key.id,
        "name": key.name,
        "created_at": key.created_at,
        "expires_at": key.expires_at,
        "revoked_at": key.revoked_at,
    }


def _own_key(context: RequestContext, key_id: uuid.UUID) -> ApiKey:
    """The caller's own key in this tenant, or the one 404 -- whether the
    key is absent, another member's, or a service account's."""
    try:
        key = get_api_key(context.tenant_id, key_id)
    except ApiKeyNotFoundError:
        raise not_found("api key") from None
    if key.user_id != context.actor_id:
        raise not_found("api key")
    return key


@router.post("", response_model=IssuedApiKeyResponse, status_code=status.HTTP_201_CREATED)
def create(
    body: ApiKeyRequest, context: RequestContext = Depends(_self_manage)
) -> IssuedApiKeyResponse:
    try:
        key, raw_key = create_api_key(
            context.tenant_id,
            body.name,
            caller=user_caller(context),
            expires_at=datetime.now(UTC) + timedelta(days=body.expires_in_days),
        )
    except InvalidApiKeyNameError:
        raise invalid_request("Invalid API key name.") from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    except (AuthorityNotAuthorizedError, InvalidPrincipalError, TenantMembershipRequiredError):
        raise denied() from None
    return IssuedApiKeyResponse(**_fields(key), key=raw_key)


@router.get("", response_model=list[ApiKeyResponse])
def list_own(
    limit: Limit = DEFAULT_PAGE_SIZE,
    offset: Offset = 0,
    context: RequestContext = Depends(_self_manage),
) -> list[ApiKeyResponse]:
    own = [k for k in list_api_keys(context.tenant_id) if k.user_id == context.actor_id]
    own.sort(key=lambda k: (k.created_at, k.id), reverse=True)  # stable across pages
    return [ApiKeyResponse(**_fields(k)) for k in page(own, limit=limit, offset=offset)]


@router.post("/{key_id}/rotate", response_model=IssuedApiKeyResponse)
def rotate(
    key_id: uuid.UUID, context: RequestContext = Depends(_self_manage)
) -> IssuedApiKeyResponse:
    _own_key(context, key_id)
    try:
        key, raw_key = rotate_api_key(
            context.tenant_id,
            key_id,
            caller=user_caller(context),
            # The new key expires when the old one did, or within the
            # maximum lifetime -- also when the old key never expired.
            expires_no_later_than=datetime.now(UTC) + timedelta(days=MAX_KEY_LIFETIME_DAYS),
        )
    except ApiKeyNotFoundError:
        raise not_found("api key") from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    except (AuthorityNotAuthorizedError, InvalidPrincipalError):
        raise denied() from None
    return IssuedApiKeyResponse(**_fields(key), key=raw_key)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke(key_id: uuid.UUID, context: RequestContext = Depends(_self_manage)) -> Response:
    _own_key(context, key_id)
    try:
        revoke_api_key(context.tenant_id, key_id, caller=user_caller(context))
    except ApiKeyNotFoundError:
        raise not_found("api key") from None
    except (AuthorityNotAuthorizedError, InvalidPrincipalError):
        raise denied() from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
