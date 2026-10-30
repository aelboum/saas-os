"""Opt-in capability router: tenant membership (docs/ADR/0040-...).

    app.include_router(saas_os.api.v1.members_router)

Not mounted by `build_platform_app()`. Exposes what
`saas_os.core.identity` already does and nothing more: list the tenant's
members, and suspend / reactivate / revoke a membership. Every mutation
is authorized and audited inside Core, in the mutation's own transaction
(ADR-0031); the route's `require_permission` names the same permission,
so a caller without it is refused before Core is reached.

Adding a member directly is not exposed: joining a tenant goes through an
invitation (`saas_os.api.v1.invitations`). Role assignment is not exposed.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from saas_os.api.context import RequestContext
from saas_os.api.dependencies import require_permission
from saas_os.api.errors import conflict, not_found
from saas_os.api.v1._common import (
    DEFAULT_PAGE_SIZE,
    TENANT_UNAVAILABLE,
    Limit,
    Offset,
    denied,
    user_caller,
)
from saas_os.api.v1.permissions import MEMBERSHIP, REACTIVATE, READ, REVOKE, SUSPEND
from saas_os.core.identity import (
    TenantMembership,
    list_tenant_members,
    reactivate_membership,
    revoke_membership,
    suspend_membership,
)
from saas_os.core.identity.errors import (
    InvalidMembershipTransitionError,
    LastTenantAdministratorError,
    MembershipNotFoundError,
)
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError

router = APIRouter(prefix="/v1/tenants/{tenant_id}/members", tags=["members"])

_read = require_permission(MEMBERSHIP, READ)
_suspend = require_permission(MEMBERSHIP, SUSPEND)
_reactivate = require_permission(MEMBERSHIP, REACTIVATE)
_revoke = require_permission(MEMBERSHIP, REVOKE)


class MembershipResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    status: str
    created_at: datetime


def _response(membership: TenantMembership) -> MembershipResponse:
    return MembershipResponse(
        id=membership.id,
        user_id=membership.user_id,
        status=membership.status,
        created_at=membership.created_at,
    )


@router.get("", response_model=list[MembershipResponse])
def list_members(
    limit: Limit = DEFAULT_PAGE_SIZE,
    offset: Offset = 0,
    context: RequestContext = Depends(_read),
) -> list[MembershipResponse]:
    members = list_tenant_members(context.tenant_id, limit=limit, offset=offset)
    return [_response(m) for m in members]


def _transition(operation, context: RequestContext, membership_id: uuid.UUID) -> MembershipResponse:  # type: ignore[no-untyped-def]
    try:
        membership = operation(context.tenant_id, membership_id, caller=user_caller(context))
    except MembershipNotFoundError:
        raise not_found("membership") from None
    except LastTenantAdministratorError:
        raise conflict(
            "The last administrator of a tenant cannot be suspended or revoked."
        ) from None
    except InvalidMembershipTransitionError:
        raise conflict("Membership is not in a state that allows this.") from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    except AuthorityNotAuthorizedError:
        raise denied() from None
    return _response(membership)


@router.post("/{membership_id}/suspend", response_model=MembershipResponse)
def suspend_member(
    membership_id: uuid.UUID, context: RequestContext = Depends(_suspend)
) -> MembershipResponse:
    return _transition(suspend_membership, context, membership_id)


@router.post("/{membership_id}/reactivate", response_model=MembershipResponse)
def reactivate_member(
    membership_id: uuid.UUID, context: RequestContext = Depends(_reactivate)
) -> MembershipResponse:
    return _transition(reactivate_membership, context, membership_id)


@router.post("/{membership_id}/revoke", response_model=MembershipResponse)
def revoke_member(
    membership_id: uuid.UUID, context: RequestContext = Depends(_revoke)
) -> MembershipResponse:
    return _transition(revoke_membership, context, membership_id)
