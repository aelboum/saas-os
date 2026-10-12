"""Opt-in capability router: invitations (docs/ADR/0040-...).

    app.include_router(saas_os.api.v1.invitations_router)

Not mounted by `build_platform_app()`. Create, list and revoke -- the
three operations an existing member performs, each authorized and audited
inside `saas_os.core.identity`.

**The raw invitation token is returned exactly once**, in the response to
the create call. Only its hash is stored; `token_hash` is never part of
any response. Delivering the token to the invitee (an email with a link
into the product's own UI) is the product's job.

**Accepting an invitation is not exposed here.** The accepting user is by
definition not yet a member, and the ingress chain's only tenant-scoped
policy requires membership; it also needs a ruling on whether the
accepting identity must match the invited email, which Core leaves to the
ingress layer. Both are open in ADR-0040. A product accepts invitations
through its own route until that is decided.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from saas_os.api.context import RequestContext
from saas_os.api.dependencies import require_permission
from saas_os.api.errors import conflict, invalid_request, not_found
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
from saas_os.api.v1.permissions import CREATE, INVITATION, READ, REVOKE
from saas_os.core.identity import (
    Invitation,
    compute_invitation_status,
    create_invitation,
    list_invitations_for_tenant,
    revoke_invitation,
)
from saas_os.core.identity.errors import (
    DuplicateInvitationError,
    InvalidInvitationEmailError,
    InvitationAlreadyAcceptedError,
    InvitationNotAuthorizedError,
    InvitationNotFoundError,
)

router = APIRouter(prefix="/v1/tenants/{tenant_id}/invitations", tags=["invitations"])

_read = require_permission(INVITATION, READ)
_create = require_permission(INVITATION, CREATE)
_revoke = require_permission(INVITATION, REVOKE)


class InvitationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=PRINTABLE)


class InvitationResponse(BaseModel):
    id: uuid.UUID
    invited_email: str
    status: str
    inviter_user_id: uuid.UUID
    created_at: datetime
    expires_at: datetime


class CreatedInvitationResponse(InvitationResponse):
    # The only place the raw token ever appears. It is not stored and
    # cannot be retrieved again.
    token: str


def _fields(invitation: Invitation) -> dict[str, Any]:
    return {
        "id": invitation.id,
        "invited_email": invitation.invited_email,
        "status": compute_invitation_status(invitation).value,
        "inviter_user_id": invitation.inviter_user_id,
        "created_at": invitation.created_at,
        "expires_at": invitation.expires_at,
    }


@router.post("", response_model=CreatedInvitationResponse, status_code=status.HTTP_201_CREATED)
def create(
    body: InvitationRequest, context: RequestContext = Depends(_create)
) -> CreatedInvitationResponse:
    try:
        invitation, raw_token = create_invitation(
            context.tenant_id, body.email, caller=user_caller(context)
        )
    except InvalidInvitationEmailError:
        raise invalid_request("Invalid invitation email.") from None
    except DuplicateInvitationError:
        raise conflict("A pending invitation already exists for this email.") from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    except InvitationNotAuthorizedError:
        raise denied() from None
    return CreatedInvitationResponse(**_fields(invitation), token=raw_token)


@router.get("", response_model=list[InvitationResponse])
def list_invitations(
    limit: Limit = DEFAULT_PAGE_SIZE,
    offset: Offset = 0,
    context: RequestContext = Depends(_read),
) -> list[InvitationResponse]:
    invitations = sorted(
        list_invitations_for_tenant(context.tenant_id), key=lambda i: (i.created_at, i.id)
    )
    return [InvitationResponse(**_fields(i)) for i in page(invitations, limit=limit, offset=offset)]


@router.post("/{invitation_id}/revoke", response_model=InvitationResponse)
def revoke(
    invitation_id: uuid.UUID, context: RequestContext = Depends(_revoke)
) -> InvitationResponse:
    try:
        invitation = revoke_invitation(
            context.tenant_id, invitation_id, caller=user_caller(context)
        )
    except InvitationNotFoundError:
        raise not_found("invitation") from None
    except InvitationAlreadyAcceptedError:
        raise conflict("Invitation was already accepted.") from None
    except InvitationNotAuthorizedError:
        raise denied() from None
    return InvitationResponse(**_fields(invitation))
