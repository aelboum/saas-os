"""Opt-in router: accepting an invitation over HTTP (ADR-0046).

    app.include_router(saas_os.api.v1.invitation_acceptance_router)

Not mounted by `build_platform_app()`, and separate from
`invitations_router` because its rule is the opposite of every capability
route: the caller is not a member, so there is no tenant permission to
check (the route's policy is `authenticated`), and the tenant in the path
is **never authority** -- it only scopes the row-level-secured lookup of
the token, which is the credential (`accept_invitation`'s docstring).

**Bound to the person invited.** The session must carry an email the
identity provider verified at login (`core.sessions.verified_email`), and
Core accepts only if it equals the invited email, comparing under the
invitation's row lock before anything is consumed.

**One answer for every refusal.** An unknown, expired, revoked or used
token, a tenant that does not match or no longer admits members, a
session with no verified email, a different email and an existing
suspended membership are all the same `404 invitation not found`, so a
link holder learns nothing about the invitation, the tenant or the
address. Rate limited per signed-in user, failing closed. A browser
request authenticated by the session cookie must come from the
application's own origin (ADR-0044), as for every unsafe method.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from saas_os.api.dependencies import get_current_session
from saas_os.api.errors import not_found, rate_limited, service_unavailable
from saas_os.api.v1._common import PRINTABLE
from saas_os.core.authority import UserCaller
from saas_os.core.identity import accept_invitation
from saas_os.core.identity.errors import (
    InvalidMembershipTransitionError,
    InvitationInvalidError,
)
from saas_os.core.identity.models import Session
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError, InvalidPrincipalError
from saas_os.infra.ratelimit import (
    RateLimitBackendError,
    RateLimitExceededError,
    enforce_rate_limit,
    get_ratelimit_config,
)

router = APIRouter(prefix="/v1/tenants/{tenant_id}/invitations", tags=["invitations"])

_RATE_LIMIT_RETRY_AFTER_SECONDS = 5


class AcceptInvitationRequest(BaseModel):
    # `secrets.token_urlsafe(32)` is 43 characters; the bound only stops an
    # oversized body from being hashed.
    token: str = Field(min_length=1, max_length=256, pattern=PRINTABLE)


class AcceptedInvitationResponse(BaseModel):
    tenant_id: uuid.UUID
    status: str


async def _accepting_session(
    request: Request, session: Session = Depends(get_current_session)
) -> Session:
    """The signed-in caller's session, after the per-user limit: one bucket
    per user for this route, whatever tenant or token is presented, and a
    limiter failure refuses rather than allows."""
    try:
        await enforce_rate_limit(
            f"invitation-accept:{session.user_id}", config=get_ratelimit_config()
        )
    except RateLimitExceededError as exc:
        raise rate_limited(exc.retry_after_seconds) from None
    except RateLimitBackendError:
        raise service_unavailable(_RATE_LIMIT_RETRY_AFTER_SECONDS) from None
    return session


@router.post("/accept", response_model=AcceptedInvitationResponse)
def accept(
    tenant_id: uuid.UUID,
    body: AcceptInvitationRequest,
    session: Session = Depends(_accepting_session),
) -> AcceptedInvitationResponse:
    if session.verified_email is None:
        # No email verified at login: nothing to bind the invitation to.
        raise not_found("invitation")
    try:
        membership = accept_invitation(
            body.token,
            tenant_id,
            caller=UserCaller(session.user_id),
            accepting_email=session.verified_email,
        )
    except (
        InvitationInvalidError,
        InvalidMembershipTransitionError,
        # The caller deactivated or removed after the session was
        # validated: refused before the token is looked up.
        AuthorityNotAuthorizedError,
        InvalidPrincipalError,
    ):
        raise not_found("invitation") from None
    return AcceptedInvitationResponse(tenant_id=membership.tenant_id, status=membership.status)
