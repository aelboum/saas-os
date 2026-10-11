"""Shared by the opt-in capability routers (docs/ADR/0040-...).

Nothing here decides anything. `user_caller()` names the already
authenticated actor for a Core function; `page()` bounds a list response;
`denied()` is what a route raises when Core itself refuses a call the
route's own permission check let through (a concurrent revocation, a
second authority Core requires) -- the same generic 403 as the ingress
chain's, never Core's own message.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import HTTPException, Query

from saas_os.api.context import RequestContext
from saas_os.api.errors import forbidden
from saas_os.core.authority import UserCaller
from saas_os.core.tenancy.errors import (
    TenantClosedError,
    TenantInaccessibleError,
    TenantNotFoundError,
)

# The tenant stopped admitting this request between the ingress chain's own
# check and the Core call (suspended, deleted, purging). Same answer as the
# chain gives: the tenant is not found.
TENANT_UNAVAILABLE = (TenantClosedError, TenantInaccessibleError, TenantNotFoundError)

# No control characters in free-text request fields: PostgreSQL rejects a
# NUL byte with a data error, which would surface as a 500.
PRINTABLE = r"^[^\x00-\x1f\x7f]+$"

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500

Limit = Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)]
Offset = Annotated[int, Query(ge=0)]


def user_caller(context: RequestContext) -> UserCaller:
    """The verified request actor as a Core caller. Always the session's
    own user -- never an identifier taken from the path or the body."""
    return UserCaller(context.actor_id)


def page[T](items: list[T], *, limit: int, offset: int) -> list[T]:
    return items[offset : offset + limit]


def denied() -> HTTPException:
    return forbidden()
